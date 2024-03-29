use alloy_primitives::TxHash;
use alloy_providers::tmp::TempProvider;
use alloy_rpc_types::BlockTransactions;
use eyre::{Context, Result};
use forge::{executors::EvmError, utils::configure_tx_env};
use foundry_cli::{
    init_progress,
    opts::RpcOpts,
    update_progress,
    utils::{handle_traces, TraceResult},
};
use foundry_common::{is_known_system_sender, SYSTEM_TRANSACTION_TYPE};
use foundry_evm::opts::EvmOpts;

use clap::Parser;
use foundry_config::{find_project_root_path, Config};
use foundry_tweak::{executor::TweakExecutor, ClonedProject};

/// Replays an on-chain historical transaction locally on a fork of the blockchain with the on-chain contract tweaked by the current cloned project.
/// In other words, `forge replay`:
/// 1. Fork the blockchain, and replace the code of the on-chain contract associated with the current cloned project (address defined in `.clone.meta`).
/// 2. Replays the historical transaction on the forked blockchain.
///
/// NOTE: `forge replay` can only be used on a `forge clone`d project, which contains the metadata of the on-chain instance of the contract.
#[derive(Clone, Debug, Parser)]
pub struct ReplayArgs {
    #[arg()]
    transaction: String,

    #[command(flatten)]
    pub rpc: RpcOpts,
}

impl ReplayArgs {
    /// Runs the `forge replay` command.
    /// Logic is akin to the `cast run` command.
    pub async fn run(self) -> Result<()> {
        let root = find_project_root_path(None).unwrap();
        let figment = Config::figment_with_root(&root).merge(self.rpc);
        let evm_opts = figment.extract::<EvmOpts>()?;
        let mut config = Config::try_from(figment)?.sanitized();
        let cloned_project = ClonedProject::load_with_root(&root)?;

        let provider = foundry_common::provider::alloy::ProviderBuilder::new(
            &config.get_rpc_url_or_localhost_http()?,
        )
        .build()?;
        let tx_hash: TxHash = self.transaction.parse().wrap_err("invalid transaction hash")?;
        let tx = provider
            .get_transaction_by_hash(tx_hash)
            .await
            .wrap_err_with(|| format!("transaction not found: {:?}", tx_hash))?;

        let tx_block_number = tx
            .block_number
            .ok_or_else(|| eyre::eyre!("tx may still be pending: {:?}", tx_hash))?
            .to::<u64>();
        let block = provider.get_block(tx_block_number.into(), true).await?;
        // fork off the parent block
        config.fork_block_number = Some(tx_block_number - 1);

        let mut executor =
            TweakExecutor::new(&config, evm_opts, vec![cloned_project].into_iter()).await?;
        let mut env = executor.env.clone();

        // Set the state to the moment right before the transaction
        let block = block.ok_or(eyre::eyre!("block not found"))?;
        let pb = init_progress!(block.transactions, "tx");
        pb.set_position(0);
        let BlockTransactions::Full(txs) = block.transactions else {
            return Err(eyre::eyre!("block transactions not found"));
        };

        for (index, tx) in txs.into_iter().enumerate() {
            // System transactions such as on L2s don't contain any pricing info so
            // we skip them otherwise this would cause
            // reverts
            if is_known_system_sender(tx.from)
                || tx.transaction_type.map(|ty| ty.to::<u64>()) == Some(SYSTEM_TRANSACTION_TYPE)
            {
                update_progress!(pb, index);
                continue;
            }
            if tx.hash == tx_hash {
                break;
            }

            configure_tx_env(&mut env, &tx);

            if let Some(to) = tx.to {
                trace!(tx=?tx.hash,?to, "executing previous call transaction");
                executor.commit_tx_with_env(env.clone()).wrap_err_with(|| {
                    format!(
                        "Failed to execute transaction: {:?} in block {}",
                        tx.hash, env.block.number
                    )
                })?;
            } else {
                trace!(tx=?tx.hash, "executing previous create transaction");
                if let Err(error) = executor.deploy_with_env(env.clone(), None) {
                    match error {
                        // Reverted transactions should be skipped
                        EvmError::Execution(_) => (),
                        error => {
                            return Err(error).wrap_err_with(|| {
                                format!(
                                    "Failed to deploy transaction: {:?} in block {}",
                                    tx.hash, env.block.number
                                )
                            })
                        }
                    }
                }
            }

            update_progress!(pb, index);
        }

        // Execute our transaction
        let result = {
            configure_tx_env(&mut env, &tx);

            if let Some(to) = tx.to {
                trace!(tx=?tx.hash, to=?to, "executing call transaction");
                TraceResult::from(executor.commit_tx_with_env(env)?)
            } else {
                trace!(tx=?tx.hash, "executing create transaction");
                match executor.deploy_with_env(env, None) {
                    Ok(res) => TraceResult::from(res),
                    Err(err) => TraceResult::try_from(err)?,
                }
            }
        };

        handle_traces(result, &config, config.chain, vec![], false).await?;

        Ok(())
    }
}
