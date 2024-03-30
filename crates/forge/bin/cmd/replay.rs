use std::collections::BTreeMap;

use alloy_primitives::{Address, Bytes, TxHash, U256};
use alloy_providers::tmp::TempProvider;
use alloy_rpc_types::{Block, BlockTransactions, Transaction};
use eyre::{eyre, Context, Result};
use forge::{
    executors::{DeployResult, EvmError, RawCallResult},
    revm::primitives::EnvWithHandlerCfg,
    utils::configure_tx_env,
};
use foundry_cli::{
    opts::RpcOpts,
    utils::{handle_traces, TraceResult},
};
use foundry_common::{is_known_system_sender, SYSTEM_TRANSACTION_TYPE};
use foundry_compilers::EvmVersion;
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

    /// Executes the transaction only with the state from the previous block.
    ///
    /// May result in different results than the live execution!
    #[arg(long, short)]
    quick: bool,

    /// Sets the number of assumed available compute units per second for this provider
    ///
    /// default value: 330
    ///
    /// See also, https://docs.alchemy.com/reference/compute-units#what-are-cups-compute-units-per-second
    #[arg(long, alias = "cups", value_name = "CUPS")]
    pub compute_units_per_second: Option<u64>,

    /// Disables rate limiting for this node's provider.
    ///
    /// default value: false
    ///
    /// See also, https://docs.alchemy.com/reference/compute-units#what-are-cups-compute-units-per-second
    #[arg(long, value_name = "NO_RATE_LIMITS", visible_alias = "no-rpc-rate-limit")]
    pub no_rate_limit: bool,

    /// The EVM version to use.
    ///
    /// Overrides the version specified in the config.
    #[arg(long, short)]
    evm_version: Option<EvmVersion>,

    #[command(flatten)]
    pub rpc: RpcOpts,
}

impl ReplayArgs {
    /// Runs the `forge replay` command.
    /// Logic is akin to the `cast run` command.
    pub async fn run(mut self) -> Result<()> {
        self.rpc.url = self.rpc.url.or(Some("http://localhost:8545".to_string()));
        let root = find_project_root_path(None).unwrap();
        let cloned_project = ClonedProject::load_with_root(&root)?;
        let tweaked_addr = cloned_project.metadata.address;
        let tweaked_code = cloned_project.tweaked_code(&self.rpc).await?;

        let figment = Config::figment_with_root(&root).merge(self.rpc);
        let evm_opts = figment.extract::<EvmOpts>()?;
        let mut config = Config::try_from(figment)?.sanitized();
        config.evm_version = self.evm_version.unwrap_or_default();
        let compute_units_per_second =
            if self.no_rate_limit { Some(u64::MAX) } else { self.compute_units_per_second };

        let tx_hash: TxHash = self.transaction.parse().wrap_err("invalid transaction hash")?;
        let r = replay_tx_hash(
            &config,
            &evm_opts,
            tx_hash,
            &vec![(tweaked_addr, tweaked_code)].into_iter().collect(),
            compute_units_per_second,
            self.quick,
        )
        .await?;

        let r = r.trace_result()?;
        handle_traces(r, &config, config.chain, vec![], false).await?;

        Ok(())
    }
}

async fn replay_tx_hash(
    config: &Config,
    evm_opts: &EvmOpts,
    tx_hash: TxHash,
    tweaks: &BTreeMap<Address, Bytes>,
    compute_units_per_second: Option<u64>,
    quick: bool,
) -> Result<ExecuteResult> {
    let mut config = config.clone();

    // construct JSON-RPC provider
    let provider = foundry_common::provider::alloy::ProviderBuilder::new(
        &config.get_rpc_url_or_localhost_http()?,
    )
    .compute_units_per_second_opt(compute_units_per_second)
    .build()?;

    // get transactiond ata
    let tx = provider.get_transaction_by_hash(tx_hash).await.unwrap();
    let tx_block_number: u64 =
        tx.block_number.ok_or(eyre!("transaction may still be pending"))?.to();

    // get preceeding transactions in the same block
    let block = provider.get_block(tx_block_number.into(), true).await.unwrap();
    let block = block.ok_or(eyre::eyre!("block not found"))?;

    config.fork_block_number = Some(tx_block_number - 1); // fork from the previous block
    let mut executor = TweakExecutor::new(&config, evm_opts, tweaks).await?;

    // set the state to the moment right before the transaction
    // we execute all transactions before the target transaction
    let mut env = executor.env.clone();
    adjust_block_env(&mut env, &block);
    env.block.number = U256::from(tx_block_number);
    let BlockTransactions::Full(txs) = block.transactions else {
        return Err(eyre::eyre!("block transactions not found"));
    };
    if !quick {
        trace!("Executing transactions before the target transaction in the same block...");
        for (_, tx) in txs.into_iter().enumerate() {
            // System transactions such as on L2s don't contain any pricing info so
            // we skip them otherwise this would cause
            // reverts
            if is_known_system_sender(tx.from)
                || tx.transaction_type.map(|ty| ty.to::<u64>()) == Some(SYSTEM_TRANSACTION_TYPE)
            {
                continue;
            }

            if tx.hash == tx_hash {
                // we reach the target transaction
                break;
            }

            // execute the transaction
            trace!("Executing transaction: {:?}", tx.hash);
            let _ = execute_tx(&mut executor, env.clone(), &tx)?;
        }
    }

    // execute the target transaction
    trace!("Executing target transaction: {:?}", tx.hash);
    let r = execute_tx(&mut executor, env, &tx)?;
    Ok(r)
}

fn adjust_block_env(env: &mut EnvWithHandlerCfg, block: &Block) {
    env.block.timestamp = block.header.timestamp;
    env.block.coinbase = block.header.miner;
    env.block.difficulty = block.header.difficulty;
    env.block.prevrandao = Some(block.header.mix_hash.unwrap_or_default());
    env.block.basefee = block.header.base_fee_per_gas.unwrap_or_default();
    env.block.gas_limit = block.header.gas_limit;
}

enum ExecuteResult {
    Call(RawCallResult),
    Create(DeployResult),
    Revert(EvmError),
}

impl ExecuteResult {
    pub fn trace_result(self) -> Result<TraceResult> {
        match self {
            ExecuteResult::Call(r) => Ok(TraceResult::from(r)),
            ExecuteResult::Create(r) => Ok(TraceResult::from(r)),
            ExecuteResult::Revert(e) => {
                TraceResult::try_from(e).map_err(|e| eyre!("revert: {}", e))
            }
        }
    }
}

fn execute_tx(
    executor: &mut TweakExecutor,
    mut env: EnvWithHandlerCfg,
    tx: &Transaction,
) -> Result<ExecuteResult> {
    configure_tx_env(&mut env, tx);
    if let Some(_) = tx.to {
        let r = executor.commit_tx_with_env(env.clone()).wrap_err_with(|| {
            format!("Failed to execute transaction: {:?} in block {}", tx.hash, env.block.number)
        })?;
        Ok(ExecuteResult::Call(r))
    } else {
        let r = executor.deploy_with_env(env, None);
        match r {
            Ok(r) => Ok(ExecuteResult::Create(r)),
            Err(e) => Ok(ExecuteResult::Revert(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use alloy_primitives::{Address, Bytes, TxHash};
    use foundry_cli::utils::handle_traces;
    use foundry_compilers::EvmVersion;
    use foundry_config::{figment::Figment, find_project_root_path, Config};
    use foundry_evm::opts::EvmOpts;

    const RPC: &str = "http://localhost:8545";

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn test_replay_tx_hash() {
        let tx: TxHash =
            "0xbfa440cd7df20320fe8400e4f61113379a018e3904eef7cf6085cf6cf22bcdb9".parse().unwrap();

        let figment = Config::figment_with_root(find_project_root_path(None).unwrap());
        let evm_opts = figment.extract::<EvmOpts>().unwrap();
        let mut config = Config::try_from(figment).unwrap().sanitized();
        config.eth_rpc_url = Some(RPC.to_string());
        config.evm_version = EvmVersion::Shanghai;
        let r = super::replay_tx_hash(&config, &evm_opts, tx, &BTreeMap::default(), None, false)
            .await
            .unwrap();
        let super::ExecuteResult::Call(result) = &r else {
            panic!("expected ExecuteResult::Call");
        };
        assert_eq!(result.reverted, false);
        assert_eq!(result.gas_used, 163_955);
        let r = r.trace_result().unwrap();
        handle_traces(r, &config, config.chain, vec![], false).await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn test_replay_tx_hash_with_tweak() {
        let tx: TxHash =
            "0xbfa440cd7df20320fe8400e4f61113379a018e3904eef7cf6085cf6cf22bcdb9".parse().unwrap();
        let factory: Address = "0x8d1fA935E5e8a5440c9Efc96C0d9fF387eBb179B".parse().unwrap();
        let tweaked_code: Bytes = "0xfe".parse().unwrap();

        let mut config = Config::default();
        let figment: Figment = config.clone().into();
        let evm_opts = figment.extract::<EvmOpts>().unwrap();
        config.eth_rpc_url = Some(RPC.to_string());

        let r = super::replay_tx_hash(
            &config,
            &evm_opts,
            tx,
            &BTreeMap::from([(factory, tweaked_code)]),
            None,
            false,
        )
        .await
        .unwrap()
        .trace_result()
        .unwrap();
        assert!(!r.success);
        handle_traces(r, &config, config.chain, vec![], false).await.unwrap();
    }
}
