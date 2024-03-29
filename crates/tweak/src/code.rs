//! Code generation for the contract we are going to tweak.
//! The contract should from a cloned project created by `forge clone` command.
//! The generation has to happen after the compatibility check.

use alloy_primitives::{Address, Bytes};
use alloy_providers::tmp::TempProvider;
use alloy_rpc_types::{BlockId, BlockTransactions};
use eyre::{eyre, Context, Result};
use foundry_cli::opts::RpcOpts;
use foundry_common::{
    is_known_system_sender, provider::alloy::ProviderBuilder, SYSTEM_TRANSACTION_TYPE,
};
use foundry_compilers::{Artifact, ConfigurableContractArtifact};
use foundry_config::{figment::Figment, Config, NamedChain};
use foundry_evm::{
    backend::Backend,
    executors::{EvmError, ExecutorBuilder},
    opts::EvmOpts,
    utils::configure_tx_env,
};
use revm::{
    interpreter::{CreateInputs, CreateOutcome},
    primitives::EnvWithHandlerCfg,
    EvmContext, Inspector,
};

use crate::ClonedProject;

struct TweakInspctor {
    creation_count: u64,
    contract_address: Option<Address>,
    target_creation_count: Option<u64>,
    tweaked_creation_code: Option<Bytes>,
    tweaked_contract_address: Option<Address>,
}

impl TweakInspctor {
    pub fn new(contract_address: Option<Address>, tweaked_creation_code: Option<Bytes>) -> Self {
        Self {
            creation_count: 0,
            contract_address,
            target_creation_count: None,
            tweaked_creation_code,
            tweaked_contract_address: None,
        }
    }

    pub fn prepare_for_pinpoint(&mut self) -> Result<()> {
        self.creation_count = 0;

        if self.contract_address.is_none() {
            return Err(eyre!("the contract address is not found"));
        }

        Ok(())
    }

    pub fn prepare_for_tweak(&mut self) -> Result<()> {
        self.creation_count = 0;

        if self.target_creation_count.is_none() {
            return Err(eyre!("the target creation count is not found"));
        }

        if self.tweaked_creation_code.is_none() {
            return Err(eyre!("the tweaked creation code is not found"));
        }

        Ok(())
    }
}

impl Inspector<&mut Backend> for TweakInspctor {
    #[inline]
    fn create(
        &mut self,
        _: &mut EvmContext<&mut Backend>,
        inputs: &mut CreateInputs,
    ) -> Option<CreateOutcome> {
        // first update the creation_count
        self.creation_count += 1;

        // we then check creation count as the target one
        if Some(self.creation_count) == self.target_creation_count {
            // we are going to tweak the creation code
            if let Some(tweaked_creation_code) = &self.tweaked_creation_code {
                inputs.init_code = tweaked_creation_code.clone();
            }
        }

        None
    }

    #[inline]
    fn create_end(
        &mut self,
        _: &mut EvmContext<&mut Backend>,
        _: &CreateInputs,
        outcome: CreateOutcome,
    ) -> CreateOutcome {
        // we shall first distinguish the replay stage
        if let Some(target_count) = self.target_creation_count {
            // record the tweaked contract address
            if self.creation_count == target_count {
                self.tweaked_contract_address = outcome.address;
            }
        } else {
            // we are here to find the target creation count
            if outcome.address == self.contract_address {
                self.target_creation_count = Some(self.creation_count);
            }
        }

        outcome
    }
}

pub async fn generate_tweaked_code(
    rpc: &RpcOpts,
    project: &ClonedProject,
    artifact: &ConfigurableContractArtifact,
) -> Result<Bytes> {
    // prepare the execution backend
    let (mut db, mut env) = prepare_backend(&rpc, &project).await?;

    // prepare the deployment bytecode (w/ parameters)
    let tweaked_creation_code = prepare_tweaked_creation_code(&project, artifact)?;

    // let hook into the creation process
    let mut inspector =
        TweakInspctor::new(Some(project.metadata.address), Some(tweaked_creation_code));

    // disable gas_limit for the inspector
    env.cfg.disable_block_gas_limit = true;
    env.tx.gas_limit = 0;

    // round 1: pinpoint the target creation count
    inspector.prepare_for_pinpoint()?;
    let rv = db.inspect(&mut env, &mut inspector)?;
    if !rv.result.is_success() {
        return Err(eyre!("failed to pinpoint the target creation count:\n {:#?}", rv.result));
    }

    // round 2: tweak the creation code
    inspector.prepare_for_tweak()?;
    let rv = db.inspect(&mut env, &mut inspector)?;
    if !rv.result.is_success() {
        return Err(eyre!("failed to tweak the creation code:\n {:#?}", rv.result));
    }

    let tweaked_account = rv
        .state
        .get(&project.metadata.address)
        .ok_or(eyre!("contract not found after tweaking"))?;
    let tweaked_account_info = &tweaked_account.info;
    let tweaked_code = &tweaked_account_info
        .code
        .clone()
        .ok_or(eyre!("contract code not found after tweaking"))?;

    Ok(tweaked_code.bytes().clone())
}

fn prepare_tweaked_creation_code(
    project: &ClonedProject,
    artifact: &ConfigurableContractArtifact,
) -> Result<Bytes> {
    let bytecode = artifact.get_bytecode().ok_or(eyre!("the contract does not have bytecode"))?;
    let deployment_bytecode =
        bytecode.bytes().ok_or(eyre!("the contract does not have bytecode"))?;
    let constructor_arguments = &project.metadata.constructor_arguments;

    // concate the deployment bytecode with the constructor arguments
    let mut tweaked_creation_code = deployment_bytecode.to_vec();
    tweaked_creation_code.extend_from_slice(&constructor_arguments[..]);

    Ok(Bytes::from(tweaked_creation_code))
}

async fn prepare_backend(
    rpc: &RpcOpts,
    project: &ClonedProject,
) -> Result<(Backend, EnvWithHandlerCfg)> {
    // get rpc_url
    let rpc_url = &rpc.url(Some(&project.config))?.ok_or(eyre!("rpc url is not found"))?;

    // prepare the RPC provider
    let provider = ProviderBuilder::new(rpc_url)
        .chain(NamedChain::try_from(project.metadata.chain_id)?)
        .build()?;

    // get block number
    let tx_receipt = provider
        .get_transaction_receipt(project.metadata.creation_transaction)
        .await?
        .ok_or(eyre!("the transaction is not mined"))?;
    let block_number =
        tx_receipt.block_number.ok_or(eyre!("the transaction is not mined"))?.to::<u64>();

    // get the figment from the cloned project's config
    let figment: Figment = project.config.clone().into();
    let figment = figment.merge(rpc);

    // set evm options
    let mut evm_opts = figment.extract::<EvmOpts>()?;
    evm_opts.fork_url = Some(rpc_url.to_string());
    evm_opts.fork_block_number = Some(block_number - 1);

    // get an updated config
    let mut config = Config::try_from(figment)?.sanitized();
    config.fork_block_number = Some(block_number - 1);

    // get env
    let env = evm_opts.evm_env().await?;

    // get backend and create a fork
    let db = Backend::spawn(evm_opts.get_fork(&config, env.clone()));

    // create the executor and the corresponding env
    let mut executor = ExecutorBuilder::new().spec(project.config.evm_spec_id()).build(env, db);
    let mut env = executor.env.clone();

    // then, we are going to replay all transactions before the creation transaction
    let block = provider
        .get_block(BlockId::Number(block_number.into()), true)
        .await?
        .ok_or(eyre!("block not found"))?;
    let BlockTransactions::Full(txs) = block.transactions else {
        return Err(eyre::eyre!("block transactions not found"));
    };

    for tx in txs {
        // skip system transactions
        if is_known_system_sender(tx.from)
            || tx.transaction_type.map(|ty| ty.to::<u64>()) == Some(SYSTEM_TRANSACTION_TYPE)
        {
            continue;
        }

        // always configure the transaction environment
        configure_tx_env(&mut env, &tx);

        // find the creation transaction
        if tx.hash == project.metadata.creation_transaction {
            break;
        }

        if tx.to.is_some() {
            let rv = executor.commit_tx_with_env(env.clone()).wrap_err_with(|| {
                format!(
                    "Failed to execute transaction: {:?} in block {}",
                    tx.hash, env.block.number
                )
            })?;
            println!("{:#?}: {:#?}", tx.hash, rv.exit_reason);
        } else {
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
    }

    Ok((executor.backend, env))
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::{
        code::{prepare_backend, TweakInspctor},
        metadata::CloneMetadata,
        ClonedProject,
    };

    use alloy_primitives::{address, TxHash};
    use foundry_cli::opts::RpcOpts;
    use tempfile;

    fn get_fake_project() -> ClonedProject {
        let fake_root = tempfile::tempdir().unwrap().path().to_path_buf();

        ClonedProject {
            root: fake_root,
            config: Default::default(),
            metadata: CloneMetadata {
                path: "src/FakeContract.sol".into(),
                target_contract: "FakeContract".into(),
                chain_id: 1,
                address: address!("8B3D32cf2bb4d0D16656f4c0b04Fa546274f1545"),
                creation_transaction: TxHash::from_str(
                    "0x79820495643caf5a1e7e96578361c9ddba0e0735cd684ada7450254f6fd58f51",
                )
                .unwrap(),
                deployer: address!("958892b4a0512b28aaac890fc938868bbd42f064"),
                constructor_arguments: Default::default(),
                storage_layout: Default::default(),
            },
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn test_with_fake_project() {
        let fake_project = get_fake_project();
        let rpc = RpcOpts { url: Some("http://localhost:8545".to_string()), ..Default::default() };
        let (mut db, mut env) = prepare_backend(&rpc, &fake_project).await.unwrap();

        // check whether the backend is created successfully by replaying the transaction
        let mut inspector = TweakInspctor::new(Some(fake_project.metadata.address), None);
        inspector.prepare_for_pinpoint().unwrap();

        env.tx.gas_limit *= 2;
        let rv = db.inspect(&mut env, &mut inspector).unwrap();

        assert!(
            inspector.target_creation_count == Some(1),
            "Failed to find the target creation count"
        );
        assert!(rv.result.is_success(), "Failed to replay the transaction");
        assert!(rv.state[&fake_project.metadata.address].info.code.is_some());
    }
}
