use std::{
    collections::BTreeSet,
    ops::{Deref, DerefMut},
};

use alloy_primitives::{keccak256, Address, Bytes, B256};
use eyre::Result;
use foundry_config::Config;
use foundry_evm::{
    backend::Backend,
    executors::{Executor, ExecutorBuilder},
    opts::EvmOpts,
};
use revm::{
    primitives::{Bytecode, KECCAK_EMPTY},
    Database,
};

use crate::{
    code::generate_tweaked_code, compatibility::check_storage_compatibility,
    metadata::ClonedProject,
};

/// The executor with on-chain contracts tweaked on a forked backend.
pub struct TweakExecutor {
    /// The underlying EVM executor.
    executor: Executor,

    /// A set of ClonedProjects that are used to tweak the on-chain contract.
    pub tweaks: BTreeSet<ClonedProject>,
}

impl TweakExecutor {
    /// Create a new TweakExecutor with the given configuration and tweaks.
    /// `config` is the configuration of current foundry project which requires this executor to run.
    /// `evm_opts` is the EVM options to configure the fork backend.
    /// `tweaks` is a list of ClonedProjects that will be used to tweak the on-chain contract.
    pub async fn new(
        config: &Config,
        mut evm_opts: EvmOpts,
        tweaks: impl Iterator<Item = ClonedProject>,
    ) -> Result<Self> {
        // construct the fork backend
        let chain_id = config.chain.unwrap_or_default().id();
        evm_opts.fork_url = Some(config.get_rpc_url_or_localhost_http()?.into_owned());
        evm_opts.fork_block_number = config.fork_block_number;
        let env = evm_opts.evm_env().await?;
        let fork = evm_opts.get_fork(config, env.clone());
        let mut db = Backend::spawn(fork);

        // tweak the code of the on-chain contracts
        let tweaks: BTreeSet<ClonedProject> = tweaks.collect();
        for tweak in tweaks.iter() {
            // we need to check the compatibility
            // storage layout
            check_storage_compatibility(tweak)?;
            // chain id
            if tweak.metadata.chain_id != chain_id {
                return Err(eyre::eyre!(
                    "the chain id ({}) of the cloned project is different from the current chain id ({}): {}",
                    tweak.metadata.chain_id,
                    chain_id,
                    tweak.root.to_string_lossy()
                ));
            }
            // calculate the tweaked code
            let tweaked_code =
                generate_tweaked_code(&tweak.root, &tweak.metadata, &tweak.main_artifact()?)?;
            Self::set_code(&mut db, tweak.metadata.address, tweaked_code)?;
        }

        // construct the underlying executor
        let executor = ExecutorBuilder::new()
            .inspectors(|stack| stack.trace(true).debug(true))
            .spec(config.evm_spec_id())
            .build(env, db);
        Ok(Self { executor, tweaks })
    }

    fn set_code(db: &mut Backend, address: Address, code: Bytes) -> Result<()> {
        let mut info = db.basic(address)?.unwrap_or_default();
        let code_hash = if code.as_ref().is_empty() {
            KECCAK_EMPTY
        } else {
            B256::from_slice(&keccak256(code.as_ref())[..])
        };
        info.code_hash = code_hash;
        info.code = Some(Bytecode::new_raw(alloy_primitives::Bytes(code.0)).to_checked());
        db.insert_account_info(address, info);
        Ok(())
    }
}

impl Deref for TweakExecutor {
    type Target = Executor;

    fn deref(&self) -> &Self::Target {
        &self.executor
    }
}

impl DerefMut for TweakExecutor {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.executor
    }
}
