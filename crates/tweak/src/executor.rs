use std::{
    collections::BTreeMap,
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

/// The executor with on-chain contracts tweaked on a forked backend.
pub struct TweakExecutor {
    /// The underlying EVM executor.
    executor: Executor,
}

impl TweakExecutor {
    /// Create a new TweakExecutor with the given configuration and tweaks.
    /// `config` is the configuration of current foundry project which requires this executor to run.
    /// `evm_opts` is the EVM options to configure the fork backend.
    /// `tweaks` is a mapping from the address of the on-chain contract to the tweaked code.
    pub async fn new(
        config: &Config,
        evm_opts: &EvmOpts,
        tweaks: &BTreeMap<Address, Bytes>,
    ) -> Result<Self> {
        // construct the fork backend
        let mut evm_opts = evm_opts.clone();
        evm_opts.fork_url = Some(config.get_rpc_url_or_localhost_http()?.into_owned());
        evm_opts.fork_block_number = config.fork_block_number;
        let env = evm_opts.evm_env().await?;
        let fork = evm_opts.get_fork(config, env.clone());
        let mut db = Backend::spawn(fork);

        // tweak the code of the on-chain contracts
        for (tweak_address, tweak_code) in tweaks.into_iter() {
            Self::set_code(&mut db, tweak_address.clone(), tweak_code.clone())?;
        }

        // construct the underlying executor
        let executor = ExecutorBuilder::new()
            .inspectors(|stack| stack.trace(true).debug(true))
            .spec(config.evm_spec_id())
            .build(env, db);
        Ok(Self { executor })
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
