use std::{
    collections::BTreeSet,
    ops::{Deref, DerefMut},
};

use eyre::Result;
use foundry_config::Config;
use foundry_evm::{
    backend::Backend,
    executors::{Executor, ExecutorBuilder},
    opts::EvmOpts,
};

use crate::metadata::ClonedProject;

/// The runner that replays a historical transaction.
pub struct TweakExecutor {
    /// The underlying EVM executor.
    executor: Executor,

    /// A set of ClonedProjects that are used to tweak the on-chain contract.
    tweaks: BTreeSet<ClonedProject>,
}

impl TweakExecutor {
    pub async fn new(
        config: &Config,
        mut evm_opts: EvmOpts,
        tweaks: impl Iterator<Item = ClonedProject>,
    ) -> Result<Self> {
        evm_opts.fork_url = Some(config.get_rpc_url_or_localhost_http()?.into_owned());
        evm_opts.fork_block_number = config.fork_block_number;
        let env = evm_opts.evm_env().await?;
        let fork = evm_opts.get_fork(config, env.clone());
        let db = Backend::spawn(fork);
        // let tweaks =
        // for tweak in tweaks {
        //     let output = tweak.compile_safe()?;
        // }
        // let executor =
        // ExecutorBuilder::new().inspectors(|stack| stack.trace(true).debug(true)).build(env, db);
        // Ok(Self { executor, tweaks: tweaks.collect() })
        todo!()
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
