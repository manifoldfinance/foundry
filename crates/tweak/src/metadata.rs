use std::path::PathBuf;

use alloy_primitives::{Address, Bytes, ChainId, TxHash};
use eyre::{eyre, Result};
use foundry_cli::opts::RpcOpts;
use foundry_common::compile::ProjectCompiler;
use foundry_compilers::{
    artifacts::{output_selection::ContractOutputSelection, StorageLayout},
    ConfigurableContractArtifact, ProjectCompileOutput,
};
use foundry_config::Config;

/// ClonedProject represents a foundry project that is cloned by the `forge clone` command.
/// It couples with an on-chain contract instance.
/// Users may modify the source code of the cloned project, but the storage layout should remain the
/// same as the original contract. The cloned project will be used to tweak the on-chain contract.
#[derive(Debug, Clone)]
pub struct ClonedProject {
    pub root: PathBuf,
    pub config: Config,
    pub metadata: CloneMetadata,
}

impl PartialEq for ClonedProject {
    fn eq(&self, other: &Self) -> bool {
        self.root == other.root
    }
}

impl Eq for ClonedProject {}

impl PartialOrd for ClonedProject {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ClonedProject {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.root.cmp(&other.root)
    }
}

impl ClonedProject {
    /// Load the cloned project from the root directory of the project.
    /// If the clone metadata file does not exist, an error is returned.
    pub fn load_with_root(root: impl Into<PathBuf>) -> Result<ClonedProject> {
        let root = root.into();
        let cwd = std::env::current_dir()?;
        std::env::set_current_dir(&root)?;
        let config = Config::load();
        std::env::set_current_dir(cwd)?;
        let metadata = CloneMetadata::load_with_root(&root)?;
        Ok(ClonedProject { root, config, metadata })
    }

    /// Compile the project and return the artifacts.
    /// The compile output is cached.
    /// A workaround for the insufficient implementation of Config::load_with_root.
    pub fn compile_safe(&self) -> Result<ProjectCompileOutput> {
        // load the foundry config
        // XXX (ZZ): some insufficient implementation of Config::load_with_root
        // prevents us from invoking this function directly
        let cwd = std::env::current_dir()?;
        std::env::set_current_dir(&self.root)?;

        // compile the project to get the current artifacts
        let mut config = self.config.clone();
        config.extra_output.push(ContractOutputSelection::StorageLayout);
        let output = ProjectCompiler::new().compile(&config.project()?)?;

        std::env::set_current_dir(cwd)?;
        Ok(output)
    }

    /// Get the artifact of the main contract of the project.
    pub fn main_artifact(&self) -> Result<ConfigurableContractArtifact> {
        let output = self.compile_safe()?;
        let (_, _, artifact) = output
            .artifacts_with_files()
            .find(|(_, contract_name, _)| **contract_name == self.metadata.target_contract)
            .ok_or_else(|| {
                eyre!("the contract {} is not found in the project", self.metadata.target_contract)
            })?;
        Ok(artifact.to_owned())
    }

    /// Get the tweaked code of the main contract of the project.
    pub async fn tweaked_code(&self, rpc: &RpcOpts) -> Result<Bytes> {
        // check chain id
        if self.config.chain.unwrap_or_default().id() != self.metadata.chain_id {
            return Err(eyre!(
                "the chain id of the project ({}) is different from the chain id of the on-chain contract ({})",
                self.config.chain.unwrap_or_default().id(),
                self.metadata.chain_id
            ));
        }
        // check the storage compatibility
        super::compatibility::check_storage_compatibility(self)?;

        // get tweaked code
        let code = super::code::generate_tweaked_code(rpc, self).await?;
        Ok(code)
    }
}

/// CloneMetadata stores the metadata that are not included by `foundry.toml` but necessary for a
/// cloned contract. This struct is the twin of the `CloneMetadata` struct in the `clone` command of
/// `forge` crate.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct CloneMetadata {
    /// The path to the source file that contains the contract declaration.
    /// The path is relative to the root directory of the project.
    pub path: PathBuf,
    /// The name of the contract in the file.
    pub target_contract: String,
    /// The address of the contract on the blockchian.
    pub address: Address,
    /// The chain id.
    pub chain_id: ChainId,
    /// The transaction hash of the creation transaction.
    pub creation_transaction: TxHash,
    /// The address of the deployer (caller of the CREATE/CREATE2).
    pub deployer: Address,
    /// The constructor arguments of the contract.
    pub constructor_arguments: Bytes,
    /// The storage layout of the contract.
    pub storage_layout: StorageLayout,
}

impl CloneMetadata {
    /// Load the metadata from the `clone.toml` file in the root directory of the project.
    /// If the file does not exist, an error is returned.
    pub fn load_with_root(root: impl Into<PathBuf>) -> Result<CloneMetadata> {
        let path = root.into().join(".clone.meta");
        let metadata = std::fs::read_to_string(path)?;
        let metadata = serde_json::from_str(&metadata)?;
        Ok(metadata)
    }
}
