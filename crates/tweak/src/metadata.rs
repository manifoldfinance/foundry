use std::path::PathBuf;

use alloy_primitives::{Address, ChainId, TxHash};
use eyre::Result;

/// CloneMetadata stores the metadata that are not included by `foundry.toml` but necessary for a cloned contract.
/// The metadata can be serialized to the `clone.toml` file in the cloned project root.
/// This struct is the twin of the `CloneMetadata` struct in the `clone` command of `forge` crate.
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
}

impl CloneMetadata {
    /// Load the metadata from the `clone.toml` file in the root directory of the project.
    /// If the file does not exist, an error is returned.
    pub fn load_with_root(root: &PathBuf) -> Result<CloneMetadata> {
        let path = root.join("clone.toml");
        let metadata = std::fs::read_to_string(&path)?;
        let metadata = toml::from_str(&metadata)?;
        Ok(metadata)
    }
}
