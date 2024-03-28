//! Code generation for the contract we are going to tweak.
//! The contract should from a cloned project created by `forge clone` command.
//! The generation has to happen after the compatibility check.

use std::path::PathBuf;

use alloy_primitives::Bytes;
use eyre::Result;
use foundry_block_explorers::contract::Metadata;
use foundry_compilers::{Artifact, ConfigurableContractArtifact};

use crate::metadata::{self, CloneMetadata};

pub fn generate_tweaked_code(
    root: &PathBuf,
    clone_metadata: &CloneMetadata,
    artifact: &ConfigurableContractArtifact,
) -> Result<Bytes> {
    let bytecode = artifact.get_bytecode();
    let aaa = artifact.get_bytecode_bytes().unwrap(); // Unwrap the Option value

    Ok(Bytes::new())
}
