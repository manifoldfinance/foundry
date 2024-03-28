//! Compatibility check of tweaking an on-chain contract with a local cloned project.
//! The local project usually should be created by `forge clone` command.
//! The `clone.toml` metadata file should be present in the root directory of the project.
//! Users may modify the source code of the cloned project, but the storage layout should remain the same as the original contract.

use std::path::PathBuf;

use foundry_compilers::artifacts::StorageLayout;

use crate::metadata::CloneMetadata;

/// Check the tweak compatibility of the project with the given root.
/// The project is compatible if:
/// 1. the project has the `clone.toml` metadata file in the root directory, which defines its original contract on chain.
/// 2. the project's storage layout is the same as the original contract.
/// If the project is not compatible, an error is returned.
pub fn check_compatibility(root: &PathBuf) -> eyre::Result<()> {
    // the clone metadata
    let clone_metadata = CloneMetadata::load_with_root(root).map_err(|e| {
        eyre::eyre!("the clone metadata file (clone.toml) does not exist or is invalid: {}", e)
    })?;

    // to check the storage layout compatibility, we need to download the original contract's code from etherscan and compile.
    let original_layout = get_original_storage_layout(&clone_metadata)?;
    let current_layout = get_current_storage_layout(root)?;
    check_storage_layout_compatibility(original_layout, current_layout)
}

pub fn get_original_storage_layout(_clone_metadata: &CloneMetadata) -> eyre::Result<StorageLayout> {
    todo!()
}

pub fn get_current_storage_layout(_root: &PathBuf) -> eyre::Result<StorageLayout> {
    todo!()
}

pub fn check_storage_layout_compatibility(
    _original: StorageLayout,
    _current: StorageLayout,
) -> eyre::Result<()> {
    todo!()
}
