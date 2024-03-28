pub mod code;
pub mod compatibility;
mod metadata;

use eyre::{eyre, Result};
use foundry_common::compile::ProjectCompiler;
use foundry_compilers::{
    artifacts::output_selection::ContractOutputSelection, ProjectCompileOutput,
};
use foundry_config::Config;
use metadata::CloneMetadata;
use std::{env::set_current_dir, path::PathBuf};

pub fn tweak(root: &PathBuf) -> Result<()> {
    // collect the clone metadata
    let metadata = CloneMetadata::load_with_root(root).map_err(|e| {
        eyre!("the clone metadata file (clone.toml) does not exist or is invalid: {}", e)
    })?;

    let output = compile_project_safe(root)?;
    let (_, _, artifact) = output
        .artifacts_with_files()
        .find(|(_, contract_name, _)| **contract_name == metadata.target_contract)
        .ok_or_else(|| {
            eyre!("the contract {} is not found in the project", metadata.target_contract)
        })?;

    compatibility::check_compatibility(&root, &metadata, &artifact)?;
    code::generate_tweaked_code(&root, &metadata, &artifact)?;

    Ok(())
}

/// Compile the project and return the artifacts.
/// A workaround for the insufficient implementation of Config::load_with_root.
fn compile_project_safe(root: &PathBuf) -> Result<ProjectCompileOutput> {
    // load the foundry config
    // XXX (ZZ): some insufficient implementation of Config::load_with_root
    // prevents us from invoking this function directly
    let cwd = std::env::current_dir()?;
    set_current_dir(root)?;
    let mut config = Config::load();

    // compile the project to get the current artifacts
    config.extra_output.push(ContractOutputSelection::StorageLayout);
    let output = ProjectCompiler::new().compile(&config.project()?)?;

    set_current_dir(cwd)?;
    Ok(output)
}
