pub mod code;
pub mod compatibility;
mod metadata;

use std::collections::BTreeMap;

use alloy_primitives::{keccak256, Address, Bytes, B256};
use eyre::Result;

use foundry_cli::opts::RpcOpts;
use foundry_evm::{backend::Backend, fork::CreateFork};
pub use metadata::ClonedProject;
use revm::{
    primitives::{Bytecode, KECCAK_EMPTY},
    Database,
};

pub type TweakData = BTreeMap<Address, Bytes>;

pub async fn build_tweak_data(projects: &Vec<ClonedProject>, rpc: &RpcOpts) -> Result<TweakData> {
    let mut tweak_data = BTreeMap::new();
    for project in projects {
        let metadata = &project.metadata;
        let address = metadata.address;
        let code = code::generate_tweaked_code(rpc, project).await?;
        tweak_data.insert(address, code);
    }
    Ok(tweak_data)
}

pub fn build_tweaked_backend(fork: Option<CreateFork>, tweak_data: &TweakData) -> Result<Backend> {
    let mut backend = Backend::spawn(fork);
    for (address, code) in tweak_data {
        tweak_backend_once(&mut backend, *address, code.clone())?;
    }
    Ok(backend)
}

/// Tweak the code of a contract in the blockchain backend.
pub fn tweak_backend_once(
    backend: &mut Backend,
    tweak_address: Address,
    tweaked_code: Bytes,
) -> Result<()> {
    let mut info = backend.basic(tweak_address)?.unwrap_or_default();
    let code_hash = if tweaked_code.as_ref().is_empty() {
        KECCAK_EMPTY
    } else {
        B256::from_slice(&keccak256(tweaked_code.as_ref())[..])
    };
    info.code_hash = code_hash;
    info.code = Some(Bytecode::new_raw(alloy_primitives::Bytes(tweaked_code.0)).to_checked());
    backend.insert_account_info(tweak_address, info);
    Ok(())
}

pub fn tweak_backend(backend: &mut Backend, tweak_data: &TweakData) -> Result<()> {
    for (tweak_address, tweaked_code) in tweak_data {
        let mut info = backend.basic(*tweak_address)?.unwrap_or_default();
        let code_hash = if tweaked_code.as_ref().is_empty() {
            revm::primitives::KECCAK_EMPTY
        } else {
            B256::from_slice(&alloy_primitives::keccak256(tweaked_code.as_ref())[..])
        };
        info.code_hash = code_hash;
        info.code =
            Some(Bytecode::new_raw(alloy_primitives::Bytes(tweaked_code.clone().0)).to_checked());
        backend.insert_account_info(*tweak_address, info);
    }

    Ok(())
}
