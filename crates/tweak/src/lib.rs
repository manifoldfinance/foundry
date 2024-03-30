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

pub async fn build_tweak_map(
    projects: &Vec<ClonedProject>,
    rpc: &RpcOpts,
) -> Result<BTreeMap<Address, Bytes>> {
    let mut tweaks = BTreeMap::new();
    for project in projects {
        let metadata = &project.metadata;
        let address = metadata.address;
        let code = code::generate_tweaked_code(rpc, project).await?;
        tweaks.insert(address, code);
    }
    Ok(tweaks)
}

pub fn build_tweaked_backend(
    fork: Option<CreateFork>,
    tweaks: &BTreeMap<Address, Bytes>,
) -> Result<Backend> {
    let mut backend = Backend::spawn(fork);
    for (address, code) in tweaks {
        tweak_backend_once(&mut backend, address.clone(), code.clone())?;
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

pub fn tweak_backend(backend: &mut Backend, tweaks: &BTreeMap<Address, Bytes>) -> Result<()> {
    for (tweak_address, tweaked_code) in tweaks {
        let mut info = backend.basic(tweak_address.clone())?.unwrap_or_default();
        let code_hash = if tweaked_code.as_ref().is_empty() {
            revm::primitives::KECCAK_EMPTY
        } else {
            B256::from_slice(&alloy_primitives::keccak256(tweaked_code.as_ref())[..])
        };
        info.code_hash = code_hash;
        info.code =
            Some(Bytecode::new_raw(alloy_primitives::Bytes(tweaked_code.clone().0)).to_checked());
        backend.insert_account_info(tweak_address.clone(), info);
    }

    Ok(())
}
