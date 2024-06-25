//! Constant values used during tweaking the code.

use alloy_primitives::Address;
use foundry_config::NamedChain;

/// Non-standard precompiled contracts
pub enum NonStandardPrecompiled {
    BinanceSmartChain([&'static str; 11]),
}

impl NonStandardPrecompiled {
    /// Binance Smart Chain non-standard precompiled contracts
    /// Collected from <https://docs.bnbchain.org/docs/learn/system-contract/>
    pub const BSC_NON_STANDARD_PRECOMPILED: NonStandardPrecompiled =
        NonStandardPrecompiled::BinanceSmartChain([
            "0x0000000000000000000000000000000000001000",
            "0x0000000000000000000000000000000000001001",
            "0x0000000000000000000000000000000000001002",
            "0x0000000000000000000000000000000000001003",
            "0x0000000000000000000000000000000000001004",
            "0x0000000000000000000000000000000000001005",
            "0x0000000000000000000000000000000000001006",
            "0x0000000000000000000000000000000000001007",
            "0x0000000000000000000000000000000000001008",
            "0x0000000000000000000000000000000000002000",
            "0x0000000000000000000000000000000000002001",
        ]);

    pub fn get_addresses(&self) -> Vec<Address> {
        match self {
            NonStandardPrecompiled::BinanceSmartChain(addresses) => {
                addresses.iter().map(|a| a.parse().expect("incorrect address")).collect()
            }
        }
    }

    pub fn get_precomiled_address(chain_id: NamedChain) -> Option<Vec<Address>> {
        match chain_id {
            NamedChain::BinanceSmartChain | NamedChain::BinanceSmartChainTestnet => {
                Some(Self::BSC_NON_STANDARD_PRECOMPILED.get_addresses())
            }
            _ => None,
        }
    }
}
