# Foundry with on-chain contract Tweak!

**Tweak** allows users/developers to alter the code of an on-chain contract with the on-chain state untouched.
Almost any modification is allowed, as long as the storage layout is preserved.

With **Tweak**, you can:
- Add `console.log()` in any on-chain contracts with source code available on Etherscan.
- Change the logic of an on-chain contract (e.g., fixing bugs, conduct what-if analysis, etc.)

Tweaking on-chain contracts are especially useful when:
- inspecting the execution on-chain transactions;
- investigating the logic of a complex contract (e.g., UniswapV3) on chain;
- debug the interaction with on-chain contracts which produce unexpected revert errors.

## Installation

This project is a fork of foundry.
The easiest way to install is to compile this project and replace the foundry toolchain originally on your machine.

```
cargo build
```

The executables are available in `target/debug` folder. 
All the tools that you are familiar in foundry are still there.

What is enhanced is the `cast` and `forge` command.

## Usage 1: Clone a verified contract code from Etherscan

```
forge clone <address> <path>
```

`forge clone` is a new feature that downloads the source code of a verified contract at `<address>` from Etherscan (or other block explorers supported by foundry) and save as a foundry project in the specified `<path>`.

The cloned project is fully compilable foundry project, guaranteed to generate exactly the same bytecode as the on-chain contract.

## Usage 2: Tweak one on-chain contract and replay a historical transaction invoking it

```
cd path/to/cloned/contract/project
forge replay <transaction_hash>
```

If the current working directory is a foundry project created by `forge clone`, then the command `forge replay` is available to replay a historical transaction with the on-chain contract's code tweaked by the current project.
Note that the cloned project "knows" which contract address it should tweak.

You may want to modify the code of the cloned contract (e.g., add `console.log`s) before running `forge replay`.

## Usage 3: Tweak multiple on-chain contracts and replay a historical transaction invoking them

```
cast run --tweak <path/to/cloned/project1> --tweak <path/to/cloned/project2> <transaction_hash>
```

`cast run` is also enhanced by allowing specified cloned projects to tweak the code of multiple on-chain contracts. 
Note that each cloned project "knows" which contract address it should tweak.

## Disclaimer

The **Tweak** feature is still under active development as part of the __EtherDebug__ project, whose ultimate goal is improve the overall development and debugging experience of EVM-compatibla smart contracts.

The functionality is not stable yet and may suffer from breaking change in the future.
Any contribution (bug reports, PRs, documentation, etc.) is welcome and greatly appreciated.