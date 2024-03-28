# foundry-tweak

The functionalities to allow tweak the code of an on-chain contract. 

## Use Scenario

1. Given an address of a contract on a blockchain (as well as a JSON-RPC endpoint), and a foundry project.
2. Find the creation transaction of that contract.
3. Resimulate the deployment of that contract with the original deployment arguments but with the code of the foundry project, and obtain the new deployed bytecode.
4. fork the blockchain and replace the code of the on-chain contract.
5. What is provided is a tweaked EVM runtime where the code of the contract is tweaked.
6. A lot of things can be done afterwards, including replay transaction or send a new transaction to invoke the tweaked contract.

## Specification

### Input

- the local foundry project (and specify contract)
- contract address to tweak
- json-rpc to fork the chain
- etherscan API key (optional)

### Pipeline

0. Ensure that the local foundry project is compatible with the on-chain contract (no storage collision).
1. Fetch constructor arguments from etherscan
2. Fetch creation transaction from etherscan
3. Replay and inspect the creation transaction, and find the message call that CREATEs the contract.
4. Replay the creation transaction again and hijack the CREATE message call, replacing the call data with new creation bytecode and original arguments.

### Output

- the tweaked code of the contract

### Downstream

- Anvil may use this crate to tweak a forked blockchain.
- Cast may use this crate to simulate a transaction on a tweaked contract.