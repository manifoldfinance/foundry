# Tongs

The functionalities to allow tweak the code of an on-chain contract. 

## Use Scenario

1. Given an address of a contract on a blockchain (as well as a JSON-RPC endpoint), and a foundry project.
2. Find the creation transaction of that contract.
3. Resimulate the deployment of that contract with the original deployment arguments but with the code of the foundry project, and obtain the new deployed bytecode.
4. fork the blockchain and replace the code of the on-chain contract.
5. What is provided is a tweaked EVM runtime where the code of the contract is tweaked.
6. A lot of things can be done afterwards, including replay transaction or send a new transaction to invoke the tweaked contract.
