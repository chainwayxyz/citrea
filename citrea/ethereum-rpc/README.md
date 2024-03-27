## Ethereum RPC

This crate provides the implementation of some of the Ethereum JSON-RPC API methods for Citrea. The remaining methods can be found in the EVM module of Citrea, in the `citrea/evm` folder.

The main logic behind this separation is mostly due to a couple of tricks, such as implementing a cache mechanism & mempool access for some of the methods, as well as building some other logic that could be useful in the context of gas oracle & fees.
