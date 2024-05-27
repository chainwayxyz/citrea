# Risc0 Bonsai Adapter

This package adapts Risc0 version 0.21 to work as a zkVM for the Sovereign SDK.

If `with_proof` is set to true, th `ZkVmHost`implementation will offload the proving to Bonsai SDK.
If `with_proof` is set to false, the `ZkVmHost` implementation will run the Risc0 zk vm in "execute" mode and only output `PublicInput`.