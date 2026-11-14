# SP1 guest precompile coverage

The SP1 guests replace selected cryptographic crates with `sp1-patches` forks that call SP1 precompiles. The patches are listed in each guest `Cargo.toml` and pinned in its lockfile. Everything else runs as ordinary RV64IM code inside the guest.

| EVM precompile           | Guest implementation         | Accelerated |
| ------------------------ | ---------------------------- | ----------- |
| `0x01` ecrecover         | `k256` (via revm-precompile) | yes         |
| `0x02` SHA-256           | `sha2`                       | yes         |
| `0x03` RIPEMD-160        | `ripemd`                     | no          |
| `0x05` modexp            | `aurora-engine-modexp`       | no          |
| `0x06`–`0x08` BN254      | `substrate-bn`               | yes         |
| `0x09` BLAKE2f           | revm-precompile              | no          |
| `0x…0100` P256VERIFY     | `p256`                       | yes         |
| `0x…0200` Schnorr verify | `k256`                       | yes         |

The guests also patch `tiny-keccak` and `sha3` (Keccak), `secp256k1`, and `crypto-bigint`. All guest patch tags target SP1 6.10.0. The light client's Groth16 verifier uses the published `substrate-bn-succinct-rs` 0.6.1, which includes the matching BN254 acceleration.

Citrea does not enable KZG point evaluation (`0x0a`) or the EIP-2537 BLS12-381 precompiles (`0x0b`–`0x11`); calls to those addresses reach empty accounts. BLS12-381 was removed because SP1 has no maintained patch for its `blst` backend, which made those calls 10–40 times more expensive to prove per unit of gas than the accelerated precompiles.
