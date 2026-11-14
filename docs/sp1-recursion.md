# SP1 native LCP recursion

The ongoing light-client chain uses **compressed SP1 STARKs**. The previous LCP is verified with SP1's native recursion API inside the next LCP. Clementine consumes that same compressed LCP through native recursion and produces its terminal **Groth16 bridge/challenge proof** for BitVM. Batch proofs remain Groth16 for their Bitcoin DA footprint; invalid batch proofs can still be rejected recoverably inside the LCP.

## Transport and verification

The shared Borsh envelope uses tag 0 for Groth16, tag 1 for explicit mock receipts, and tag 3 for compressed receipts. Mock receipts carry the native `[u32; 8]` method ID; downstream consumers must use that representation as well. Clementine additionally uses tag 2 for its development Groth16 circuit. A compressed receipt contains the native `[u32; 8]` key hash, bincode-encoded SP1 `SP1Proof::Compressed`, bincode-encoded `SP1VerifyingKey`, and the exact public journal. Serialization is pinned to SDK 6.10.0.

The host removes the large proof and key payloads from ordinary guest input, retaining only the native key hash and journal. It deserializes the compressed witness and calls `stdin.write_proof(*proof, vk.vk)`. Each guest `verify_sp1_proof(&native_key_hash, &sha256(journal))` consumes the corresponding witness in order and registers a deferred verification obligation. SP1's recursion machinery authenticates that obligation before a real parent proof can verify.

Program IDs use `vk.hash_u32()` directly. The guest compares the compressed receipt's eight canonical KoalaBear words with the trusted method ID and passes that same native digest to recursive verification. BN254 packing is only needed when verifying Groth16 batch proofs. It hashes the full journal using SHA-256. After proving, the selected SP1 SDK client verifies the complete proof bundle before the host creates the transport envelope.

Groth16 receipts are rejected at LCP verification entry points. A Groth16 proof cannot be used as a native compressed assumption, and the adapter does not attempt to extract a compressed proof from one. Citrea's circuit-input RPC returns guest `input` plus host-only `assumptions`; a caller proving the next LCP must preserve both. Store the complete compressed receipt for continued recursion, not its stripped guest claim.

## Guest stdin

Every Citrea SP1 guest, batch and light client, reads its stdin in this order:

1. `stdin.write_vec(input)`, the Borsh circuit input returned by the circuit-input RPCs.
2. For each compressed assumption, in order: `stdin.write_proof(proof, vk.vk)`, as described above. Batch proofs have none; mock assumptions add none.

When `[sp1_host].tx_backup_dir` is set, the prover writes `{job_id}-sp1-stdin.bin`, the bincode-encoded `SP1Stdin` with both parts, before proving. Deserialize it with `bincode::deserialize::<SP1Stdin>` to replay the session.

## Mock execution and tests

`execute` proving mode runs guests and returns an explicitly tagged mock receipt. Mainnet rejects mocks. Development guests permit them only through their existing explicit development policy.

After changing an LCP guest, rebuild all four Citrea network artifacts, import their program keys into Clementine, and regenerate dependent guest artifacts. Existing Groth16 LCP databases are incompatible; this change does not provide a production activation checkpoint.
