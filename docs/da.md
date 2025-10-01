# Data Availability

Data Availability (DA) is a crucial layer in the Citrea architecture that ensures the integrity and availability of data across the network. It serves as a foundational component that guarantees that all necessary data for transaction validation and state transitions is accessible to all participants, including sequencer, batch/light client provers, full nodes, l1 syncer, and others. This layer is essential for maintaining trust and reliability in the system, and it ensures that all nodes can independently verify the state of the blockchain.

## Data structure

We use a taproot commit + reveal scheme like Ordinals protocol to inscribe data. The main property of the reveal transactions is that their `wtxid`s start from a specific prefix.

The header of the reveal Script looks like this:

```
PushBytes(XOnlyPublicKey)
OP_CHECKSIGVERIFY
PushBytes([2 bytes for transaction type in LE])
```

There are 4 transaction types:

- `Complete` batch proof (when it's lower than 397000 bytes). Type = 0x00.
- `Aggregate` batch proof (when it's higher than 397000 bytes). Type = 0x01.
- `Chunks` for `Aggregate` batch proof. Type = 0x02.
- Batch proof MethodId. Type = 0x03.
- Sequencer commitment. Type = 0x04.

The format of the bodies is different for each type.

### Complete Batch Proof

```
OP_FALSE
OP_IF
OP_PUSHDATA(signature)
OP_PUSHDATA(batch_prover_public_key)
OP_PUSHDATA(1; - up to 520-bytes chunk of blob)
...
OP_PUSHDATA(N; - up to 520-bytes chunk of blob)
OP_ENDIF
OP_PUSHDATA(8 random bytes [nonce, nonce > 15 to avoid script parsing issues ])
OP_NIP
```

Where `blob` is `borsh(DataOnDa::Complete(compress(Proof)))`, `signature` is the signature of the `blob`.

### Aggregate Batch Proof

```
OP_FALSE
OP_IF
OP_PUSHDATA(signature)
OP_PUSHDATA(batch_prover_public_key)
OP_PUSHDATA(1; - up to 520-bytes chunk of blob)
...
OP_PUSHDATA(N; - up to 520-bytes chunk of blob)
OP_ENDIF
OP_PUSHDATA(8 random bytes [nonce, nonce > 15 to avoid script parsing issues ])
OP_NIP
```

Where `blob` is `borsh(DataOnDa::Aggregate([chunk1_txid, chunk2_txid..], [chunk1_wtxid, chunk2_wtxid..]))`, `signature` is the signature of the `blob`, not the proof itself.

### Chunks for Aggregate Batch Proof

```
OP_FALSE
OP_IF
OP_PUSHDATA(1; - up to 520-bytes chunk of blob)
...
OP_PUSHDATA(N; - up to 520-bytes chunk of blob)
OP_ENDIF
OP_PUSHDATA(8 random bytes [nonce, nonce > 15 to avoid script parsing issues ])
OP_NIP
```

Where `blob` is `borsh(DataOnDa::Aggregate([chunk1_txid, chunk2_txid..], [chunk1_wtxid, chunk2_wtxid..]))`, `signature` is the signature of the `blob`, not the proof itself.

The pseudo-code to split batch proof into chunks is:

```
let compressed = compress(Proof)
let chunks = compressed.chunks(397000)
let chunk_bodies = [borsh(DataOnDa::Chunk(chunk)) for chunk in chunks]
for chunk in chunk_bodies:
    create commit/reveal transaction...
```

### Batch Proof MethodId

```
OP_FALSE
OP_IF
OP_PUSHDATA(signature)
OP_PUSHDATA(batch_prover_public_key)
OP_PUSHDATA(up to 520-bytes chunk of blob)
OP_ENDIF
OP_PUSHDATA(8 random bytes [nonce, nonce > 15 to avoid script parsing issues ])
OP_NIP
```

Where `blob` is `borsh(DataOnDa::BatchProofMethodId(BatchProofMethodId))`, `signature` is the signature of the `blob`.

And `BatchProofMethodId` is:

```rust
struct BatchProofMethodId {
    /// New method id of upcoming fork
    method_id: [u32; 8],
    /// Activation L2 height of the new method id
    activation_l2_height: u64,
}
```

### Sequencer Commitment

```
OP_FALSE
OP_IF
OP_PUSHDATA(signature)
OP_PUSHDATA(sequencer_public_key)
OP_PUSHDATA(up to 520-bytes chunk of blob)
OP_ENDIF
OP_PUSHDATA(8 random bytes [nonce, nonce > 15 to avoid script parsing issues ])
OP_NIP
```

Where `blob` is `borsh(DataOnDa::SequencerCommitment(SequencerCommitment))`, `signature` is the signature of the `blob`.

And `SequencerCommitment` is:

```rust
struct SequencerCommitment {
    /// Merkle root of l2 block hashes
    merkle_root: [u8; 32],
    /// Absolute order of the sequencer commitment, the first commitment has index 0, the next one has 1...
    index: u32,
    /// End L2 block's number
    l2_end_block_number: u64,
}
```

## MAX_TX_BODY_SIZE

It is a special constant that defines the maximum size of the transaction body that can be included in a reveal transaction. This is calculated specifically to `397000` bytes, so that we can fit a transaction into Bitcoin limit of `400000` bytes, which is the maximum size of a transaction that can be included in a block. The rest `3000` bytes are reserved for the transaction header and other Script operations like OP_PUSHDATA overhead, OP_NIP, and others.

It tests we set it to `39700` bytes in order to test our code with a smaller `Proof` that is split into `Chunks`.

## WTXID Prefix

In order to find our data in the Bitcoin blockchain, we use the `reveal_tx_prefix`.
It is a prefix of the wtxid of the reveal transaction.
A relevant transaction is a transaction which wtxid starts from the `reveal_tx_prefix` and it contains a script that we are able to parse according to our tx format.

In tests the `reveal_tx_prefix` is of 1 byte length, but in production it is of 2 bytes length. Because in production it's 2 bytes long, the probability of getting a random wtxid to match our prefix is 1/2^16. That's how we can ignore the transactions that do not start with our prefix. And it saves us from parsing all the transactions in the Bitcoin blockchain.

The process of finding the right wtxid prefix is called "mining". It is done by adding a nonce to the reveal script. Changing the nonce changes the wtxid of the transaction.
