// Create reveal key
let secp256k1 = Secp256k1::new();
let key_pair = UntweakedKeypair::new(&secp256k1, &mut rand::thread_rng());
let (public_key, _parity) = XOnlyPublicKey::from_keypair(&key_pair);

let header = TransactionHeaderBatchProof {
    rollup_name,
    kind: TransactionKindBatchProof::SequencerCommitment,
};
let header_bytes = header.to_bytes();

// sign the body for authentication of the sequencer
let (signature, signer_public_key) =
    sign_blob_with_private_key(&body, da_private_key).expect("Sequencer sign the body");

// start creating inscription content
let reveal_script_builder = script::Builder::new()
    .push_x_only_key(&public_key)
    .push_opcode(OP_CHECKSIGVERIFY)
    .push_slice(PushBytesBuf::try_from(header_bytes).expect("Cannot push header"))
    .push_opcode(OP_FALSE)
    .push_opcode(OP_IF)
    .push_slice(PushBytesBuf::try_from(signature).expect("Cannot push signature"))
    .push_slice(
        PushBytesBuf::try_from(signer_public_key).expect("Cannot push sequencer public key"),
    )
    .push_slice(PushBytesBuf::try_from(body).expect("Cannot push sequencer commitment"))
    .push_opcode(OP_ENDIF);