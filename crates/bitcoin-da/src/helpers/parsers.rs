use core::num::NonZeroU16;

use bitcoin::blockdata::script::Instruction;
use bitcoin::hashes::Hash;
use bitcoin::opcodes::all::{OP_CHECKSIGVERIFY, OP_DROP};
use bitcoin::script::Instruction::{Op, PushBytes};
use bitcoin::script::{Error as ScriptError, PushBytes as StructPushBytes};
use bitcoin::secp256k1::{ecdsa, Message, Secp256k1};
use bitcoin::{secp256k1, Opcode, Script, Transaction, Txid};
use thiserror::Error;

use super::{
    calculate_double_sha256, TransactionHeaderBatchProof, TransactionHeaderLightClient,
    TransactionKindBatchProof, TransactionKindLightClient,
};

#[derive(Debug, Clone)]
pub enum ParsedLightClientTransaction {
    /// Kind 0
    Complete(ParsedComplete),
    /// Kind 1
    Aggregate(ParsedAggregate),
    /// Kind 2
    Chunk(ParsedChunk),
}

#[derive(Debug, Clone)]
pub enum ParsedBatchProofTransaction {
    /// Kind 0
    SequencerCommitment(ParsedSequencerCommitment),
    // /// Kind 1
    // ForcedTransaction(ForcedTransaction),
}

#[derive(Debug, Clone)]
pub struct ParsedComplete {
    pub body: Vec<u8>,
    pub signature: Vec<u8>,
    pub public_key: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ParsedAggregate {
    pub body: Vec<u8>,
    pub signature: Vec<u8>,
    pub public_key: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ParsedChunk {
    pub body: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ParsedSequencerCommitment {
    pub body: Vec<u8>,
    pub signature: Vec<u8>,
    pub public_key: Vec<u8>,
}

/// To verify the signature of the inscription and get the hash of the body
pub(crate) trait VerifyParsed {
    fn public_key(&self) -> &[u8];
    fn signature(&self) -> &[u8];
    fn body(&self) -> &[u8];

    /// Verifies the signature of the inscription and returns the hash of the body
    fn get_sig_verified_hash(&self) -> Option<[u8; 32]> {
        let public_key = secp256k1::PublicKey::from_slice(self.public_key());
        let signature = ecdsa::Signature::from_compact(self.signature());
        let hash = calculate_double_sha256(self.body());
        let message = Message::from_digest_slice(&hash).unwrap(); // cannot fail

        let secp = Secp256k1::new();

        if public_key.is_ok()
            && signature.is_ok()
            && secp
                .verify_ecdsa(&message, &signature.unwrap(), &public_key.unwrap())
                .is_ok()
        {
            Some(hash)
        } else {
            None
        }
    }
}

impl VerifyParsed for ParsedComplete {
    fn public_key(&self) -> &[u8] {
        &self.public_key
    }
    fn signature(&self) -> &[u8] {
        &self.signature
    }
    fn body(&self) -> &[u8] {
        &self.body
    }
}

impl VerifyParsed for ParsedAggregate {
    fn public_key(&self) -> &[u8] {
        &self.public_key
    }
    fn signature(&self) -> &[u8] {
        &self.signature
    }
    fn body(&self) -> &[u8] {
        &self.body
    }
}

impl VerifyParsed for ParsedSequencerCommitment {
    fn public_key(&self) -> &[u8] {
        &self.public_key
    }
    fn signature(&self) -> &[u8] {
        &self.signature
    }
    fn body(&self) -> &[u8] {
        &self.body
    }
}

impl ParsedAggregate {
    pub fn txids(&self) -> Result<Vec<Txid>, bitcoin::hashes::FromSliceError> {
        self.body
            .chunks_exact(32)
            .into_iter()
            .map(Txid::from_slice)
            .collect()
    }
}

#[derive(Error, Debug, Clone, PartialEq)]
pub enum ParserError {
    #[error("Invalid rollup name")]
    InvalidRollupName,
    #[error("Invalid header length")]
    InvalidHeaderLength,
    #[error("Invalid header type {0}")]
    InvalidHeaderType(NonZeroU16),
    #[error("No witness in tapscript")]
    NonTapscriptWitness,
    #[error("Unexpected end of script")]
    UnexpectedEndOfScript,
    #[error("Invalid opcode in the script")]
    UnexpectedOpcode,
    #[error("Script error: {0}")]
    ScriptError(String),
}

impl From<ScriptError> for ParserError {
    fn from(value: ScriptError) -> ParserError {
        ParserError::ScriptError(value.to_string())
    }
}

pub fn parse_transaction(
    tx: &Transaction,
    rollup_name: &str,
) -> Result<ParsedLightClientTransaction, ParserError> {
    let script = get_script(tx)?;
    let instructions = script.instructions().peekable();
    // Map all Instructions errors into ParserError::ScriptError
    let mut instructions = instructions.map(|r| r.map_err(ParserError::from));

    parse_relevant_lightclient(&mut instructions, rollup_name)
}

pub fn parse_batch_proof_transaction(
    tx: &Transaction,
    rollup_name: &str,
) -> Result<ParsedBatchProofTransaction, ParserError> {
    let script = get_script(tx)?;
    let instructions = script.instructions().peekable();
    // Map all Instructions errors into ParserError::ScriptError
    let mut instructions = instructions.map(|r| r.map_err(ParserError::from));

    parse_relevant_batchproof(&mut instructions, rollup_name)
}

// Returns the script from the first input of the transaction
fn get_script(tx: &Transaction) -> Result<&Script, ParserError> {
    tx.input[0]
        .witness
        .tapscript()
        .ok_or(ParserError::NonTapscriptWitness)
}

fn parse_relevant_lightclient(
    instructions: &mut dyn Iterator<Item = Result<Instruction<'_>, ParserError>>,
    rollup_name: &str,
) -> Result<ParsedLightClientTransaction, ParserError> {
    // PushBytes(XOnlyPublicKey)
    let _public_key = read_push_bytes(instructions)?;
    if OP_CHECKSIGVERIFY != read_opcode(instructions)? {
        return Err(ParserError::UnexpectedOpcode);
    }

    // Parse header
    let header_slice = read_push_bytes(instructions)?;
    let Some(header) = TransactionHeaderLightClient::from_bytes(header_slice.as_bytes()) else {
        return Err(ParserError::InvalidHeaderLength);
    };

    // Check rollup name
    if header.rollup_name != rollup_name.as_bytes() {
        return Err(ParserError::InvalidRollupName);
    }

    // Parse transaction body according to type
    match header.kind {
        TransactionKindLightClient::Complete => light_client::parse_type_0_body(instructions)
            .map(ParsedLightClientTransaction::Complete),
        TransactionKindLightClient::Chunked => light_client::parse_type_1_body(instructions)
            .map(ParsedLightClientTransaction::Aggregate),
        TransactionKindLightClient::ChunkedPart => {
            light_client::parse_type_2_body(instructions).map(ParsedLightClientTransaction::Chunk)
        }
        TransactionKindLightClient::Unknown(n) => Err(ParserError::InvalidHeaderType(n)),
    }
}

fn parse_relevant_batchproof(
    instructions: &mut dyn Iterator<Item = Result<Instruction<'_>, ParserError>>,
    rollup_name: &str,
) -> Result<ParsedBatchProofTransaction, ParserError> {
    // PushBytes(XOnlyPublicKey)
    let _public_key = read_push_bytes(instructions)?;
    if OP_CHECKSIGVERIFY != read_opcode(instructions)? {
        return Err(ParserError::UnexpectedOpcode);
    }

    // Parse header
    let header_slice = read_push_bytes(instructions)?;
    let Some(header) = TransactionHeaderBatchProof::from_bytes(header_slice.as_bytes()) else {
        return Err(ParserError::InvalidHeaderLength);
    };

    // Check rollup name
    if header.rollup_name != rollup_name.as_bytes() {
        return Err(ParserError::InvalidRollupName);
    }

    // Parse transaction body according to type
    match header.kind {
        TransactionKindBatchProof::SequencerCommitment => {
            batch_proof::parse_type_0_body(instructions)
                .map(ParsedBatchProofTransaction::SequencerCommitment)
        }
        TransactionKindBatchProof::Unknown(n) => Err(ParserError::InvalidHeaderType(n)),
    }
}

fn read_instr<'a>(
    instructions: &mut dyn Iterator<Item = Result<Instruction<'a>, ParserError>>,
) -> Result<Instruction<'a>, ParserError> {
    let instr = instructions
        .next()
        .unwrap_or(Err(ParserError::UnexpectedEndOfScript))?;
    Ok(instr)
}

fn read_push_bytes<'a>(
    instructions: &mut dyn Iterator<Item = Result<Instruction<'a>, ParserError>>,
) -> Result<&'a StructPushBytes, ParserError> {
    let instr = read_instr(instructions)?;
    match instr {
        PushBytes(push_bytes) => Ok(push_bytes),
        _ => Err(ParserError::UnexpectedOpcode),
    }
}

fn read_opcode(
    instructions: &mut dyn Iterator<Item = Result<Instruction<'_>, ParserError>>,
) -> Result<Opcode, ParserError> {
    let instr = read_instr(instructions)?;
    let Op(op) = instr else {
        return Err(ParserError::UnexpectedOpcode);
    };
    Ok(op)
}

mod light_client {
    use bitcoin::hashes::Hash;
    use bitcoin::opcodes::all::{OP_DROP, OP_ENDIF, OP_IF};
    use bitcoin::script::Instruction;
    use bitcoin::script::Instruction::{Op, PushBytes};
    use bitcoin::Txid;

    use super::{
        read_instr, read_opcode, read_push_bytes, ParsedAggregate, ParsedChunk, ParsedComplete,
        ParserError,
    };

    // Parse transaction body of Type0
    pub(super) fn parse_type_0_body(
        instructions: &mut dyn Iterator<Item = Result<Instruction<'_>, ParserError>>,
    ) -> Result<ParsedComplete, ParserError> {
        let op_false = read_push_bytes(instructions)?;
        if !op_false.is_empty() {
            return Err(ParserError::UnexpectedOpcode);
        }

        if OP_IF != read_opcode(instructions)? {
            return Err(ParserError::UnexpectedOpcode);
        }

        let signature = read_push_bytes(instructions)?;
        let public_key = read_push_bytes(instructions)?;

        let mut chunks = vec![];

        loop {
            let instr = read_instr(instructions)?;
            match instr {
                PushBytes(chunk) => {
                    if chunk.is_empty() {
                        return Err(ParserError::UnexpectedOpcode);
                    }
                    chunks.push(chunk)
                }
                Op(OP_ENDIF) => break,
                Op(_) => return Err(ParserError::UnexpectedOpcode),
            }
        }

        // Nonce
        let _nonce = read_push_bytes(instructions)?;
        if OP_DROP != read_opcode(instructions)? {
            return Err(ParserError::UnexpectedOpcode);
        }
        // END of transaction
        if instructions.next().is_some() {
            return Err(ParserError::UnexpectedOpcode);
        }

        let body_size: usize = chunks.iter().map(|c| c.len()).sum();
        let mut body = Vec::with_capacity(body_size);
        for chunk in chunks {
            body.extend_from_slice(chunk.as_bytes());
        }

        let signature = signature.as_bytes().to_vec();
        let public_key = public_key.as_bytes().to_vec();

        Ok(ParsedComplete {
            body,
            signature,
            public_key,
        })
    }

    // Parse transaction body of Type1
    pub(super) fn parse_type_1_body(
        instructions: &mut dyn Iterator<Item = Result<Instruction<'_>, ParserError>>,
    ) -> Result<ParsedAggregate, ParserError> {
        let op_false = read_push_bytes(instructions)?;
        if !op_false.is_empty() {
            return Err(ParserError::UnexpectedOpcode);
        }

        if OP_IF != read_opcode(instructions)? {
            return Err(ParserError::UnexpectedOpcode);
        }

        let signature = read_push_bytes(instructions)?;
        let public_key = read_push_bytes(instructions)?;

        let mut chunks = vec![];

        loop {
            let instr = read_instr(instructions)?;
            match instr {
                PushBytes(chunk) => {
                    if chunk.len() != 32 {
                        return Err(ParserError::UnexpectedOpcode);
                    }
                    chunks.push(chunk)
                }
                Op(OP_ENDIF) => break,
                Op(_) => return Err(ParserError::UnexpectedOpcode),
            }
        }

        // Nonce
        let _nonce = read_push_bytes(instructions)?;
        if OP_DROP != read_opcode(instructions)? {
            return Err(ParserError::UnexpectedOpcode);
        }
        // END of transaction
        if instructions.next().is_some() {
            return Err(ParserError::UnexpectedOpcode);
        }

        let body_size: usize = 32 * chunks.len();
        let mut body = Vec::with_capacity(body_size);
        for chunk in chunks {
            body.extend_from_slice(chunk.as_bytes());
        }

        let signature = signature.as_bytes().to_vec();
        let public_key = public_key.as_bytes().to_vec();

        Ok(ParsedAggregate {
            body,
            signature,
            public_key,
        })
    }

    // Parse transaction body of Type2
    pub(super) fn parse_type_2_body(
        instructions: &mut dyn Iterator<Item = Result<Instruction<'_>, ParserError>>,
    ) -> Result<ParsedChunk, ParserError> {
        let op_false = read_push_bytes(instructions)?;
        if !op_false.is_empty() {
            return Err(ParserError::UnexpectedOpcode);
        }

        if OP_IF != read_opcode(instructions)? {
            return Err(ParserError::UnexpectedOpcode);
        }

        let mut chunks = vec![];

        loop {
            let instr = read_instr(instructions)?;
            match instr {
                PushBytes(chunk) => {
                    if chunk.is_empty() {
                        return Err(ParserError::UnexpectedOpcode);
                    }
                    chunks.push(chunk)
                }
                Op(OP_ENDIF) => break,
                Op(_) => return Err(ParserError::UnexpectedOpcode),
            }
        }

        let body_size: usize = chunks.iter().map(|c| c.len()).sum();
        let mut body = Vec::with_capacity(body_size);
        for chunk in chunks {
            body.extend_from_slice(chunk.as_bytes());
        }

        Ok(ParsedChunk { body })
    }
}

mod batch_proof {
    use bitcoin::opcodes::all::{OP_DROP, OP_ENDIF, OP_IF};
    use bitcoin::script::Instruction;

    use super::{read_opcode, read_push_bytes, ParsedSequencerCommitment, ParserError};

    // Parse transaction body of Type0
    pub(super) fn parse_type_0_body(
        instructions: &mut dyn Iterator<Item = Result<Instruction<'_>, ParserError>>,
    ) -> Result<ParsedSequencerCommitment, ParserError> {
        let op_false = read_push_bytes(instructions)?;
        if !op_false.is_empty() {
            return Err(ParserError::UnexpectedOpcode);
        }

        if OP_IF != read_opcode(instructions)? {
            return Err(ParserError::UnexpectedOpcode);
        }

        let signature = read_push_bytes(instructions)?;
        let public_key = read_push_bytes(instructions)?;
        let body = read_push_bytes(instructions)?;

        if OP_ENDIF != read_opcode(instructions)? {
            return Err(ParserError::UnexpectedOpcode);
        }

        // Nonce
        let _nonce = read_push_bytes(instructions)?;
        if OP_DROP != read_opcode(instructions)? {
            return Err(ParserError::UnexpectedOpcode);
        }
        // END of transaction
        if instructions.next().is_some() {
            return Err(ParserError::UnexpectedOpcode);
        }

        let signature = signature.as_bytes().to_vec();
        let public_key = public_key.as_bytes().to_vec();
        let body = body.as_bytes().to_vec();

        Ok(ParsedSequencerCommitment {
            body,
            signature,
            public_key,
        })
    }
}

#[cfg(feature = "native")]
pub fn parse_hex_transaction(
    tx_hex: &str,
) -> Result<Transaction, bitcoin::consensus::encode::Error> {
    use bitcoin::consensus::Decodable;

    if let Ok(reader) = hex::decode(tx_hex) {
        Transaction::consensus_decode(&mut &reader[..])
    } else {
        Err(bitcoin::consensus::encode::Error::ParseFailed(
            "Could not decode hex",
        ))
    }
}
#[cfg(test)]
mod tests {
    use bitcoin::key::XOnlyPublicKey;
    use bitcoin::opcodes::all::{OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_DROP, OP_ENDIF, OP_IF};
    use bitcoin::opcodes::{OP_FALSE, OP_TRUE};
    use bitcoin::script::{self, PushBytesBuf};

    use super::{
        parse_relevant_lightclient, ParsedLightClientTransaction, ParserError,
        TransactionHeaderLightClient, TransactionKindLightClient,
    };

    #[test]
    fn correct() {
        let header = TransactionHeaderLightClient {
            rollup_name: b"sov-btc",
            kind: TransactionKindLightClient::Complete,
        };

        let reveal_script_builder = script::Builder::new()
            .push_x_only_key(&XOnlyPublicKey::from_slice(&[1; 32]).unwrap())
            .push_opcode(OP_CHECKSIGVERIFY)
            .push_slice(PushBytesBuf::try_from(header.to_bytes()).expect("Cannot push header"))
            .push_opcode(OP_FALSE)
            .push_opcode(OP_IF)
            .push_slice([2u8; 64]) // signature
            .push_slice([3u8; 64]) // public key
            .push_slice([4u8; 64]) // chunk
            .push_slice([4u8; 64]) // chunk
            .push_opcode(OP_ENDIF)
            .push_slice(42i64.to_le_bytes()) // random
            .push_opcode(OP_DROP);

        let reveal_script = reveal_script_builder.into_script();
        let mut instructions = reveal_script
            .instructions()
            .map(|r| r.map_err(ParserError::from));

        let result = parse_relevant_lightclient(&mut instructions, "sov-btc");

        let result = result.inspect_err(|e| {
            dbg!(e);
        });
        assert!(result.is_ok());

        let ParsedLightClientTransaction::Complete(result) = result.unwrap() else {
            panic!("Unexpected tx kind");
        };

        assert_eq!(result.body, vec![4u8; 128]);
        assert_eq!(result.signature, vec![2u8; 64]);
        assert_eq!(result.public_key, vec![3u8; 64]);
    }

    #[test]
    fn wrong_rollup_tag() {
        let header = TransactionHeaderLightClient {
            rollup_name: b"not-sov-btc",
            kind: TransactionKindLightClient::Complete,
        };

        let reveal_script_builder = script::Builder::new()
            .push_x_only_key(&XOnlyPublicKey::from_slice(&[1; 32]).unwrap())
            .push_opcode(OP_CHECKSIGVERIFY)
            .push_slice(PushBytesBuf::try_from(header.to_bytes()).expect("Cannot push header"));

        let reveal_script = reveal_script_builder.into_script();
        let mut instructions = reveal_script
            .instructions()
            .map(|r| r.map_err(ParserError::from));

        let result = parse_relevant_lightclient(&mut instructions, "sov-btc");

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), ParserError::InvalidRollupName);
    }

    #[test]
    fn only_checksig() {
        let header = TransactionHeaderLightClient {
            rollup_name: b"sov-btc",
            kind: TransactionKindLightClient::Complete,
        };

        let reveal_script_builder = script::Builder::new()
            .push_x_only_key(&XOnlyPublicKey::from_slice(&[1; 32]).unwrap())
            .push_opcode(OP_CHECKSIGVERIFY)
            .push_slice(PushBytesBuf::try_from(header.to_bytes()).expect("Cannot push header"));

        let reveal_script = reveal_script_builder.into_script();

        let mut instructions = reveal_script
            .instructions()
            .map(|r| r.map_err(ParserError::from));

        let result = parse_relevant_lightclient(&mut instructions, "sov-btc");

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), ParserError::UnexpectedEndOfScript);
    }

    #[test]
    fn complex_envelope() {
        let header = TransactionHeaderLightClient {
            rollup_name: b"sov-btc",
            kind: TransactionKindLightClient::Complete,
        };

        let reveal_script = script::Builder::new()
            .push_x_only_key(&XOnlyPublicKey::from_slice(&[1; 32]).unwrap())
            .push_opcode(OP_CHECKSIGVERIFY)
            .push_slice(PushBytesBuf::try_from(header.to_bytes()).expect("Cannot push header"))
            .push_opcode(OP_FALSE)
            .push_opcode(OP_IF)
            .push_slice([2u8; 64]) // signature
            .push_slice([3u8; 64]) // public key
            .push_slice(PushBytesBuf::try_from(vec![1u8; 64]).unwrap())
            .push_opcode(OP_TRUE)
            .push_opcode(OP_IF)
            .push_x_only_key(&XOnlyPublicKey::from_slice(&[1; 32]).unwrap())
            .push_opcode(OP_CHECKSIG)
            .push_opcode(OP_ENDIF)
            .push_opcode(OP_ENDIF)
            .push_slice(42i64.to_le_bytes()) // random
            .push_opcode(OP_DROP)
            .into_script();

        let mut instructions = reveal_script
            .instructions()
            .map(|r| r.map_err(ParserError::from));

        let result = parse_relevant_lightclient(&mut instructions, "sov-btc");

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), ParserError::UnexpectedOpcode);
    }

    #[test]
    fn two_envelopes() {
        let header = TransactionHeaderLightClient {
            rollup_name: b"sov-btc",
            kind: TransactionKindLightClient::Complete,
        };

        let reveal_script = script::Builder::new()
            .push_x_only_key(&XOnlyPublicKey::from_slice(&[1; 32]).unwrap())
            .push_opcode(OP_CHECKSIGVERIFY)
            .push_slice(PushBytesBuf::try_from(header.to_bytes()).expect("Cannot push header"))
            .push_opcode(OP_FALSE)
            .push_opcode(OP_IF)
            .push_slice([2u8; 64]) // signature
            .push_slice([3u8; 64]) // public key
            .push_slice(PushBytesBuf::try_from(vec![0u8; 64]).unwrap())
            .push_opcode(OP_ENDIF)
            .push_slice(42i64.to_le_bytes()) // random
            .push_opcode(OP_DROP)
            .push_opcode(OP_FALSE)
            .push_opcode(OP_IF)
            .push_slice([2u8; 64]) // signature
            .push_slice([3u8; 64]) // public key
            .push_slice(PushBytesBuf::try_from(vec![1u8; 64]).unwrap())
            .push_opcode(OP_ENDIF)
            .push_slice(42i64.to_le_bytes()) // random
            .push_opcode(OP_DROP)
            .into_script();

        let mut instructions = reveal_script
            .instructions()
            .map(|r| r.map_err(ParserError::from));

        let result = parse_relevant_lightclient(&mut instructions, "sov-btc");

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), ParserError::UnexpectedOpcode);
    }

    #[test]
    fn big_push() {
        let header = TransactionHeaderLightClient {
            rollup_name: b"sov-btc",
            kind: TransactionKindLightClient::Complete,
        };

        let reveal_script = script::Builder::new()
            .push_x_only_key(&XOnlyPublicKey::from_slice(&[1; 32]).unwrap())
            .push_opcode(OP_CHECKSIGVERIFY)
            .push_slice(PushBytesBuf::try_from(header.to_bytes()).expect("Cannot push header"))
            .push_opcode(OP_FALSE)
            .push_opcode(OP_IF)
            .push_slice([2u8; 64]) // signature
            .push_slice([3u8; 64]) // public key
            .push_slice(PushBytesBuf::try_from(vec![1u8; 512]).unwrap())
            .push_slice(PushBytesBuf::try_from(vec![1u8; 512]).unwrap())
            .push_slice(PushBytesBuf::try_from(vec![1u8; 512]).unwrap())
            .push_slice(PushBytesBuf::try_from(vec![1u8; 512]).unwrap())
            .push_slice(PushBytesBuf::try_from(vec![1u8; 512]).unwrap())
            .push_slice(PushBytesBuf::try_from(vec![1u8; 512]).unwrap())
            .push_opcode(OP_ENDIF)
            .push_slice(42i64.to_le_bytes()) // random
            .push_opcode(OP_DROP)
            .into_script();

        let mut instructions = reveal_script
            .instructions()
            .map(|r| r.map_err(ParserError::from));

        let result = parse_relevant_lightclient(&mut instructions, "sov-btc");

        assert!(result.is_ok());

        let ParsedLightClientTransaction::Complete(result) = result.unwrap() else {
            panic!("Unexpected tx kind");
        };

        assert_eq!(result.body, vec![1u8; 512 * 6]);
        assert_eq!(result.signature, vec![2u8; 64]);
        assert_eq!(result.public_key, vec![3u8; 64]);
    }
}
