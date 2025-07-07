use core::num::NonZero;

use bitcoin::blockdata::script::Instruction;
use bitcoin::opcodes::all::OP_CHECKSIGVERIFY;
use bitcoin::script::Instruction::{Op, PushBytes};
use bitcoin::script::{Error as ScriptError, PushBytes as StructPushBytes};
use bitcoin::{Opcode, Script, Transaction};
use sha2::Digest;
use thiserror::Error;

#[derive(Debug, Clone)]
pub enum ParsedTransaction {
    /// Kind 0
    Complete(ParsedComplete),
    /// Kind 1
    Aggregate(ParsedAggregate),
    /// Kind 2
    Chunk(ParsedChunk),
    /// Kind 3
    BatchProverMethodId(ParsedBatchProverMethodId),
    /// Kind 4
    SequencerCommitment(ParsedSequencerCommitment),
    // /// Kind ?
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

#[derive(Debug, Clone)]
pub struct ParsedBatchProverMethodId {
    pub body: Vec<u8>,
    pub signature: Vec<u8>,
    pub public_key: Vec<u8>,
}

/// To verify the signature of the inscription and get the hash of the body
pub trait VerifyParsed {
    fn public_key(&self) -> &[u8];
    fn signature(&self) -> &[u8];
    fn body(&self) -> &[u8];

    /// Verifies the signature of the inscription and returns the hash of the body
    fn get_sig_verified_hash(&self) -> Option<[u8; 32]> {
        if let Ok(key) = k256::ecdsa::VerifyingKey::from_sec1_bytes(self.public_key()) {
            use k256::ecdsa::signature::DigestVerifier;
            let hash = sha2::Sha256::new_with_prefix(self.body());
            let signature = k256::ecdsa::Signature::from_slice(self.signature());
            if signature.is_ok() && key.verify_digest(hash.clone(), &signature.unwrap()).is_ok() {
                return Some(hash.finalize().into());
            }
        }

        None
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

impl VerifyParsed for ParsedChunk {
    fn public_key(&self) -> &[u8] {
        unimplemented!("public_key call Should not be used with chunks")
    }
    fn signature(&self) -> &[u8] {
        unimplemented!("signature call Should not be used with chunks")
    }
    fn body(&self) -> &[u8] {
        &self.body
    }
}

impl VerifyParsed for ParsedBatchProverMethodId {
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

#[derive(Error, Debug, Clone, PartialEq)]
pub enum ParserError {
    #[error("Invalid header length")]
    InvalidHeaderLength,
    #[error("Invalid header type {0}")]
    InvalidHeaderType(NonZero<u16>),
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

pub fn parse_relevant_transaction(tx: &Transaction) -> Result<ParsedTransaction, ParserError> {
    let script = get_script(tx)?;
    let instructions = script.instructions().peekable();
    // Map all Instructions errors into ParserError::ScriptError
    let mut instructions = instructions.map(|r| r.map_err(ParserError::from));

    parse_transaction(&mut instructions)
}

// Returns the script from the first input of the transaction
fn get_script(tx: &Transaction) -> Result<&Script, ParserError> {
    tx.input[0]
        .witness
        .tapscript()
        .ok_or(ParserError::NonTapscriptWitness)
}

fn parse_transaction(
    instructions: &mut dyn Iterator<Item = Result<Instruction<'_>, ParserError>>,
) -> Result<ParsedTransaction, ParserError> {
    use super::TransactionKind;

    // PushBytes(XOnlyPublicKey)
    let _public_key = read_push_bytes(instructions)?;
    if OP_CHECKSIGVERIFY != read_opcode(instructions)? {
        return Err(ParserError::UnexpectedOpcode);
    }

    // Parse header
    let kind_slice = read_push_bytes(instructions)?;
    let Some(kind) = TransactionKind::from_bytes(kind_slice.as_bytes()) else {
        return Err(ParserError::InvalidHeaderLength);
    };

    // Parse transaction body according to type
    match kind {
        TransactionKind::Complete => {
            body_parsers::parse_type_0_body(instructions).map(ParsedTransaction::Complete)
        }
        TransactionKind::Aggregate => {
            body_parsers::parse_type_1_body(instructions).map(ParsedTransaction::Aggregate)
        }
        TransactionKind::Chunks => {
            body_parsers::parse_type_2_body(instructions).map(ParsedTransaction::Chunk)
        }
        TransactionKind::BatchProofMethodId => body_parsers::parse_type_3_body(instructions)
            .map(ParsedTransaction::BatchProverMethodId),
        TransactionKind::SequencerCommitment => body_parsers::parse_type_4_body(instructions)
            .map(ParsedTransaction::SequencerCommitment),
        TransactionKind::Unknown(n) => Err(ParserError::InvalidHeaderType(n)),
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

mod body_parsers {
    use bitcoin::opcodes::all::{OP_ENDIF, OP_IF, OP_NIP};
    use bitcoin::script::Instruction;
    use bitcoin::script::Instruction::{Op, PushBytes};

    use super::{
        read_instr, read_opcode, read_push_bytes, ParsedAggregate, ParsedBatchProverMethodId,
        ParsedChunk, ParsedComplete, ParsedSequencerCommitment, ParserError,
    };

    // Parse transaction body of Type0
    pub(super) fn parse_type_0_body(
        instructions: &mut dyn Iterator<Item = Result<Instruction<'_>, ParserError>>,
    ) -> Result<ParsedComplete, ParserError> {
        let op_false = read_push_bytes(instructions)?;
        if !op_false.is_empty() {
            // OP_FALSE = OP_PUSHBYTES_0
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
        if OP_NIP != read_opcode(instructions)? {
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
            // OP_FALSE = OP_PUSHBYTES_0
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
                PushBytes(chunk) => chunks.push(chunk),
                Op(OP_ENDIF) => break,
                Op(_) => return Err(ParserError::UnexpectedOpcode),
            }
        }

        // Nonce
        let _nonce = read_push_bytes(instructions)?;
        if OP_NIP != read_opcode(instructions)? {
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
            // OP_FALSE = OP_PUSHBYTES_0
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

        // Nonce
        let _nonce = read_push_bytes(instructions)?;
        if OP_NIP != read_opcode(instructions)? {
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

        Ok(ParsedChunk { body })
    }

    // Parse transaction body of Type3
    pub(super) fn parse_type_3_body(
        instructions: &mut dyn Iterator<Item = Result<Instruction<'_>, ParserError>>,
    ) -> Result<ParsedBatchProverMethodId, ParserError> {
        let op_false = read_push_bytes(instructions)?;
        if !op_false.is_empty() {
            // OP_FALSE = OP_PUSHBYTES_0
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
        if OP_NIP != read_opcode(instructions)? {
            return Err(ParserError::UnexpectedOpcode);
        }
        // END of transaction
        if instructions.next().is_some() {
            return Err(ParserError::UnexpectedOpcode);
        }

        let signature = signature.as_bytes().to_vec();
        let public_key = public_key.as_bytes().to_vec();
        let body = body.as_bytes().to_vec();

        Ok(ParsedBatchProverMethodId {
            body,
            signature,
            public_key,
        })
    }

    // Parse transaction body of Type4
    pub(super) fn parse_type_4_body(
        instructions: &mut dyn Iterator<Item = Result<Instruction<'_>, ParserError>>,
    ) -> Result<ParsedSequencerCommitment, ParserError> {
        let op_false = read_push_bytes(instructions)?;
        if !op_false.is_empty() {
            // OP_FALSE = OP_PUSHBYTES_0
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
        if OP_NIP != read_opcode(instructions)? {
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
    use bitcoin::opcodes::all::{OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_ENDIF, OP_IF, OP_NIP};
    use bitcoin::opcodes::{OP_FALSE, OP_TRUE};
    use bitcoin::script::{self, PushBytesBuf};
    use bitcoin::Transaction;

    use super::{parse_relevant_transaction, parse_transaction, ParsedTransaction, ParserError};
    use crate::helpers::TransactionKind;

    #[test]
    fn correct() {
        let kind = TransactionKind::Complete;

        let reveal_script_builder = script::Builder::new()
            .push_x_only_key(&XOnlyPublicKey::from_slice(&[1; 32]).unwrap())
            .push_opcode(OP_CHECKSIGVERIFY)
            .push_slice(PushBytesBuf::try_from(kind.to_bytes()).expect("Cannot push header"))
            .push_opcode(OP_FALSE)
            .push_opcode(OP_IF)
            .push_slice([2u8; 64]) // signature
            .push_slice([3u8; 64]) // public key
            .push_slice([4u8; 64]) // chunk
            .push_slice([4u8; 64]) // chunk
            .push_opcode(OP_ENDIF)
            .push_slice(42i64.to_le_bytes()) // random
            .push_opcode(OP_NIP);

        let reveal_script = reveal_script_builder.into_script();
        let mut instructions = reveal_script
            .instructions()
            .map(|r| r.map_err(ParserError::from));

        let result = parse_transaction(&mut instructions);

        let result = result.inspect_err(|e| {
            dbg!(e);
        });
        assert!(result.is_ok());

        let ParsedTransaction::Complete(result) = result.unwrap() else {
            panic!("Unexpected tx kind");
        };

        assert_eq!(result.body, vec![4u8; 128]);
        assert_eq!(result.signature, vec![2u8; 64]);
        assert_eq!(result.public_key, vec![3u8; 64]);
    }

    #[test]
    fn only_checksig() {
        let kind = TransactionKind::Complete;

        let reveal_script_builder = script::Builder::new()
            .push_x_only_key(&XOnlyPublicKey::from_slice(&[1; 32]).unwrap())
            .push_opcode(OP_CHECKSIGVERIFY)
            .push_slice(PushBytesBuf::try_from(kind.to_bytes()).expect("Cannot push header"));

        let reveal_script = reveal_script_builder.into_script();

        let mut instructions = reveal_script
            .instructions()
            .map(|r| r.map_err(ParserError::from));

        let result = parse_transaction(&mut instructions);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), ParserError::UnexpectedEndOfScript);
    }

    #[test]
    fn non_parseable_tx() {
        let hex_tx = "020000000001013a66019bfcc719ba12586a83ebbb0b3debdc945f563cd64fd44c8044e3d3a1790100000000fdffffff028fa2aa060000000017a9147ba15d4e0d8334de3a68cf3687594e2d1ee5b00d879179e0090000000016001493c93ad222e57d65438545e048822ede2d418a3d0247304402202432e6c422b93705fbc57b350ea43e4ef9441c0907988eff051eaac807fc8cf2022046c92b540b5f04f8da11febb5d2a478aed1b8bc088e769da8b78fffcae8c9a9a012103e2991b47d9c788f55379f9ef519b642d79d7dfe0e7555ec5575ee934b2dca1223f5d0c00";

        let tx: Transaction =
            bitcoin::consensus::deserialize(&hex::decode(hex_tx).unwrap()).unwrap();

        let result = parse_relevant_transaction(&tx);

        assert!(result.is_err(), "Failed to error on non-parseable tx.");
        assert_eq!(result.unwrap_err(), ParserError::UnexpectedOpcode);
    }

    #[test]
    fn complex_envelope() {
        let kind = TransactionKind::Complete;

        let reveal_script = script::Builder::new()
            .push_x_only_key(&XOnlyPublicKey::from_slice(&[1; 32]).unwrap())
            .push_opcode(OP_CHECKSIGVERIFY)
            .push_slice(PushBytesBuf::try_from(kind.to_bytes()).expect("Cannot push header"))
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
            .push_opcode(OP_NIP)
            .into_script();

        let mut instructions = reveal_script
            .instructions()
            .map(|r| r.map_err(ParserError::from));

        let result = parse_transaction(&mut instructions);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), ParserError::UnexpectedOpcode);
    }

    #[test]
    fn two_envelopes() {
        let kind = TransactionKind::Complete;

        let reveal_script = script::Builder::new()
            .push_x_only_key(&XOnlyPublicKey::from_slice(&[1; 32]).unwrap())
            .push_opcode(OP_CHECKSIGVERIFY)
            .push_slice(PushBytesBuf::try_from(kind.to_bytes()).expect("Cannot push header"))
            .push_opcode(OP_FALSE)
            .push_opcode(OP_IF)
            .push_slice([2u8; 64]) // signature
            .push_slice([3u8; 64]) // public key
            .push_slice(PushBytesBuf::try_from(vec![0u8; 64]).unwrap())
            .push_opcode(OP_ENDIF)
            .push_slice(42i64.to_le_bytes()) // random
            .push_opcode(OP_NIP)
            .push_opcode(OP_FALSE)
            .push_opcode(OP_IF)
            .push_slice([2u8; 64]) // signature
            .push_slice([3u8; 64]) // public key
            .push_slice(PushBytesBuf::try_from(vec![1u8; 64]).unwrap())
            .push_opcode(OP_ENDIF)
            .push_slice(42i64.to_le_bytes()) // random
            .push_opcode(OP_NIP)
            .into_script();

        let mut instructions = reveal_script
            .instructions()
            .map(|r| r.map_err(ParserError::from));

        let result = parse_transaction(&mut instructions);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), ParserError::UnexpectedOpcode);
    }

    #[test]
    fn big_push() {
        let kind = TransactionKind::Complete;

        let reveal_script = script::Builder::new()
            .push_x_only_key(&XOnlyPublicKey::from_slice(&[1; 32]).unwrap())
            .push_opcode(OP_CHECKSIGVERIFY)
            .push_slice(PushBytesBuf::try_from(kind.to_bytes()).expect("Cannot push header"))
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
            .push_opcode(OP_NIP)
            .into_script();

        let mut instructions = reveal_script
            .instructions()
            .map(|r| r.map_err(ParserError::from));

        let result = parse_transaction(&mut instructions);

        assert!(result.is_ok());

        let ParsedTransaction::Complete(result) = result.unwrap() else {
            panic!("Unexpected tx kind");
        };

        assert_eq!(result.body, vec![1u8; 512 * 6]);
        assert_eq!(result.signature, vec![2u8; 64]);
        assert_eq!(result.public_key, vec![3u8; 64]);
    }
}
