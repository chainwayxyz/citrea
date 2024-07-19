use bitcoin::blockdata::opcodes::all::{OP_ENDIF, OP_IF};
use bitcoin::blockdata::script::Instruction;
use bitcoin::hashes::{sha256d, Hash};
use bitcoin::opcodes::all::{OP_CHECKSIG, OP_DROP};
use bitcoin::script::Instruction::{Op, PushBytes};
use bitcoin::script::{Error as ScriptError, PushBytes as StructPushBytes};
use bitcoin::secp256k1::{ecdsa, Message, Secp256k1};
use bitcoin::{secp256k1, Opcode, Script, Transaction};
use thiserror::Error;

use super::{TransactionHeader, TransactionType};

#[derive(Debug, Clone)]
pub struct ParsedInscription {
    pub body: Vec<u8>,
    pub signature: Vec<u8>,
    pub public_key: Vec<u8>,
}

impl ParsedInscription {
    /// Verifies the signature of the inscription and returns the hash of the body
    pub fn get_sig_verified_hash(&self) -> Option<[u8; 32]> {
        let public_key = secp256k1::PublicKey::from_slice(&self.public_key);
        let signature = ecdsa::Signature::from_compact(&self.signature);
        let hash = sha256d::Hash::hash(&self.body).to_byte_array();
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

#[derive(Error, Debug, Clone, PartialEq)]
pub enum ParserError {
    #[error("Invalid rollup name")]
    InvalidRollupName,
    #[error("Invalid header length")]
    InvalidHeaderLength,
    #[error("Invalid header type")]
    InvalidHeaderType,
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
) -> Result<ParsedInscription, ParserError> {
    let script = get_script(tx)?;
    let instructions = script.instructions().peekable();
    // Map all Instructions errors into ParserError::ScriptError
    let mut instructions = instructions.map(|r| r.map_err(|e| ParserError::from(e)));

    parse_relevant_inscriptions(&mut instructions, rollup_name)
}

// Returns the script from the first input of the transaction
fn get_script(tx: &Transaction) -> Result<&Script, ParserError> {
    tx.input[0]
        .witness
        .tapscript()
        .ok_or(ParserError::NonTapscriptWitness)
}

fn parse_relevant_inscriptions(
    instructions: &mut dyn Iterator<Item = Result<Instruction<'_>, ParserError>>,
    rollup_name: &str,
) -> Result<ParsedInscription, ParserError> {
    // Parse header
    let header_slice = read_push_bytes(instructions)?;
    let Some(header) = TransactionHeader::from_bytes(header_slice.as_bytes()) else {
        return Err(ParserError::InvalidHeaderLength);
    };

    // Check rollup name
    if header.rollup_name != rollup_name.as_bytes() {
        return Err(ParserError::InvalidRollupName);
    }

    // Parse transaction body according to type
    match header.typ {
        TransactionType::Inscribed => parse_type_0_body(instructions),
        TransactionType::Unknown(_) => Err(ParserError::InvalidHeaderType),
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

// Parse transaction body of Type0
fn parse_type_0_body(
    instructions: &mut dyn Iterator<Item = Result<Instruction<'_>, ParserError>>,
) -> Result<ParsedInscription, ParserError> {
    // PushBytes(XOnlyPublicKey)
    let _public_key = read_push_bytes(instructions)?;
    if OP_CHECKSIG != read_opcode(instructions)? {
        return Err(ParserError::UnexpectedOpcode);
    }

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
            PushBytes(chunk) => chunks.push(chunk),
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

    Ok(ParsedInscription {
        body,
        signature,
        public_key,
    })
}

#[cfg(any(feature = "native", test))]
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
    use bitcoin::opcodes::all::{OP_CHECKSIG, OP_DROP, OP_ENDIF, OP_IF};
    use bitcoin::opcodes::{OP_FALSE, OP_TRUE};
    use bitcoin::script::{self, PushBytesBuf};
    use bitcoin::Transaction;

    use super::{parse_relevant_inscriptions, TransactionHeader, TransactionType};
    use crate::helpers::parsers::{parse_transaction, ParserError};

    #[test]
    fn correct() {
        let header = TransactionHeader {
            rollup_name: b"sov-btc",
            typ: TransactionType::Inscribed,
        };

        let reveal_script_builder = script::Builder::new()
            .push_slice(PushBytesBuf::try_from(header.to_bytes()).expect("Cannot push header"))
            .push_x_only_key(&XOnlyPublicKey::from_slice(&[1; 32]).unwrap())
            .push_opcode(OP_CHECKSIG)
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
            .map(|r| r.map_err(|e| ParserError::from(e)));

        let result = parse_relevant_inscriptions(&mut instructions, "sov-btc");

        let result = result.inspect_err(|e| {
            dbg!(e);
        });
        assert!(result.is_ok());

        let result = result.unwrap();

        assert_eq!(result.body, vec![4u8; 128]);
        assert_eq!(result.signature, vec![2u8; 64]);
        assert_eq!(result.public_key, vec![3u8; 64]);
    }

    #[test]
    fn wrong_rollup_tag() {
        let header = TransactionHeader {
            rollup_name: b"not-sov-btc",
            typ: TransactionType::Inscribed,
        };

        let reveal_script_builder = script::Builder::new()
            .push_slice(PushBytesBuf::try_from(header.to_bytes()).expect("Cannot push header"));

        let reveal_script = reveal_script_builder.into_script();
        let mut instructions = reveal_script
            .instructions()
            .map(|r| r.map_err(|e| ParserError::from(e)));

        let result = parse_relevant_inscriptions(&mut instructions, "sov-btc");

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), ParserError::InvalidRollupName);
    }

    // #[test]
    // fn leave_out_tags() {
    //     // name
    //     let reveal_script_builder = script::Builder::new()
    //         .push_x_only_key(&XOnlyPublicKey::from_slice(&[1; 32]).unwrap())
    //         .push_opcode(OP_CHECKSIG)
    //         .push_opcode(OP_FALSE)
    //         .push_opcode(OP_IF)
    //         .push_slice(PushBytesBuf::try_from(SIGNATURE_TAG.to_vec()).unwrap())
    //         .push_slice(PushBytesBuf::try_from(vec![0u8; 64]).unwrap())
    //         .push_slice(PushBytesBuf::try_from(PUBLICKEY_TAG.to_vec()).unwrap())
    //         .push_slice(PushBytesBuf::try_from(vec![0u8; 64]).unwrap())
    //         .push_slice(PushBytesBuf::try_from(RANDOM_TAG.to_vec()).unwrap())
    //         .push_int(0)
    //         .push_slice(PushBytesBuf::try_from(BODY_TAG.to_vec()).unwrap())
    //         .push_slice(PushBytesBuf::try_from(vec![0u8; 128]).unwrap())
    //         .push_opcode(OP_ENDIF);

    //     let reveal_script = reveal_script_builder.into_script();
    //     let mut instructions = reveal_script
    //     .instructions()
    //     .map(|r| r.map_err(|e| ParserError::from(e)));

    // let result = parse_relevant_inscriptions(&mut instructions, "sov-btc");

    //     assert!(result.is_err(), "Failed to error on no name tag.");
    //     assert_eq!(result.unwrap_err(), ParserError::EnvelopeHasIncorrectFormat);

    //     // signature
    //     let reveal_script_builder = script::Builder::new()
    //         .push_x_only_key(&XOnlyPublicKey::from_slice(&[1; 32]).unwrap())
    //         .push_opcode(OP_CHECKSIG)
    //         .push_opcode(OP_FALSE)
    //         .push_opcode(OP_IF)
    //         .push_slice(PushBytesBuf::try_from(ROLLUP_NAME_TAG.to_vec()).unwrap())
    //         .push_slice(PushBytesBuf::try_from("sov-btc".as_bytes().to_vec()).unwrap())
    //         .push_slice(PushBytesBuf::try_from(PUBLICKEY_TAG.to_vec()).unwrap())
    //         .push_slice(PushBytesBuf::try_from(vec![0u8; 64]).unwrap())
    //         .push_slice(PushBytesBuf::try_from(RANDOM_TAG.to_vec()).unwrap())
    //         .push_int(0)
    //         .push_slice(PushBytesBuf::try_from(BODY_TAG.to_vec()).unwrap())
    //         .push_slice(PushBytesBuf::try_from(vec![0u8; 128]).unwrap())
    //         .push_opcode(OP_ENDIF);

    //     let reveal_script = reveal_script_builder.into_script();
    //     let mut instructions = reveal_script
    //     .instructions()
    //     .map(|r| r.map_err(|e| ParserError::from(e)));

    // let result = parse_relevant_inscriptions(&mut instructions, "sov-btc");

    //     assert!(result.is_err(), "Failed to error on no signature tag.");
    //     assert_eq!(result.unwrap_err(), ParserError::EnvelopeHasIncorrectFormat);

    //     // publickey
    //     let reveal_script_builder = script::Builder::new()
    //         .push_x_only_key(&XOnlyPublicKey::from_slice(&[1; 32]).unwrap())
    //         .push_opcode(OP_CHECKSIG)
    //         .push_opcode(OP_FALSE)
    //         .push_opcode(OP_IF)
    //         .push_slice(PushBytesBuf::try_from(ROLLUP_NAME_TAG.to_vec()).unwrap())
    //         .push_slice(PushBytesBuf::try_from("sov-btc".as_bytes().to_vec()).unwrap())
    //         .push_slice(PushBytesBuf::try_from(SIGNATURE_TAG.to_vec()).unwrap())
    //         .push_slice(PushBytesBuf::try_from(vec![0u8; 64]).unwrap())
    //         .push_slice(PushBytesBuf::try_from(RANDOM_TAG.to_vec()).unwrap())
    //         .push_int(0)
    //         .push_slice(PushBytesBuf::try_from(BODY_TAG.to_vec()).unwrap())
    //         .push_slice(PushBytesBuf::try_from(vec![0u8; 128]).unwrap())
    //         .push_opcode(OP_ENDIF);

    //     let reveal_script = reveal_script_builder.into_script();
    //     let mut instructions = reveal_script
    //     .instructions()
    //     .map(|r| r.map_err(|e| ParserError::from(e)));

    // let result = parse_relevant_inscriptions(&mut instructions, "sov-btc");

    //     assert!(result.is_err(), "Failed to error on no publickey tag.");
    //     assert_eq!(result.unwrap_err(), ParserError::EnvelopeHasIncorrectFormat);

    //     // body
    //     let reveal_script_builder = script::Builder::new()
    //         .push_x_only_key(&XOnlyPublicKey::from_slice(&[1; 32]).unwrap())
    //         .push_opcode(OP_CHECKSIG)
    //         .push_opcode(OP_FALSE)
    //         .push_opcode(OP_IF)
    //         .push_slice(PushBytesBuf::try_from(ROLLUP_NAME_TAG.to_vec()).unwrap())
    //         .push_slice(PushBytesBuf::try_from("sov-btc".as_bytes().to_vec()).unwrap())
    //         .push_slice(PushBytesBuf::try_from(SIGNATURE_TAG.to_vec()).unwrap())
    //         .push_slice(PushBytesBuf::try_from(vec![0u8; 64]).unwrap())
    //         .push_slice(PushBytesBuf::try_from(PUBLICKEY_TAG.to_vec()).unwrap())
    //         .push_slice(PushBytesBuf::try_from(vec![0u8; 64]).unwrap())
    //         .push_slice(PushBytesBuf::try_from(RANDOM_TAG.to_vec()).unwrap())
    //         .push_int(0)
    //         .push_opcode(OP_ENDIF);

    //     let reveal_script = reveal_script_builder.into_script();

    //     let mut instructions = reveal_script
    //         .instructions()
    //         .map(|r| r.map_err(|e| ParserError::from(e)));

    //     let result = parse_relevant_inscriptions(&mut instructions, "sov-btc");

    //     assert!(result.is_err(), "Failed to error on no body tag.");

    //     // random
    //     let reveal_script_builder = script::Builder::new()
    //         .push_x_only_key(&XOnlyPublicKey::from_slice(&[1; 32]).unwrap())
    //         .push_opcode(OP_CHECKSIG)
    //         .push_opcode(OP_FALSE)
    //         .push_opcode(OP_IF)
    //         .push_slice(PushBytesBuf::try_from(ROLLUP_NAME_TAG.to_vec()).unwrap())
    //         .push_slice(PushBytesBuf::try_from("sov-btc".as_bytes().to_vec()).unwrap())
    //         .push_slice(PushBytesBuf::try_from(SIGNATURE_TAG.to_vec()).unwrap())
    //         .push_slice(PushBytesBuf::try_from(vec![0u8; 64]).unwrap())
    //         .push_slice(PushBytesBuf::try_from(PUBLICKEY_TAG.to_vec()).unwrap())
    //         .push_slice(PushBytesBuf::try_from(vec![0u8; 64]).unwrap())
    //         .push_slice(PushBytesBuf::try_from(BODY_TAG.to_vec()).unwrap())
    //         .push_slice(PushBytesBuf::try_from(vec![0u8; 128]).unwrap())
    //         .push_opcode(OP_ENDIF);

    //     let reveal_script = reveal_script_builder.into_script();

    //     let mut instructions = reveal_script
    //         .instructions()
    //         .map(|r| r.map_err(|e| ParserError::from(e)));

    //     let result = parse_relevant_inscriptions(&mut instructions, "sov-btc");

    //     assert!(result.is_err(), "Failed to error on no random tag.");
    //     assert_eq!(result.unwrap_err(), ParserError::EnvelopeHasIncorrectFormat);
    // }

    // #[test]
    // fn non_parseable_tx() {
    //     let hex_tx = "020000000001013a66019bfcc719ba12586a83ebbb0b3debdc945f563cd64fd44c8044e3d3a1790100000000fdffffff028fa2aa060000000017a9147ba15d4e0d8334de3a68cf3687594e2d1ee5b00d879179e0090000000016001493c93ad222e57d65438545e048822ede2d418a3d0247304402202432e6c422b93705fbc57b350ea43e4ef9441c0907988eff051eaac807fc8cf2022046c92b540b5f04f8da11febb5d2a478aed1b8bc088e769da8b78fffcae8c9a9a012103e2991b47d9c788f55379f9ef519b642d79d7dfe0e7555ec5575ee934b2dca1223f5d0c00";

    //     let tx: Transaction =
    //         bitcoin::consensus::deserialize(&hex::decode(hex_tx).unwrap()).unwrap();

    //     let result = parse_transaction(&tx, "sov-btc");

    //     assert!(result.is_err(), "Failed to error on non-parseable tx.");
    //     assert_eq!(result.unwrap_err(), ParserError::EnvelopeHasIncorrectFormat);
    // }

    #[test]
    fn only_checksig() {
        let header = TransactionHeader {
            rollup_name: b"sov-btc",
            typ: TransactionType::Inscribed,
        };

        let reveal_script_builder = script::Builder::new()
            .push_slice(PushBytesBuf::try_from(header.to_bytes()).expect("Cannot push header"))
            .push_x_only_key(&XOnlyPublicKey::from_slice(&[1; 32]).unwrap())
            .push_opcode(OP_CHECKSIG);

        let reveal_script = reveal_script_builder.into_script();

        let mut instructions = reveal_script
            .instructions()
            .map(|r| r.map_err(|e| ParserError::from(e)));

        let result = parse_relevant_inscriptions(&mut instructions, "sov-btc");

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), ParserError::UnexpectedEndOfScript);
    }

    // #[test]
    // fn complex_envelope() {
    //     let reveal_script = script::Builder::new()
    //         .push_x_only_key(&XOnlyPublicKey::from_slice(&[1; 32]).unwrap())
    //         .push_opcode(OP_CHECKSIG)
    //         .push_opcode(OP_FALSE)
    //         .push_opcode(OP_IF)
    //         .push_slice(PushBytesBuf::try_from(ROLLUP_NAME_TAG.to_vec()).unwrap())
    //         .push_slice(PushBytesBuf::try_from("sov-btc".as_bytes().to_vec()).unwrap())
    //         .push_slice(PushBytesBuf::try_from(SIGNATURE_TAG.to_vec()).unwrap())
    //         .push_slice(PushBytesBuf::try_from(vec![0u8; 64]).unwrap())
    //         .push_opcode(OP_TRUE)
    //         .push_opcode(OP_IF)
    //         .push_x_only_key(&XOnlyPublicKey::from_slice(&[1; 32]).unwrap())
    //         .push_opcode(OP_CHECKSIG)
    //         .push_opcode(OP_ENDIF)
    //         .push_slice(PushBytesBuf::try_from(PUBLICKEY_TAG.to_vec()).unwrap())
    //         .push_slice(PushBytesBuf::try_from(vec![0u8; 64]).unwrap())
    //         .push_slice(PushBytesBuf::try_from(RANDOM_TAG.to_vec()).unwrap())
    //         .push_int(0)
    //         .push_slice(PushBytesBuf::try_from(BODY_TAG.to_vec()).unwrap())
    //         .push_slice(PushBytesBuf::try_from(vec![0u8; 128]).unwrap())
    //         .push_opcode(OP_ENDIF)
    //         .into_script();

    //         let mut instructions = reveal_script
    //         .instructions()
    //         .map(|r| r.map_err(|e| ParserError::from(e)));

    //     let result = parse_relevant_inscriptions(&mut instructions, "sov-btc");

    //     assert!(result.is_err());
    //     assert_eq!(result.unwrap_err(), ParserError::EnvelopeHasNonPushOp);
    // }

    // #[test]
    // fn two_envelopes() {
    //     let reveal_script = script::Builder::new()
    //         .push_opcode(OP_FALSE)
    //         .push_opcode(OP_IF)
    //         .push_slice(PushBytesBuf::try_from(ROLLUP_NAME_TAG.to_vec()).unwrap())
    //         .push_slice(PushBytesBuf::try_from("sov-btc".as_bytes().to_vec()).unwrap())
    //         .push_slice(PushBytesBuf::try_from(SIGNATURE_TAG.to_vec()).unwrap())
    //         .push_slice(PushBytesBuf::try_from(vec![0u8; 64]).unwrap())
    //         .push_slice(PushBytesBuf::try_from(PUBLICKEY_TAG.to_vec()).unwrap())
    //         .push_slice(PushBytesBuf::try_from(vec![0u8; 64]).unwrap())
    //         .push_slice(PushBytesBuf::try_from(RANDOM_TAG.to_vec()).unwrap())
    //         .push_int(0)
    //         .push_slice(PushBytesBuf::try_from(BODY_TAG.to_vec()).unwrap())
    //         .push_slice(PushBytesBuf::try_from(vec![0u8; 128]).unwrap())
    //         .push_opcode(OP_ENDIF)
    //         .push_x_only_key(&XOnlyPublicKey::from_slice(&[1; 32]).unwrap())
    //         .push_opcode(OP_CHECKSIG)
    //         .push_opcode(OP_FALSE)
    //         .push_opcode(OP_IF)
    //         .push_slice(PushBytesBuf::try_from(ROLLUP_NAME_TAG.to_vec()).unwrap())
    //         .push_slice(PushBytesBuf::try_from("sov-btc".as_bytes().to_vec()).unwrap())
    //         .push_slice(PushBytesBuf::try_from(SIGNATURE_TAG.to_vec()).unwrap())
    //         .push_slice(PushBytesBuf::try_from(vec![1u8; 64]).unwrap())
    //         .push_slice(PushBytesBuf::try_from(PUBLICKEY_TAG.to_vec()).unwrap())
    //         .push_slice(PushBytesBuf::try_from(vec![1u8; 64]).unwrap())
    //         .push_slice(PushBytesBuf::try_from(RANDOM_TAG.to_vec()).unwrap())
    //         .push_int(1)
    //         .push_slice(PushBytesBuf::try_from(BODY_TAG.to_vec()).unwrap())
    //         .push_slice(PushBytesBuf::try_from(vec![1u8; 128]).unwrap())
    //         .push_opcode(OP_ENDIF)
    //         .into_script();

    //         let mut instructions = reveal_script
    //         .instructions()
    //         .map(|r| r.map_err(|e| ParserError::from(e)));

    //     let result = parse_relevant_inscriptions(&mut instructions, "sov-btc");

    //     assert!(result.is_ok());

    //     let result = result.unwrap();

    //     assert_eq!(result.body, vec![0u8; 128]);
    //     assert_eq!(result.signature, vec![0u8; 64]);
    //     assert_eq!(result.public_key, vec![0u8; 64]);
    // }

    #[test]
    fn big_push() {
        let header = TransactionHeader {
            rollup_name: b"sov-btc",
            typ: TransactionType::Inscribed,
        };

        let reveal_script = script::Builder::new()
            .push_slice(PushBytesBuf::try_from(header.to_bytes()).expect("Cannot push header"))
            .push_x_only_key(&XOnlyPublicKey::from_slice(&[1; 32]).unwrap())
            .push_opcode(OP_CHECKSIG)
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
            .map(|r| r.map_err(|e| ParserError::from(e)));

        let result = parse_relevant_inscriptions(&mut instructions, "sov-btc");

        assert!(result.is_ok());

        let result = result.unwrap();

        assert_eq!(result.body, vec![1u8; 512 * 6]);
        assert_eq!(result.signature, vec![2u8; 64]);
        assert_eq!(result.public_key, vec![3u8; 64]);
    }
}
