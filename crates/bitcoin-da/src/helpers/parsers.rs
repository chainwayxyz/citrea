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
        TransactionKind::Chunked => {
            body_parsers::parse_type_1_body(instructions).map(ParsedTransaction::Aggregate)
        }
        TransactionKind::ChunkedPart => {
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
    use citrea_primitives::compression::decompress_blob;
    use sov_rollup_interface::da::DataOnDa;

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
    fn issue_1686() {
        let hex_tx = "020000000001015ab9169631a38a1685e2881b2978a32f0c6b8436682daf0304151f6e2cf51d660000000000fdffffff0122020000000000002251206d7604747b7a36ea98e50a5a6ec92ec0d8b46ecbf356bcad49a390405ea6999b0340601eba044133206d68978fd9908bee3c02c99bf134f7662cbe82923aad781e7ed97f18465be02e64c1f95bcf6e80a98691cbf9229eb9accd3f9f07c9dccb9909fdc63220f00eae06e9c6567d253d1d1b37847ba666b5c1660438cfcd3f020bd76ba2e1c6ad0200000063404f8a047e21801a87e9f63e965b72848b2e17561dd50ba6f42e936be269bd9fb7050e0c7f885295386c3c70332f6bfb82b0fb0e3ae0c9c6adcb9af02adbd68ffe210357d255ab93638a2d880787ebaadfefdfc9bb51a26b4a37e5d588e04e54c60a424d08025b6624323250b323f1a96706848d23a0001e01ff488c6d13e5d189f4c9af65eff747a8e40370ce25fb41e0abb7043ec103726ea48efb49235c0de8a6f70d1ec434b84bdb8d02bc813cce36201d60ac59a104e2878904c0a513195801ffd80de4406e0be5cd83b30cdaa20f18457c14469c69ea6d3d0a38a4a07f3d81bdbd663e1bc2e50f6480536832b5a5f84027a823fed5b17b613171216a4a350afec2d8609f0120c6e4a000500000000001dcfe1f98b6b74d2c03b4d477436b68fe81caf3214882d2b61f44839b3e5cb644b8df0b982f21f5acb561b9d80b8c1c7933f97547edbf93f8c805c475f6a27ccfb6a966c2020410b7be5344818fac910ba011a3a88c6db0c449796189fb1babdee0e600968998551f71fb9d3b6883953da8a67a09a6643fb4ac6411da78f5d643425a3084df562e17a54ebf0367af41ce65d87fff97eca3bc79b3813e0133aa00ef254350b6672ccde3e1fb58d448c1de8df9db7ff891b200686e83e1f52d924ee13f913863107cf277eb49d3bea557dea37b958863502c4e873af10dd6a9aba7113040aa5467e7ed58381c2d817558de14a5805bb271c7d1a707d713d932a25ffeeb4c8077121c811880d0a17e227725138746316c7ff59a6c9c81e890c2a9e44b39a470cfe62aaaf708701a48dbf90705e47bac3b4e8c66e7a43ad39e7e4242b496b38cfc8e597f3fe4564333fa78162adcf5ca183dbfb07fa53f4d0802e0e07c462189a15e8996b5fb5fc2d568c3a90c812e5d33841aecfb83f2e6594cba59f88e4a374e8605163ae3e14fc9aa8040da0f84603778e042000078000040dcc39ec998097da7e6be01841600001003008b1b0038a87abc62c5b4dd5d984eedfd9e72562eca55b92977e5a13c9597f2563eca57f9297f15a00255900a56212a5485a97015a12255948a56312a56c5a97895a01255924a56292a55a955555375d5504dd5526dd5515dd5537d355043355263355153355373b5504bb5526bb5515bb5537b755047755267755157755377f5504ff5526ff5515ff5a37ed59ffaa7fe2b5e50855458455454c5545c255452a5545a655456e5545e155451955459555455d5545d355453b5545b755457f5545f0dd4508dd4584dd454cdd45c2dd452add45a6dd456edd45e1dd4519dd4595dd455ddd45d3dd453bdd45bfdaa3ff47fd1010aa8400aac200aaa600aae100aa9500aad300aab700aaf088aa8488aac288aaa688aae188aa9588aad388aab788aaf044aa8444aac244aaa644aae144aa9544aad344aab744aaf0ccaa84ccaac2ccaaa6ccaae1ccaa95ccaad3ccaab7ccaaf022a0ba2a00aa6e00aa1900aa5d00a501885553885570445542445561445553445570cc5542cc5561cc5553cc5570225542225561225553225570aa554a05229b5d228add229bd3228a33229b3b228abb229bb7228a77229b7f228aff229bf0aa8a00aa9b08a4d0802a8a88aa9b84aa8a44aa9b4caa8accaa9bc2aa8a22aa9b2aaa8aaaaa9ba6aa8a66aa9b6eaa8aeeaa9be1aa8a11aa9b19aa8a99aa9b95aa8a55aa9b5daa8addaa9bd3aa8a33aa9b3baa8abbaa9bb7aa8a77aa9b7faa8af827ea84ff5a5bed58f0aaa900aab888aaa988aab844aaa944aab8ccaaa9ccaab822aaa922aab8aaaaa9aaaab866aaa966aab8eeaaa9eeaab811aaa911aab899aaa999aab855aaa955aab8ddaaa9ddaab833aaa933aab8bbaaa9bbaab877aaa977aab5ff587fe2f064001154881154441154cc1154221154aa1154661154ee1154111154991154551154dd1154331154bb1154771154ff1954009954889954449954cc9954229954aa9954669954ee9954119954999954559954dd9954339954bb9954779954ff9554065411454c1145c211452a1145a010aa3b00aa7f08aa0888aa4c88aa2a88aa6e88aa1988aa5d88aa3b88aa7f84aa0844aa4c44aa2a44aa6e44aa1940a542aa5561aa5553aa5570665542665561665553665570ee5542ee5561ee5553ee5570115542115561115553115570995542995561995553995570555542555561555553555570dd5542dd5561dd5553dd5570335542335561335553335570bb5542bb5561bb5553bb5570775542775561775553775570ff5542ff5561ff555d00ff5a9bed4b7fa5141155261155151155371955049955269955159955379555045555265555155555375d5504d4d0802d5526dd5515dd5537d355043355263355153355373b5504bb5526bb5515bb5537b755047755267755157755377f5504ff5526ff5abfed0ffc50428a00229b08228a88229b84228a44229b4c228acc229bc2228a22229b2a228aaa229ba6228a66229b6e228aee229be1228a11229b19228a99229b95228a55229b5d228add229bd3228a33229b3b228abb229bb7228a77229b7f228aff229bf0aa82c88822a98822b84422a94422b40611456e1145e111451911459511455d1145d311453b1145b711457f1145f099450899458499454c9945c299452814aa5d44aa3b44aa7f4caa08ccaa4cccaa2accaa6eccaa19ccaa5dccaa3bccaa7fc2aa0822aa4c22aa2a22aa6e22aa1922aa5d22aa3b22aa7f2aaa08aaaa4caaaa2aaaaa6eaaaa19aaaa5daaaa3baaaa7fa6aa0866aa4c66aa2a66aa6e66aa1966aa5d66aa3b66aa7f6eaa08eeaa4ceeaa2aeeaa6eeeaa19eeaa5deeaa3be0afaa13ed597fa563f2aa8422aac222aaa622aae122aa9522aad322aab722aaf0aaaa84aaaac2aaaaa6aaaae1aaaa95aaaad3aaaab7aaaaf066aa8466aac266aaa666aae166aa9566aad366aab766aaf0eeaa84eeaac2eeaaa6eeaae1eeaa95eeaad7ed51ffabf580005542005561005553005570885542885561885553885570445542445561445553445570cc5542cc5561cc5553cc5570225542225561225553225570aa5542aa5561aa5553aa5570665544d08022665561665553665570ee5542ee5561ee5553ee55701f5c58cb01251a24a4c892b0925a9a494b49251b24a4ec92b05a5a89494b25251aa4a4da92b0da5991608496b7022a63c77b6539b28bc0c0b0e21f95550b2e710a70d10ec9a2b57875b2c43e7406dee346d26b0a219e390153ff6a4769d684db10422f936bf7f7a3989cae5b5579024e67bafd2616aced6dfb8cb7064303744c4c9a78ef9b538665408107062c1fa6fe27bc16711295d266f4a19c11d286b44751810d86c8f742ae13e7819039648a3d6e65ca0ef5b0daff4983a50c544e44e988c90284f932267899039da6ab2f7b7751753738a20af500784a5cf94282b83e69fae57d219f05718c5cac2ce2ae74e7a6e050dc6a4234779b018782703a62cdde3880c8e8fb16c32f5e31865be16696ebf4ab9c9f09800678a7891c10310193289f4202130fa3749d45704bfaba81e68893f86f7d12af31d5b1a0e14e5998109ca88e922b5c618769f6415bc15c180e23998eedeffced8d78a785414f38e12168dd25fc64c6f6598b25367a1628878d51f990b65d94990e55fbf9dd65994632c31e77f560a64c2f4375206db7e84f3551bcd0a4fd5f5176842630859b08a9bbe6fd362a64fb52c28532644cf0f45b5b780a9966d521c31c3eef5edf9bd35bbbee40bf0bf2d46cec74bfa326312b0c23f9d157366515a3c02de16cabfc618d3f36f04dd86bd967729bbd372b3c99ce92674cf4d080254e7fa6cf2a51e7e9f7be2a7c4c58b23958ed9cff8edf8212a56264745164caad07cf124b668b65da2c792ceaa7b593265cefbc6da6cedc064179b0cad1e4d5932610d86f25a4cce998c37e3d06f5c01f2a5cc2db2544308948e66d7178c34a7ae64c5a43e37aa94d46edace8382d9274f163400326c1446d151003b4441834e879b2a296ba6b44c2d56f93034050c061fda1c64d139b54b4a16cb6aa424e4a4aa4c6fa56135d93075d2952005ea0ffad2bba28e537614db1f99fb432cb78397bc98cf608638d5f1c99669ef3ba08dc079135e1f1e17dc5e25dd3c03fc7581d3c423ef35693c3afca5675b764c09099e58ce5a78bb4007c540d411deaaa045bf3cafd4bb07ae7d3db4255740bdec999ef7e5f9d97303b92c7803fed72066388f478e94d1a121bb0c9b883ee17f8388c881e9b25a09141086e4c375dea194055ff1ed6c33040ea0e2d229ec0d6c5154a934902313b5fe44e552da2d3b6ef89bab00e309c7962b6a7fc1bfff62bcc7c8f9694dc71f72620216c163c94f41ff82c561e505171f21af19467bf293518eff11792103198dc2e5cca4f1b15e4cc664b740c8ac7b0cd7b095bec64698ae7c04045f0fcdfff4272c87940b53f96c8d112fbad5a1caafda3f7306540245c408545f0fcac2fe0a1eb887dc1863b932595bd06d1004e4c8c58f23f60df3257870d431667ba9941e75273c1235d9237ccb8d094dbad0532a1e84c54d0802e776c31347fd749048975f43677c7287ac51bdecfaaf50b0dc99361441813b84d90109585931f11a1189add0648dad4eb36ece3843f8c50a6c19f260f269910ce08b4733c9e4eaeb80273f0141b2499208c23947d6a4db9f4ea96d6e932753e281d65e9ca54028b65ddd0e15ff7855454d017decbd676b921304e3ddc40587bc989623a174f727bd9638c2ec6eb4003383d8e1d4befcbba0a3ba9603d35284b71ef2669a44d53632b4bb4da287f52e8c3b625bbe7fa845871ad951722f4fa947991189960fd39b79388aa893bb13e32a39065f6188e53def71897a62a2204b5e3e8cc621f19d7c99f2625f97e8ed14a1d159db5743e706ca148ff05f10f725678eabf4d08cac7b3be5c7242e9322f5c77e256bb382a2908180b780bda20bcc12ee8da5cee73e781c965946fe4c7b5d4925fc6345e6e157b30e9188289d1a67404e0f91d6d52d716254afa6a55905303d307a09cb625b48e11516b377714b7ba4a4b0b79d3f22053d5d375934846e7f2b9009f217d06755374c851cd7cdde57a0e3a7a29f21502c8fea7c21aa661560f9ffaa20266bd03089f4601ce079b38b4cafc63f741c761ca1e8efe892e1c275c3157613640533f5976a531234e38d41693c481313bfacf179483b36c66193ac6d181f9911068a2a8409a6da071bf1ff69e7f0657388bf3950bf8e60729fc0c52a56a7ca13fd8f1198814299b6e930eb344c324f8bc08c82d14d0802689138359480c52027e2a437891681897b73cb0a6352ba5cefef909719f0db3e296e62248a68253fc5148376ebbe2e968c7d8a4aba5138936e488af2a0cf827b752c51a4439684ebe1dfb7f56d1ccb59bbf50bc97682064d4530fdcda046add35f73723e06792411d85894403088384310c247813ff9c3f789e2a048269c2c1d6636149ad40f23d81eab2eeb021148fffa64a43a52a630a370b232563d45318571e27a5630ddf4d314f63b65a74238f217fe75899b139ab0e52f9e4b1da2cb503413697b13f530acf248de541b027177053fe055e15ea1f13b2f211553074ac5a2a518a689a4e596f1a7bf66535e68ca25ef9e857aa03cde33a8c3a2dfb04102387ef2af8a65aacc7a668ba3d978e56399f9f9d98a6211e8d10cfc881f3f1fc1ae58bc8b227b501c13f055d5aab9da81f0d035fede954b463deed9c9a869bf7b47b46b9fb444afac46f14c6299f2590dea85125a3200b10f4915639d27f346ccb3071ed7044f18d45c3943253059b35abaddf91892a2b48b853dfc2ff324c6c3b4312ddeb10ca2882fe85ef5f6572213a5305905234a78ccbd6de90b278711d74af396c5a110dcc2ff6e1f39f6d1231625317db073228819545657cc4794cbf2938e66808e0797c02329ae94ddede5efbe262999a9a2694c2100e4bc865365580bbec3a5ef83ea8bea91f8404d5570949ab6494343294c5fbb441db3839b1ba55a868b956235454d4d08026b85f3968854cd46c3f7fad2284f494a653a023929b9f285507b2c8fbe3be2af7dc5a1e227655397997e19b9af8704ed06551a933785d3d768cc83ba88141b77c7d60a499f63a685ac5ca6885189a4724ec126b9d29954290f5817902eff263b09af9db98acacbc04addcfb0040e592d73cc265f01b995c1f430f2d8bfcba1184470eab0375e1759a638765ecd34cc47c85a64ed1ed08aada54ca6c27999c1f4b49ed2e1063d17e91308bb4e28ec7f1f73457d49a7894baec08156653115fa0ccf6371b163a34243caf69a5272c7f05d4f56112b8fa50b1483b37a13e32b9ba9b8e59341dc28b6f192ca7a75dd35d2b4961ba47130163d647504616952863655394ce0ca553e75ae2e6e64a411d0caf3bcbd8cf81c2a876ea10866f429f0160d251aca6592cdbdee9fc55a9f6f4f9392efe1acfbd265cb99672af693d04ce1e1f9dd309f551e9394aa9dfa7b1d416ac9bff94228e5e39eb9823d2712b4581e16b172ab94fb4801e533815ecad39b71fe8c6c577138d032db309b3ebd86054f521908a635c15d518b24a880492105ef68386c2e0910a500c054aa6741eb9372b2f6e2a3fa91eb2ef7ab94fca742a6adff4ce9ba8c77a7dd9a73e66712e25e19b02ac3f7435684021f68e78da13ff52a62023d11580f0d60ccfd545ba3dc3f9a865ef1dacc3e61c66c702ee4d3a14434fe5231d3be7647ffc69127bf5850ca9128e73529493fbb79de4d0802abe41fae6c0b7fd62f7c629530792854838295e98dd96d61a6c2ff405e63d5b65f85e45ebd35760e104b9fdd59eb2f53914b72b77b43330da2a5dc07773a88a5b6919e351f4ad7cd66c0dc412606a7a24a99c07c0b0972f2cb07903d07d8782bc13922de700dc729c6838ee014e594ea2b6154c614935dfd2e55ae9cc65df9616b221dbdaac9033a9f55f0b77dc3df5c58e0e6654de54c61184394b7f89774c0fdf88c0b1db74db7ebbac92c5c1b2afd86a21f45a1103dfd63b2b74e2863948ef961345cec5c3dccb0da82523852361f9c50d5cbce9ab2ab3f5705d3a22c3bd32134b62036dac099d77c40704eb042bf869fbdaaf8c2c0606c1d7ca6804c95a42eb60b543ff76b1ed74b7ec3a387e63d817ff48be4980241bf65d38219ae54c90409e5431f40fe460bfb278f2bac0151c9f3715e1fb39d5ff9008538497ad48e5f554c25d40eb76d556f6bf5a53cc4e4233f62cc3e43dc89f7cba373e82406c52ad9bfaa6642ba3c995765ca562af42ceb764f95c7c36b5615a7fa03f48347895fa0a92c63560d53c1901eb67bca142acf681396cbcfd809ca02333a4313e8173ab318322da75e8b6a99b0c52a7a0de7540c22d18e6c53276d1ed289126bd6ed5d2f4936fbf9b65ffe8eaa8e69753469b5224f35c0a19a921f5457897e96e3c0b2b287dc75353344711ba8d6a17a26780f6c7d4081aab1682d2d655ac7b6dac748ad4d37c778e6624d080284f71c18702f4e0d4cfcf2cb30ee19f6a7157503d8e18905240131d9d7e53eef7c1f0a8926e5ebeb736a641a71b0318f9a62dec64cf9d44b13d823ed6f490efcf5533dbc45b94cf228f3c55713137bbe46cad33824e59c656af2530c2ff6d8540d5ca98819f81709239a179388af9a998eb08c0346b194ed6eb2d3e9a8b0fd7fef88825254f0a1df11c94d2c9c209dbed4c2b4c316eaa08e00c326b328a7d1fb864ddc7905c1419a483a7e96d3bdf3b92be0ad56a6011688037883e08ab4e772f66df45e489a46ad3b7d714fce76eec66917ef2476b531853a632cf7932dd4e9caddc3157fb4aad010a381a577d9bf5c75e4793d5665d7aa9d896bddbc4ddb2b61528875db1e0fd4d30cd701151d61145b35f5d2645e8b83a0471d4c9ab07620edc5f6e526b9a957bfbcb9ae9b14580be65db94bb3adffaa8d98cf99d5c924401fa58677eaf3d191dc496a3572a2e957024eb73c60d9b7ae368ab048a19eab2e268cd18af4bf137e0bf93bbd0ac1b505dae23b347f65f753fa257a92c71005129cd4cd549bbcc7f1fd350d767688ec65c238c89afd76fe73f5d809fe23a54043d46663ac1e26b07606c13e6803168952694a1a4427ee4f5529a8edf3b4b780742f69f2f6b935f5324957157d5d23cfa39f3f90cb8309fd7885354062d14cc7659e9c511e278d49cda98f4956cc635649293e9ecd8a8b93b6382b23a293c6365098b0b3687c2746164d08028882a47e26682982e8ba5fa2ca8e541fb47a75bdb326bfa400df34f3daaae7ac2881d23a780d30e56fe1c8d15cd81d9ca1536c45e0420d6fcfd9b6ba7324ff3ec731879981d4136a90a926afabba1ef49f30cb9a5f4aa6c935bf3f1aed11cd0c55d3bdf59534b2c1aabc8698b03dc9438daef06d82b4b0933e11cf3a82ca36b0bea8d817e190d9fe3a400a4b6998a979521afd3bb0475bab52616efd6405073d3cff6b758463b6165f6030afca0242234c9072c3e0976643e83941bec16b4cd7893383a722cf8eaa63c006a85a96d0962a8d323d7f0fa7a748831749fcdff2c9e2baa58be0f22a4042e5d43bdb2782fb945756d61813f0ffb9f13207910778f503874fbb152f914d71493cfea687da1dcbc94b00738ac699b2aac206a26cafe5c90a6ec8ed5285fa849e564153df46f479502398d52c2ee334c1d46b6ca0adfa2a5f0cf7f74cbb6c8bcef6328b1906c329b8c7ccd1c8ff2cf7a151934c318efb146fc5e215ac86ec8224e64c5aa3427a095c8214eaf7cb13e2c541dccb9a6212eac135456ea2def81f907edd1b1ea9b935c642055ed0067b7833e4e0a07cb9ab69268ac939b2f276709293c0e6c66514abd14bf5cce7eb5eb82c7417ffb32a879007cd30357089811844852fe76826fe893d2a1e031268cbb95fe8b5f1959a433f932a4e68968998fc35bf4755fd47d84720160370f5e3f53283bb1b8053a3b7eabc7b227de2a6394d080226210cf8c8ad746ead55c6e6e66ab0751a86ca519777a2753f32e22c1ef5e4a56bcd33b166311f9335d90156c42e9bb38c56fc7a93f652ca6408cdc8d508b24a3c7f89b4c0744dcffbacd3011223604c1651deb55ca7044d9176b76bc0ebdb7e310f493ff4a945a692f7549af59d1ac0fa0dd253b76a14f49ff0aae5c5e914975099a5a3c5f18e5c2d31e538d9fa511f3e23f727726e231a57024adb9c4face83ef771b966122ef626d2f59fa9d09c151257b39dab6e49f0e7e4e57f8ae94d8c5e0af24c084fbcbbb088e17aa796997ccac44f63454f5476670d69eabdf3927dc3c737c7e58b48c68e4ab74b3887d5b4c29453bea7f83aa066c8c789bd877da9976822906e0c2657bb65b643769acfe4bcaa5526b60205a0b67e2677855549f2b3381a52bb5832de11717c5dbac8ff418815fb0bad31b5cd5ff68e80c5655747f141ea1d4ee10cfe61f9e103af685892842a17b4ce8ad33a137236773fabb73e46269dfb79a3437104d7ff95c2916ffe0f6f353fdd50de27286d303de12204871050097e484022b9d275af0bfcbb3a13e6260e1ee3e8bc9d564e11d32653aec3f651fb7398b546790d59d1958ef5c37e8d77f6fcc2aced2c6f1f0e639b83b69842eac58746afcc9bbe44560c1b779235d5799b764bf8bd933d2621f78d5f05ccb4cd64f90bfcccfd5fb9b2356e86c8b0a1c8c3e7400fcbe6a3dabe4324be257f494da71d261c72624d0802bd39fa8fc509f9e8dde0b18e75af3bf17046f698b7deaac7f2f390cf66ed32fd7cf929b46e9c05114f6d70c36654deb099b08d4fbb3510502a84fac78d1338698f49c26b6a68ba57d4c0729c3cf5c1328ba96e44ff47dcb7eb6248c665a58e45df5dfb4cc85e6e976109a190b39444be4f2f24641c4122356c714dbcf64c72d8d33276313a60dab525eb32e537f99beb8ef47d68e872c2aca12e3673cb7859f6390dd4f4efddd32153378d38fe592835201a7bf4e738a957340dff2809c5d398ae34ba2130b8574344474c8174594a5cc11c7ebe5549335c1a72d5e549e62a9c2da59fbfd05887ef436f0e1d33057a8a5b7bb5c4e92baf089b1f16ae29510fe68237a0305ebf0b7e9e8508e346eb84097d9a52edffa53c11efcc30a975051987461819d3ebd88da8dfdf259f997d580d9d32e1aa8548b9e4b14bf41dd91ea7ca17ebba5164788d2362d2420fff2bb64f71d4d319136d3e92bb1bdfe568d86a26173a03ec39154fd5d8f68b3291b1d4f87611b7aeaace99363dd37752ce78db17d38d04398e5a8762b93d99091a1f7c3ccce70fa9b6bea974c164de706568ff0e3f75ff7e042b2ae0d890a5e2f4cfc540a6f5306a508d02ccfd5b974cba882d9b59ec7d63605c34db33fef06f50b1db65ef5be5a579e4a13fc3cf22edba622acad445b6cd4f185fb8d685be2d515bd31f9fc5a081a7d96bd1e99b6985cff8d235936fa6e67b9c21034d080217d73c2f7fb2f5743e32adb2a50c1b3aaeb95a11166dd44a896e988694699d7aa50917574d1675f9082e8b23717d9e4487f1232fbd611ff822ab2674cbf4a551dd5ec22e9b9f74a4cf0649c1d0518f727ef58d85c627151070aa176595a33b26b8274e16583644271bfe520a67deefe5d01ea5ab540cdf75d9286ed251fb8052dd3359eb12eb6a30a73543b68aaef34a053f1036646dc53bd1d8e38763b77e5e0a01f5c094a55ddd179d72e100e176a9a0bb485704811532d77a47e31c57cabdb3b2178aa847262abc0b648552d403c2de7cdba8c328be8620a802f1047951fa76bbcf4b4214623d314141ec4fdcb9c0d94a1d9c7f9103843cc951837edfb6df6b308082680a1a98f87a662a9890fa5afdf2915fcd9be242a2aa499488b8d82a6c18b5a78b9bf1a5875ae5d60bd33acf31f6977e7aeab1c3c47eadfcc62fcb373b3461e5bc41d50aee191662b3975e99c054c8ee038de824248d15c5b6da37dcf999e39f8525051d8bab6da4b04c4773f5c69416e5b5c639c95bc0bf8058c500f39992c7c86e2f2d4d9e39fbb97e1155f3cf4aef4c052f66373db44d42ed3cda76bd67ffae301365be5979a185eb98710817892d3ef4c1242a0f1538d3c9bb3b7dcdf44e80273bb0413ae1b68b47b80434a6869e478696d1275331a8826646fbdc506094a8790614c14f7d5d77d8efce434eeeb9ea653c25fc90be989262c9130762344ef29858954d0802dc5e139a81c90c5d34f5a20f9979c0fb6721d9727d339593916cc6d20cf9433de93ff33abe4b8ad7cc4adc08965bddfe85fa1249e0b3d00f937633e4c1534cd24961a88adb28f3ecdfc2f32a4af48cf49ef1975f89ddf8ca0cfdf2e851238264f2e25de825ce41c36c7fd95f2ce573d75b24ecf4f92ab292cffa3d1978002684de53ae54976c79dfeb93e2efae6d553757ce268cc9ad70a8d906b469a317458130d52b93acdfd135b40185b0bb7c1c651ad5a1d6df4bccfe6f568992a0b4fc83b411281377c447e17a0994b1f2ef55d91ed34e9d24cb9ae42117355191e43a5bfd88f894c098f2413636f5bd2c806732611f58b49971af4d6e8ffd82f2e705250cd5e8b9cba80267024443dbec282717e512e4d17533d547cb617ca278c2d3e426c72281044fc4390b82a9fa965443c308465ad7be5865df8c1a8e14f65b912fff2da4f05d7f0eab03ac53904cb05cc89244080557a69e208fc3e65647f9fead365475d952833920f46710609a8262ca28774775bf57daec9aba6146387fb318394357ee1cb8bab03dcaaed423fa9811349343be59da86aa465feccbff01ed326bd941f8a53d4b95a6a8da567a98151ac25cc130097343fdd0005497ea88a8feeceed51985bf5a199201248a8bb06ec04d31279705cb44b39b2203920a2a2d92f2fa7baac2a2567b9f352d70587299fab15b1c8eda1e213826acf86e89d5532fbeb2e8e5b3763c014d0802cfe506f80c844d8ba9c42e03fff6a4a023c1331130d592fefa522cfaaafca12068922afd6776ce31c242836f82fd42d8818ad32c04a61c72ebd6e4bcb9341f92e2241f6fa2409cc7a6578e72e27884f48dac9adccf682132bd89e84b4e945b66b996c7769163cce304779f0a55e884d35b52e9fb350fcb1a088909694ef8a32f0fe5166338aa87995baadb908ffa54a4977d6bf19c988ed2888947c84c843fbacca401644fe3b4d2823c0862399adda2b4b19cc2fd39db10fdfcd3c074a1307945b0baf5e7144de1184595bbb0308d0a65cf118bf65886e28033b4d6abc1550b9569c0d524f2a21ea270f5e84d6c34e873e64ff23ef98c05eb9d931c62c69b4fb4add0985a0d63e22bbda9238f3bf817898da2496619ec0f661577e1463c944d7954157f84ce14e04aa60d904085cb778925866c83a1c00e8757dcad9e45625b143b53b7ada11506d3b117da2b71318e84632cd4074c49f63ac82a263bfaf8b9d5d6378c92328eb787309916db91668e2d37ca1609b26ac86a8e7b16eaba69e61198bfed8ab36334a7a32285c58459191da3034ad6727945faf3526cd211778ec62862c6817eb6b4af5c1e56a62e6ca6391217dece00b8b3ceedef14418a6388548d3ac13dd49c4cce7c344c69cbbe6ae1309d91b9b211ac3573eaf00eab042a53d10bd7d0c01ad4e21c7fc7622f7450508d0997a99cba95f137e9fb7ae70a63bd80da68c73105344d080209df055ffc531aba59804c2a5b784c31be5dd4645e88c8cd3eb3939258cbb16c18683bf5365d872f4ff58caa98bbe9c2674ae933a5980a6860645ab564aa6cc33beade95e72ba826373878a0b38ca58b3a1201d3bfc6bb4d3e7c9313da59f359c943b41e75f702d744af768bb2645b4c85143b55113239e51bd795edfed43eb4a3011f5912323c6d08e54b0ca50af1104a106de14c0122624adad27165fbb4a6150cf4f904b422f74cee99430e09aa5d0d5a7e50f4e99e2d44cc64e7895e7c376cc5fe4db56046c35fe96a663adc4814f47e47c1b009c483699b15099324ef52f544d795b4e21ddf59217e8fb9bffac96071b6c396e10184fd748e4bad4899c6f38cd7067c5be7e467352640733634cadeb50a358410c5b714689ab3d7191744c684481c0997df45196aa220ddba8032c43c5eaac858f8fe98e526eaba695032672f72a6c77b9f7df9957dea3b96a1ffdcadc8a9d2c8ec4a67936e5a0b7fbe817c7b63eea2604aa81078e32da8fe8e24f4b0c10ebfbe2deefb10593b3707cd28886099addb8f172513bfaea9606b1125bbeef330e23a6e5934773b41db372bb4ca64979e69223da2afa8981ccf3386ebad5e620d9b9d7ca4900fabaaf2b7084e3459707355544b7e877a1344cd744b7ab1f27e395821f51a0418a189ad8e792db13722edb4c26024003c8e1b9845c3840463233935827f1db01013ff1a71fdcdc802098cd6b9ff654d0802426e28a3661828172d93a7344f2df857c1ca6f9d16b3ab4129f87d45eaaf7e92359156562af8a6ca879be8985ac41a3cc672f9f1af8ed1148d4883fcec8a300697523f43f076fe0cbe4199ac8a9e6971d3a2510115c642e9eb4b5e08127f35f808b3e07bee1bdbcabd67044e5bbb5d0c4cf74da7efaf52b741d8ebc7f8a28f22b5119ebca9c34d44fca4c7f07b0b28c0ff6264b2f7c1944f30e0ad7a29b431f6c278bf082df45041bbfb5bc9cfe4bcfc13935d2126a6527045643c6c3ae015879811c5c1a88542e56cced4003f9bb5ba0851d49c08bd989994daf04a07970b54628f461e8c00cc3630260a0d8e45f56cb2989b4a30995adc6261f2f4b27d960e9b8f6183c5ea93fd15f34ffc470f15a09ef18fdda48e831a56b749ac4c07c8514a2b171ea49ac01b726e1fe434882430997495778c24377cd48885c131b131054483aef7f2d9fab1988b9586fbdd575b6389d32466da8e8a90db613ce3299c889dc92187282c2a741d16fdc979ed418b5a7c4a73a6b6c9b3807060b7b771d2e926421c4c69e237270d48088233cb8af5d225cd59f7871c8d9477ba338f181912e7bcd318e264eaa4762494d3a992a0abcbace9abf5f67887f128d633335bbfbe95b522a12cfb272e26c83e1d542265b5089619ba6eda167e58b77791aa1be70b5a6a04b7bb55505b7bfd6102f319779ddf42cf4a9f181748d6afd33751b29216533ea79298f845334d080297ce8c15375383cb715f4bf638a4a9acfb369c12c52162d9c17d9c4bef07d10ef1f0fa98c3a67898c0c5bc69b6c349bda22b1166ab9310c58d03264856bd3f69a03eb2edf76c9e87c4cbe4ddc71b60d4b01b71115541e2f1e18de0fedf868a0cfbf4c3677cd20fbeb6415b7c4ca9277732171a594482e6844b04d016118a8fb037dfe58a0f188345651b3afa36e2671a65dd77063e419d933311fccd26aec6403d474f3083af73db50d404fb335afc2501262d2a4c089694da0b83440bb419f5eb4ccde1baac8145c24ddd42e76f61e53b4309328d4813ca83335436400c870b0da8411818258e4620ac8fcfa56aadab3d9844934988293552755bafbfac7c81b86b4736dc429220d1b41489baf79991bb8bfbbb69a84ac24c8dfb4440779c171e0b7a5dfbca6f0204ad10d2427e307609fe9c61b650d9cd4c89307d5cc3ceec56a563e4d79d0519949ad8e1014d7163c3f733cba68e608c11687524cab469f31ce9b96bffe8a5c37dfa753e91688686b424750c9fd9639f0909e9bd5f2b31a62a880580d2312ca2891b2cbf29d4201ec5129d6675e24cea60c29096734523aec499dc44a5d48826ad13a7c4c1a208d88464709722ae9a5ee21fb984804baed064889260ca357b2cb800427d85e62f886bb1e6355fbe3a40e3f64ad863e15fd1c11556c14b92696194bfc4ad363004ae0d4f8d41c972baee80af27bccdd46cf84c86b20afd8855524d08024c127bb5a17f3b185d7fced8f79348b394c8a8ff0331e786ee5875d748a96ecde624cd44c90e9272fd842148a16a795bdaba37e51102c29a757898b6344a11e83647ba2619a6dbd416574235ce2a543f77b5c4075961555ee71c478e41a9639111f041361f61c96a69a8c5cb0fd1df0614c231ca67aa7baa1707600b3d561f3ae3d08b29ecf623498e49d5f6b95635c4f443f4595435deaba7fe7d139b3782eb7368905ea68ca112b25ef24c6a0806f03e875dd3bc9a7cb8f554c03091da9366bd82c02bd347269ab3b28753293075bf86510de789449de093cd19f1494beaa42dab527af98eabed3e1c21eab0324b91294a7c2a62720c6c61a73caf132647425ae91a9fda87b623226e69c348b23dc7514a4c1c3c9c2f0321a9a06431b09e42a7830d5ef4246f87bf469ac424d924269f0152526612ba7265bb73e614678be9f5c54a7f2544a406538e6f07aaf637f0e3c704d63a4b85c94fcf79bffa565a6c890830fad516c1725da3f4aeabbda7ed90b0e4de787b5a22552602fa929fb55be4a3ee352641dbf1f610e0173fa7925eeee6ad060183e6ec7a9cd498be51599ed0a2ec07466d6a8671888b97c17d6dd8a2778e2f09e56269700af8f8a5ce9406c2db6c3d7388df9962becded3cd88ae2e948a83bef9f45d441cea6fcef89541a4c02fee7dc399d53f892785dd95776a41dcc3c99bd4d45b548fd0e6cb946e51736d25cba4e6776614d0802e08d82902ac277c9b563b75d37da731c496d397a363279217db245bd04e35c73633326100fd0cdde8098605afe6c674cdfa72abcc5b275fa3fee12aa385e5a8c1bda5db1c8b7d0ff54497496cff48541108f2c4a8044bc92f1a504f8376e8d81f51f035a552743a8787d3fd6c0f5c34b9d8835ce88b0f0a6d5cb7f43c54f52fadf1c74a5f6f0b2ed6afa414c985a0e4d9b491afd39401028603586183068e1011a541fc0f6303fb7e8e496a8014331ddfb3eb7ac5fb524b72dd7ce73176119db18db9c50a9c0a9650a129491d5bc83d2fbba2adccbe390ed8b47b64c3bd00a62aefd6cdeb175148de11b575269c9b35bf8145bc56de8054554c3e7f8e6b71e1cb817a6d736593ba48ecec55f881968af1e607fcb77e454d20e19b1d19af8c7a036e41f5327ed7d8c506ed4d5e10dbdae8a6acbb99045a9aba843a9b34dab33a586a709f7f5674dcecb028dd2403d1d631c561ff1a3587c94d5f293e54beb2d77f4131e3f73f97a1a56feb4994ff67cd4d7a990399a2c1c256b155e42c72dc399a27f0eb4ac0c5ecc701c670d88b527fb0a42039dfdb39f9551b1160b76df400f1efdb0edd081c16cfb05cfbefd4cac48e0d406361aea84bfc3c111832ef442f05aa8d229d5bd5e3c0a6a86205ab1d8c8fb4c48683b15a291cef96cc145aee98d9d0310b38e9463702aa855227b8b9ecbfce0fff9689e492e351aeb98fbb66a24f36c34c18d0441de4d0802a935381570586bb4e2098331585da04f70309aa089ced4120b03aaf708e17d6b9b673cad12a5156fd6929a81973d29007f5c280c130d4d7542ff0d47e24d2fd77689af9c30a337de229afce9646bf6b8d54059eb6499e8ed41339d080051fa030213b12ce5340f57f73a609dc0cdef50548cbbb8f890d7a0cc2c07cd75ea31157cb02b822451faea97ee8d2906f5348c942d63c35f56296d1abc606e63d142a71d3f3905042b05f53de85f8deeb5fb2bc1c8a5cc4cfb42c4f60809e8170b1f1e5aeaa4215407a55e474b6a17b23791ae129ac8a96a71a8f77b0f962a8b8452f62ff1a0954e3e39e1fe3618719d3cf68d9c1fd319befd8b84cf5a6fce089bc4d2210a4aec005aeba4859fd6e91fc6459faca907d7680b529f6fc77e155ed54cfce24b2b44e5609aa18d4e855e69bf1a3a82fd6f16576724611abf47c8e963b7ffaeb5974123cfe6532905daeab84cb3d2316955adc8946d2795ad8e8224477a063ed6534b158bdc3c748a0641a09d8e1fb23725e529d31f051256bebe03ed30b61010e2a23145ec8a2ba51ff9b8794bb4d709f5e5b5e2455144f22661c9edcfe9a5f985b45cbf05d01a4d2e1efbf08c7590a0c3f32794561bb712fa1d3a9e30fef45b67297f491e302bc84ac9d316b70c4535e4bde3a97620d0717c2990ed6377b5b8ab1a8637fbaefd4b5c51e78d44bb0b0db771a58b3cf0eb3f77aaa654b32d77bf4d8011349d5d4d08023a0891d7bf30ab850344c4556eb27e0e45d48b7114215aaa7a687a84a1ff0d7b2f4f549956ccdbc45cdd2431787389a24b0ddac1a4b89d24327987d0e5e9a4002445328d118911f9602b3ad55c6d2049ef47dc0a87cc89b8444ef4e8ed8c87da8116c6e2a5747f88ad6f067f7c77f89188d27de97d24200db070c9c69356de4c1321c5efb47dc273cd0ca5566a8b3b2ccd1ee61777b8961f2bae2a92187d673438633f797363168336ed6e544b5e48cd32b348e0b597bed092d622af43dc7085448436c83717f5a342d51a4fc12f22c16b436003a9b609079609eefb2472259944241c4d58bf4d93c377dcf397f51a332f1e96412539fceb7938514f41c2fdeb911809f16ae7c6f8b8cf69d7817b14fe2810baca15fede2d02e62500d3e89dd40670aeea921836516072c27dd39822c2af82c020f3ce11709fb9306e2b876f0a41299433b779ae8092881076d478f64b7f640df71559b79453d6d097028ad01ab11fe5b48287b8924fd60f431af146bc802d1f5b59597341624ae6ee8631172a76e708ca0dd349c4ae89b6fef4ea22d42243ecdbfb4c5d637812a40f71236d01b7b1e23d6e884062a4bd1b23cfd329dbf05af41ea36d8c1a2f4da630d1970632e0c8ceaace9e88c37003411271753c226d3cc5f2afe23d748fa0d01ad26c518f2efc08cc19de8cc22537402cffff72237712635601cd24975adeab7cf1c18f12bb92c691888daa254d2601aaaa93d778ed99ffe5958b3ba522318865869177c65cec0ca2aa903986c4e2d3d6c9f162e5c6a618d466bb7cb16f18b8b3a3f2afcc9d5093f94ff9ceb1a025701109c19284aefed296e840812af8bb0f425ac47aafded57b2f52ed003766aeb64fa94933b38dc9dfdd5d98ea23071308736e05298300aac7b9ec1ac7fb0cbc1b671a1ea6e883c9ded73fdce85d01de82b04a489a55b01753e62542fec1de2f7d1cf3e850b6861c9c1afa101ce02e7fc51b7bcb55444721702f90f8d6c04074fce4e907c69c7122220e2e6f1d4f018ac29c2b442614f5c60b5db92178b9563843ad19f85ed260d70f28c3bb84eb1805e442bc8bcbfcdfe6da721f6a5bfdd6470860413ace3a3b3c67aa80e8a66208d4f2caea8ab51a5e5e4d8d6f0fabaaf4d8d79b6f1135c72268080d100100000000007721c1f00eae06e9c6567d253d1d1b37847ba666b5c1660438cfcd3f020bd76ba2e1c600000000";

        let tx: Transaction =
            bitcoin::consensus::deserialize(&hex::decode(hex_tx).unwrap()).unwrap();

        let result = parse_relevant_transaction(&tx);
        let parsed = result.unwrap();
        let ParsedTransaction::Complete(complete) = parsed else {
            panic!("Tx is not of a Complete kind");
        };
        let body = decompress_blob(&complete.body).unwrap();
        let _ = DataOnDa::borsh_parse_complete(&body).unwrap();
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
