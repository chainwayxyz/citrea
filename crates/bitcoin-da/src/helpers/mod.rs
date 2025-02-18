use core::num::NonZeroU16;

use bitcoin::consensus::Encodable;
use bitcoin::Transaction;
use sha2::{Digest, Sha256};

#[cfg(feature = "native")]
pub mod builders;
pub mod merkle_tree;
pub mod parsers;

/// Type represents a typed enum for LightClient kind
#[repr(u16)]
enum TransactionKindLightClient {
    /// This type of transaction includes full body (< 400kb)
    Complete = 0,
    /// This type of transaction includes txids of chunks (>= 400kb)
    Chunked = 1,
    /// This type of transaction includes chunk parts of body (>= 400kb)
    ChunkedPart = 2,
    /// This type of transaction includes a new batch proof method_id
    BatchProofMethodId = 3,
    Unknown(NonZeroU16),
}

impl TransactionKindLightClient {
    #[cfg(feature = "native")]
    fn to_bytes(&self) -> Vec<u8> {
        match self {
            TransactionKindLightClient::Complete => 0u16.to_le_bytes().to_vec(),
            TransactionKindLightClient::Chunked => 1u16.to_le_bytes().to_vec(),
            TransactionKindLightClient::ChunkedPart => 2u16.to_le_bytes().to_vec(),
            TransactionKindLightClient::BatchProofMethodId => 3u16.to_le_bytes().to_vec(),
            TransactionKindLightClient::Unknown(v) => v.get().to_le_bytes().to_vec(),
        }
    }
    fn from_bytes(bytes: &[u8]) -> Option<TransactionKindLightClient> {
        if bytes.len() != 2 {
            return None;
        }
        let mut kind_bytes = [0; 2];
        kind_bytes.copy_from_slice(bytes);
        match u16::from_le_bytes(kind_bytes) {
            0 => Some(TransactionKindLightClient::Complete),
            1 => Some(TransactionKindLightClient::Chunked),
            2 => Some(TransactionKindLightClient::ChunkedPart),
            3 => Some(TransactionKindLightClient::BatchProofMethodId),
            n => Some(TransactionKindLightClient::Unknown(
                NonZeroU16::new(n).expect("Is not zero"),
            )),
        }
    }
}

/// Type represents a typed enum for BatchProof kind
#[repr(u16)]
enum TransactionKindBatchProof {
    /// SequencerCommitment
    SequencerCommitment = 0,
    // /// ForcedTransaction
    // ForcedTransaction = 1,
    Unknown(NonZeroU16),
}

impl TransactionKindBatchProof {
    #[cfg(feature = "native")]
    fn to_bytes(&self) -> Vec<u8> {
        match self {
            TransactionKindBatchProof::SequencerCommitment => 0u16.to_le_bytes().to_vec(),
            // TransactionKindBatchProof::ForcedTransaction => 1u16.to_le_bytes(),
            TransactionKindBatchProof::Unknown(v) => v.get().to_le_bytes().to_vec(),
        }
    }
    fn from_bytes(bytes: &[u8]) -> Option<TransactionKindBatchProof> {
        if bytes.len() != 2 {
            return None;
        }
        let mut kind_bytes = [0; 2];
        kind_bytes.copy_from_slice(bytes);
        match u16::from_le_bytes(kind_bytes) {
            0 => Some(TransactionKindBatchProof::SequencerCommitment),
            // 1 => TransactionKindBatchProof::ForcedTransaction,
            n => Some(TransactionKindBatchProof::Unknown(
                NonZeroU16::new(n).expect("Is not zero"),
            )),
        }
    }
}

pub fn calculate_double_sha256(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::default();
    hasher.update(input);
    let result = hasher.finalize_reset();
    hasher.update(result);
    hasher.finalize().into()
}

/// Computes the [`Txid`].
///
/// Hashes the transaction **excluding** the segwit data (i.e. the marker, flag bytes, and the
/// witness fields themselves). For non-segwit transactions which do not have any segwit data,
/// this will be equal to [`Transaction::compute_wtxid()`].
pub fn calculate_txid(tx: &Transaction) -> [u8; 32] {
    // input and output types might have different sizes
    // however we are dealing with taproot transactions
    // input size and output size holds without witness data
    //
    // Even if the capacity does not hold, the vec will
    // resize itself to hold the data
    let mut enc = Vec::with_capacity(
        4 // version
        + 9 // max varint size for the number of inputs
        + tx.input.len() * 40 // tx inputs
        + 9 // max varint size for the number of outputs
        + tx.output.len() * 40, // tx outputs
    );

    tx.version
        .consensus_encode(&mut enc)
        .expect("engines don't error");
    tx.input
        .consensus_encode(&mut enc)
        .expect("engines don't error");
    tx.output
        .consensus_encode(&mut enc)
        .expect("engines don't error");
    tx.lock_time
        .consensus_encode(&mut enc)
        .expect("engines don't error");
    calculate_double_sha256(&enc)
}

/// Computes the segwit version of the transaction id.
///
/// Hashes the transaction **including** all segwit data (i.e. the marker, flag bytes, and the
/// witness fields themselves). For non-segwit transactions which do not have any segwit data,
/// this will be equal to [`Transaction::txid()`].
pub fn calculate_wtxid(tx: &Transaction) -> [u8; 32] {
    let mut enc = vec![];
    tx.consensus_encode(&mut enc).expect("engines don't error");
    calculate_double_sha256(&enc)
}

#[cfg(test)]
mod tests {
    use bitcoin::hashes::Hash;
    use bitcoin::Transaction;

    use crate::helpers::{calculate_txid, calculate_wtxid};

    #[test]
    fn calculate_txid_wtxid() {
        let hex_tx = "020000000001013a66019bfcc719ba12586a83ebbb0b3debdc945f563cd64fd44c8044e3d3a1790100000000fdffffff028fa2aa060000000017a9147ba15d4e0d8334de3a68cf3687594e2d1ee5b00d879179e0090000000016001493c93ad222e57d65438545e048822ede2d418a3d0247304402202432e6c422b93705fbc57b350ea43e4ef9441c0907988eff051eaac807fc8cf2022046c92b540b5f04f8da11febb5d2a478aed1b8bc088e769da8b78fffcae8c9a9a012103e2991b47d9c788f55379f9ef519b642d79d7dfe0e7555ec5575ee934b2dca1223f5d0c00";
        let taproot = "02000000000101a196aca845bc2974cf6fe319b261b507c6ccd50e1d4caea8d354a2f604bce56b0000000000ffffffff01d02410000000000022512041a287c2929429246f946b6ed5fb0e09b4603ce1ba37304f1465095bfa1507ef0c000040c941f8f22379e3ee06516746364294b5bd0e8817bfdd5ba453823faafe0650f72b89f0a90e8157a72c3172524598ad339e6bba52b01e47c3858f54008038e7c740dfe1c1a9871cf63498a30711abf7f4464ac355d87e109a5efff5194886655e30cf64b5aa0632cbef05dcc3c55733b755320003b983def2d8f4a9ec25f2df0d0f40868be49f22d7b7c461480658d32e922387153b74c52167cab3a764f7f7722d8f40e56cdf3b6e87dc64f4a7ec86d8c36bb71ec577b502472ddd53b0b15a3bcc9800407a9ef2501f18be9db4971806bc9711c2c6a729c8a516f95b5f5f26b52fc61f1dc57632112c09bd08f7be0c067ebd2f5881bbc089ffd0eb360e6d548dbd577e7440cae7c292336738cbf3523762359595b398af1805da66f0c429516cf89a48786de289789278431f52a0806c896ef87a3005db874be0aba90108e7b77ceb53977e40f499e7e1b99b980aa4352465c5bb3db2a13705ebe53512dd15a75c26ba802514327a09de7894b053829963ec1ff958029ddf7729be49a79bf8bf5cbb2afd172a40389a3b1f15c2d4a2c7c6b6d65e8ba56e8a5dbaed2f9750d7bbd0ad79920eb2d07cbdb92221b9952157294fa6e570a8a3144f88ca33b1bafb368d13d48df0c0e9fd5601203adc3c668fe1bd096bf0088e9b51469fb706292b4c4c77c9436275f17e9530abad2023b29f89b45f4af41588dcaf0ca572ada32872a88224f311373917f1b37d08d1ac204b15848e495a3a62283daaadb3f458a00859fe48e321f0121ebabbdd6698f9faba208242640732773249312c47ca7bdb50ca79f15f2ecc32b9c83ceebba44fb74df7ba20cbdd028cfe32c1c1f2d84bfec71e19f92df509bba7b8ad31ca6c1a134fe09204ba20d3c79b99ac4d265c2f97ac11e3232c07a598b020cf56c6f055472c893c0967aeba20d45c70d28f169e1f0c7f4a78e2bc73497afe585b70aa897955989068f3350aaaba20de13fc96ea6899acbdc5db3afaa683f62fe35b60ff6eb723dad28a11d2b12f8cba20e36200aaa8dce9453567bba108bdc51f7f1174b97a65e4dc4402fc5de779d41cba20f178fcce82f95c524b53b077e6180bd2d779a9057fdff4255a0af95af918cee0ba569c61c150929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac046e5d29daed70ecd9d769aba5109997be4ff474e853e28256d5eb64d1327f934419b9d368c90acef45745e70de113270bfbe970d7bf73624a468f878519e92e100000000";
        let segwit = "01000000000101805dc5cccfdbd08dfa4f86381bbd6355494884596fa48db3767df89d4a166a4a0100000000ffffffff022d450500000000002251201a2128fb15aed5eb41c8a1ee326308c9d1df9456c678bf6121da7727a91f8c340931ba000000000016001400b4a8c8806c2ea75094b3762b29d0d6c4356d6a02483045022100a1e377b19aaac488e0a2d91d1a5eaefa994a1d33176a9478bf30088e311a3955022057694eef88ca2ec10fabdcdb5ccab8aa7ebc3a286e627299fd198867bbf0bc020121022310eb6b8c4e4c3611bdee21704963654042c9d52d2d820beb86f22deff90e2300000000";
        let non_segwit = "0100000001032e38e9c0a84c6046d687d10556dcacc41d275ec55fc00779ac88fdf357a187000000008c493046022100c352d3dd993a981beba4a63ad15c209275ca9470abfcd57da93b58e4eb5dce82022100840792bc1f456062819f15d33ee7055cf7b5ee1af1ebcc6028d9cdb1c3af7748014104f46db5e9d61a9dc27b8d64ad23e7383a4e6ca164593c2527c038c0857eb67ee8e825dca65046b82c9331586c82e0fd1f633f25f87c161bc6f8a630121df2b3d3ffffffff0200e32321000000001976a914c398efa9c392ba6013c5e04ee729755ef7f58b3288ac000fe208010000001976a914948c765a6914d43f2a7ac177da2c2f6b52de3d7c88ac00000000";

        compare_txid_wtxid(hex_tx);
        compare_txid_wtxid(taproot);
        compare_txid_wtxid(segwit);
        compare_txid_wtxid(non_segwit);
    }

    fn compare_txid_wtxid(tx: &str) {
        let tx: Transaction = bitcoin::consensus::deserialize(&hex::decode(tx).unwrap()).unwrap();

        assert_eq!(tx.compute_txid().to_byte_array(), calculate_txid(&tx));
        assert_eq!(tx.compute_wtxid().to_byte_array(), calculate_wtxid(&tx));
    }
}
