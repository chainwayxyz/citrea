use std::env;

use async_trait::async_trait;
use borsh::ser::BorshSerialize;
use demo_stf::runtime::Runtime;
use sov_bank::{Bank, Coins};
use sov_mock_da::{
    MockAddress, MockBlob, MockBlock, MockBlockHeader, MockHash, MockValidityCond,
    MOCK_SEQUENCER_DA_ADDRESS,
};
use sov_modules_api::default_context::DefaultContext;
use sov_modules_api::default_signature::private_key::DefaultPrivateKey;
use sov_modules_api::transaction::Transaction;
use sov_modules_api::{Address, AddressBech32, EncodeCall, PrivateKey, PublicKey, Spec};
use sov_rollup_interface::da::{BlockHeaderTrait, DaSpec, DaVerifier};
use sov_rollup_interface::services::da::{DaService, SlotData};

pub fn sender_address_with_pkey() -> (Address, DefaultPrivateKey) {
    // TODO: maybe generate address and private key randomly, instead of
    // hard coding them?
    let addr_bytes = "sov15vspj48hpttzyvxu8kzq5klhvaczcpyxn6z6k0hwpwtzs4a6wkvqmlyjd6".to_string();
    let addr = Address::from(
        AddressBech32::try_from(addr_bytes)
            .unwrap_or_else(|e| panic!("Failed generating sender address: {:?}", e)),
    );

    let pk = DefaultPrivateKey::from_hex("236e80cb222c4ed0431b093b3ac53e6aa7a2273fe1f4351cd354989a823432a27b758bf2e7670fafaf6bf0015ce0ff5aa802306fc7e3f45762853ffc37180fe6").unwrap();

    (addr, pk)
}

#[derive(Clone, Default)]
/// A simple [`DaService`] for a random number generator.
pub struct RngDaService;

impl RngDaService {
    /// Instantiates a new [`RngDaService`].
    pub fn new() -> Self {
        RngDaService
    }
}

/// A simple DaSpec for a random number generator.
#[derive(serde::Serialize, serde::Deserialize, PartialEq, Eq, Debug, Clone, Default)]
pub struct RngDaSpec;

impl DaSpec for RngDaSpec {
    type SlotHash = MockHash;
    type BlockHeader = MockBlockHeader;
    type BlobTransaction = MockBlob;
    type Address = MockAddress;
    type ValidityCondition = MockValidityCond;
    type InclusionMultiProof = [u8; 32];
    type CompletenessProof = ();
    type ChainParams = ();
}

#[async_trait]
impl DaService for RngDaService {
    type Spec = RngDaSpec;
    type Verifier = RngDaVerifier;
    type FilteredBlock = MockBlock;
    type Error = anyhow::Error;

    async fn get_finalized_at(&self, height: u64) -> Result<Self::FilteredBlock, Self::Error> {
        let num_bytes = height.to_le_bytes();
        let mut barray = [0u8; 32];
        barray[..num_bytes.len()].copy_from_slice(&num_bytes);

        let block = MockBlock {
            header: MockBlockHeader {
                hash: barray.into(),
                prev_hash: [0u8; 32].into(),
                height,
            },
            validity_cond: MockValidityCond { is_valid: true },
            blobs: Default::default(),
        };

        Ok(block)
    }

    async fn get_block_at(&self, _height: u64) -> Result<Self::FilteredBlock, Self::Error> {
        unimplemented!()
    }

    fn extract_relevant_blobs(
        &self,
        block: &Self::FilteredBlock,
    ) -> Vec<<Self::Spec as DaSpec>::BlobTransaction> {
        let mut num_txns = 10000;
        if let Ok(val) = env::var("TXNS_PER_BLOCK") {
            num_txns = val
                .parse()
                .expect("TXNS_PER_BLOCK var should be a +ve number");
        }

        let data = if block.header().height() == 0 {
            // creating the token
            generate_create(0)
        } else {
            // generating the transfer transactions
            generate_transfers(num_txns, (block.header.height() - 1) * (num_txns as u64))
        };

        let address = MockAddress::from(MOCK_SEQUENCER_DA_ADDRESS);
        let blob = MockBlob::new(data, address, [0u8; 32]);

        vec![blob]
    }

    async fn get_extraction_proof(
        &self,
        _block: &Self::FilteredBlock,
        _blobs: &[<Self::Spec as DaSpec>::BlobTransaction],
    ) -> (
        <Self::Spec as DaSpec>::InclusionMultiProof,
        <Self::Spec as DaSpec>::CompletenessProof,
    ) {
        unimplemented!()
    }

    async fn send_transaction(&self, _blob: &[u8]) -> Result<(), Self::Error> {
        unimplemented!()
    }

    fn convert_to_transaction(
        &self,
        blob: &[u8],
        hash: [u8; 32],
    ) -> Result<
        (
            <Self::Spec as sov_rollup_interface::da::DaSpec>::BlobTransaction,
            Vec<u8>,
        ),
        Self::Error,
    > {
        unimplemented!()
    }

    fn hash_blob(&self, blob: &[u8]) -> Result<[u8; 32], anyhow::Error> {
        unimplemented!()
    }
}

pub struct RngDaVerifier;
impl DaVerifier for RngDaVerifier {
    type Spec = RngDaSpec;

    type Error = anyhow::Error;

    fn new(_params: <Self::Spec as DaSpec>::ChainParams) -> Self {
        Self
    }

    fn verify_relevant_tx_list(
        &self,
        _block_header: &<Self::Spec as DaSpec>::BlockHeader,
        _txs: &[<Self::Spec as DaSpec>::BlobTransaction],
        _inclusion_proof: <Self::Spec as DaSpec>::InclusionMultiProof,
        _completeness_proof: <Self::Spec as DaSpec>::CompletenessProof,
    ) -> Result<<Self::Spec as DaSpec>::ValidityCondition, Self::Error> {
        Ok(MockValidityCond { is_valid: true })
    }
}

pub fn generate_transfers(n: usize, start_nonce: u64) -> Vec<u8> {
    let token_name = "sov-test-token";
    let (sa, pk) = sender_address_with_pkey();
    let token_address = sov_bank::get_token_address::<DefaultContext>(token_name, sa.as_ref(), 11);
    let mut message_vec = vec![];
    for i in 1..(n + 1) {
        let priv_key = DefaultPrivateKey::generate();
        let address: <DefaultContext as Spec>::Address = priv_key.pub_key().to_address();
        let msg: sov_bank::CallMessage<DefaultContext> =
            sov_bank::CallMessage::<DefaultContext>::Transfer {
                to: address,
                coins: Coins {
                    amount: 1,
                    token_address,
                },
            };
        let enc_msg =
            <Runtime<DefaultContext, RngDaSpec> as EncodeCall<Bank<DefaultContext>>>::encode_call(
                msg,
            );
        let tx =
            Transaction::<DefaultContext>::new_signed_tx(&pk, enc_msg, start_nonce + (i as u64));
        let ser_tx = tx.try_to_vec().unwrap();
        message_vec.push(ser_tx)
    }
    message_vec.try_to_vec().unwrap()
}

pub fn generate_create(start_nonce: u64) -> Vec<u8> {
    let mut message_vec = vec![];

    let (minter_address, pk) = sender_address_with_pkey();
    let msg: sov_bank::CallMessage<DefaultContext> =
        sov_bank::CallMessage::<DefaultContext>::CreateToken {
            salt: 11,
            token_name: "sov-test-token".to_string(),
            initial_balance: 100000000,
            minter_address,
            authorized_minters: vec![minter_address],
        };
    let enc_msg =
        <Runtime<DefaultContext, RngDaSpec> as EncodeCall<Bank<DefaultContext>>>::encode_call(msg);
    let tx = Transaction::<DefaultContext>::new_signed_tx(&pk, enc_msg, start_nonce);
    let ser_tx = tx.try_to_vec().unwrap();
    message_vec.push(ser_tx);
    message_vec.try_to_vec().unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sender_address_with_pkey_okay() {
        // Checks that it doesn't crash.
        sender_address_with_pkey();
    }
}
