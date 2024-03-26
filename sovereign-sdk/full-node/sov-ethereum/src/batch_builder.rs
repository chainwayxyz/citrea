use std::collections::VecDeque;

pub struct EthBatchBuilder<C: sov_modules_api::Context> {
    mempool: VecDeque<Vec<u8>>,
    #[allow(dead_code)]
    sov_tx_signer_private_key: C::PrivateKey,
    #[allow(dead_code)]
    nonce: u64,
    #[allow(dead_code)]
    min_blob_size: Option<usize>,
}

impl<C: sov_modules_api::Context> EthBatchBuilder<C> {
    /// Creates a new `EthBatchBuilder`.
    pub fn new(
        sov_tx_signer_private_key: C::PrivateKey,
        nonce: u64,
        min_blob_size: Option<usize>,
    ) -> Self {
        EthBatchBuilder {
            mempool: VecDeque::new(),
            sov_tx_signer_private_key,
            nonce,
            min_blob_size,
        }
    }

    /// Adds `messages` to the mempool.
    pub fn add_messages(&mut self, messages: Vec<Vec<u8>>) {
        self.mempool.extend(messages);
    }
}
