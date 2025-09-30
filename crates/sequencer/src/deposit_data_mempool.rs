use std::collections::{HashSet, VecDeque};

use alloy_primitives::TxKind;
use alloy_rpc_types_eth::transaction::{TransactionInput, TransactionRequest};
use alloy_sol_types::SolCall;
use citrea_evm::system_contracts::{BridgeContract, BridgeWrapper};
use citrea_evm::SYSTEM_SIGNER;
use rs_merkle::algorithms::Sha256;
use rs_merkle::Hasher;
use tracing::{debug, instrument};

use crate::metrics::SEQUENCER_METRICS as SM;

/// Type alias for deposit transaction data
pub type Deposit = Vec<u8>;

/// A mempool specifically for handling deposit transaction data
#[derive(Clone, Debug, Default)]
pub struct DepositDataMempool {
    /// Queue of accepted deposit transaction data
    accepted_deposit_txs: VecDeque<Deposit>,
    /// Set of pending deposit TxIds to prevent duplicates
    pending_deposits: HashSet<Vec<u8>>,
}

impl DepositDataMempool {
    /// Creates a new empty deposit data mempool
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a transaction request for a deposit from raw deposit data
    ///
    /// # Arguments
    /// * `deposit_tx_data` - Raw deposit transaction data to be processed
    ///
    /// # Returns
    /// A transaction request configured for the bridge contract
    pub fn make_deposit_tx_from_data(&mut self, deposit_tx_data: Deposit) -> TransactionRequest {
        TransactionRequest {
            from: Some(SYSTEM_SIGNER),
            to: Some(TxKind::Call(BridgeWrapper::address())),
            input: TransactionInput::new(BridgeWrapper::deposit(deposit_tx_data)),
            ..Default::default()
        }
    }

    /// Retrieves a limited number of deposit transactions from the mempool without removing them
    ///
    /// # Arguments
    /// * `limit_per_block` - Maximum number of deposits to return
    ///
    /// # Returns
    /// A vector of deposit transaction data, limited by the specified amount
    pub fn fetch_deposits(&mut self, limit_per_block: usize) -> Vec<Deposit> {
        let number_of_deposits = self.accepted_deposit_txs.len().min(limit_per_block);
        SM.deposit_data_mempool_txs
            .set(self.accepted_deposit_txs.len() as f64);
        let deposits: Vec<Deposit> = self
            .accepted_deposit_txs
            .iter()
            .take(number_of_deposits)
            .cloned()
            .collect();

        deposits
    }

    /// Removes specific deposits from the mempool after they have been successfully included in a block
    ///
    /// # Arguments
    /// * `deposits_to_remove` - The deposits that were successfully included
    ///
    /// # Returns
    /// The number of deposits actually removed
    #[instrument(level = "trace", skip_all, ret)]
    pub fn remove_deposits(&mut self, deposits_to_remove: &[Deposit]) -> usize {
        let mut removed_count = 0;

        // Calculate txids for the deposits to remove
        let mut txids_to_remove = HashSet::new();
        for deposit in deposits_to_remove {
            let txid = Self::calc_tx_id(deposit)
                .expect("calc_tx_id should never be called on non-deposit");
            txids_to_remove.insert(txid.to_vec());
        }

        // Retain only deposits that are not in the removal set
        self.accepted_deposit_txs.retain(|deposit| {
            let txid = Self::calc_tx_id(deposit)
                .expect("calc_tx_id should never be called on non-deposit");
            if txids_to_remove.contains(txid.as_slice()) {
                // Remove from pending set
                self.pending_deposits.remove(txid.as_slice());
                removed_count += 1;
                return false;
            }
            true
        });

        // Update metrics
        SM.deposit_data_mempool_txs
            .set(self.accepted_deposit_txs.len() as f64);

        debug!("Removed {} deposits from mempool", removed_count);
        removed_count
    }

    /// Adds a new deposit transaction to the mempool
    ///
    /// # Arguments
    /// * `req` - Raw deposit transaction data to be added
    ///
    /// # Returns
    /// `true` if the deposit was added, `false` if it was already pending
    #[instrument(level = "trace", skip_all, ret)]
    pub fn add_deposit_tx(&mut self, req: Deposit) -> anyhow::Result<bool> {
        let txid = Self::calc_tx_id(&req)?;

        debug!("Adding deposit with tx: {}", hex::encode(txid));

        // Check if deposit is already pending
        if !self.pending_deposits.insert(txid.to_vec()) {
            tracing::debug!("Deposit already pending in mempool");
            return Ok(false);
        }

        self.accepted_deposit_txs.push_back(req);
        SM.deposit_data_mempool_txs_inc.increment(1);
        SM.deposit_data_mempool_txs
            .set(self.accepted_deposit_txs.len() as f64);

        Ok(true)
    }

    /// Calculate the transaction ID from deposit data.
    ///
    /// # Arguments
    /// * `req`  - Raw deposit transaction data
    ///
    /// # Returns
    /// `Ok(transaction_id)` if the deposit data are valid
    /// `Err` if deposit data are invalid.
    fn calc_tx_id(req: &Deposit) -> anyhow::Result<[u8; 32]> {
        let call = BridgeContract::depositCall::abi_decode_raw(req, true)
            .map_err(|e| anyhow::anyhow!("Could not decode DepositCall ABI: {:?}", e))?;

        let tx = call.moveTx;

        let mut data = Vec::new();

        data.extend_from_slice(&tx.version.0);
        data.extend_from_slice(&tx.vin.0);
        data.extend_from_slice(&tx.vout.0);
        data.extend_from_slice(&tx.locktime.0);

        let hasher = Sha256::hash(&data);

        let second = Sha256::hash(&hasher);

        Ok(second)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEPOSIT1: &str = "000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000002e0b6f8e2dcc206207bf3d7833cd5c07b1ec48e98c5bc562414b28478e105d5f3380300000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c0000000000000000000000000000000000000000000000000000000000000012000000000000000000000000000000000000000000000000000000000000001800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002a01d6f8ca5989d1f597ddef9bd640d0490816bfc1e84496382db7020babd91199090000000000fdffffff0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000390210c99a3b00000000225120bafa392359558fab8049bfa4fa7d4e61a704f40a18f31f96c48aadb5e9a1e2d4f0000000000000000451024e730000000000000000000000000000000000000000000000000000000000000000000000000000cf03406aaa72b55a79a6b050e84a347b80d2e333814c757373b3dd708dc0ccf8e1a85ae4e2269c2fd44da04ac3725f73ecedef9cdd932481168433eb7f02b6e404a1cb4a2024280baf12b3532692fe42f41852b3122a509731c8f5462f88bc22391d7d7376ac00630663697472656114564cb100d2d5deceb792fe913b9185fcfb80871208000000003b9aca006841c193c7378d96518a75448821c4f7c8f4bae7ce60f804d03d1f0628dd5dd0f5de512c9e3733d03b3d7c3fa8c08b3674ea53ee85a4ce80d222f33c0f078ab7d6e648000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000017a6e000000000000000000000000000000000000000000000000000000000000052f000000000000000000000000000000000000000000000000000000000000016060f6d3ffa4ac4f4240304dc327b062c547804f76ef1fb7fa6ebb4d432f65e6f11d59e3a963d11dfe390542a94f3a1beb03e1915d470c63652fd4791d6485d23887239c0a19ae656b1d9003d7df064379ff025eac5ab8492f2273030b072df9552edd8eea0bc1b990e0ece8df58ac932e1290f4438b2ccae7dc0a9d900fa188a9b00a26baca1ad1f8e5f58c8c92767c27ed2a61fd9d6bf8679414d2dcae1f51cd7d608c169246a33403e2a0a1ab49d88b3130c70eea3284839cd0f8fd8220b0983bfd7c003b54e53e4255d6525d2018725a5387a68ab9721b952dc048c199bd0aba895554af5edb49897bd2a886093ca5f5c96f1d479a0859b986f11bb6fd309847776897b78316e1eee5ae8f0a633a27eb79ff1377638b06e0b4288fd0770edf16fa3b4358854a0c1fc957a8eff91511bbb8a4086533ea816d5c3bfaba505041ddd79acc6d2d7b709d2f3d5ebfca4be4cc1a68f9026b81a1d6804332e0948ea2";
    const DEPOSIT2: &str = "000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000002e0b6f8e2dcc206207bf3d7833cd5c07b1ec48e98c5bc562414b28478e105d5f3380300000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c0000000000000000000000000000000000000000000000000000000000000012000000000000000000000000000000000000000000000000000000000000001800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002a01b96565ba43c235e59e3d7b37eaf76b2350109e5c5b6b31ada790dac6df8b9e270000000000fdffffff0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000390210c99a3b00000000225120bafa392359558fab8049bfa4fa7d4e61a704f40a18f31f96c48aadb5e9a1e2d4f0000000000000000451024e730000000000000000000000000000000000000000000000000000000000000000000000000000cf0340c8d04b8a64990dfc0c5d077ae29d2ff3e37b7aa978e3ab4d5ede051eabc901e6544ce4484b1626c22b288de73bf0fea9da7582a1ceea0a325652fdf6255a02484a2024280baf12b3532692fe42f41852b3122a509731c8f5462f88bc22391d7d7376ac00630663697472656114564cb100d2d5deceb792fe913b9185fcfb80871208000000003b9aca006841c193c7378d96518a75448821c4f7c8f4bae7ce60f804d03d1f0628dd5dd0f5de512c9e3733d03b3d7c3fa8c08b3674ea53ee85a4ce80d222f33c0f078ab7d6e648000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000017a6e00000000000000000000000000000000000000000000000000000000000004e70000000000000000000000000000000000000000000000000000000000000160020d88c92331bf49f2c713a645a7909dd5d3e4683bb97ba968d9f672602bbcb38c1da1caf7d016e8ac2649c5cec1be67ff701ffcffc36fc2fbfaa80348851ddd96cb9c9953b727f8d71823517c77ea1d2070547ccb1bf62317ff6673e0ffa09ed5d65308a83a115b5504f413d8f0f82b917a389214c994e89ad132a3cd200298f5fd2e945c89727d138add5c9c76f5662ee2fd4af4eaf6bb236a164922c4fb4a80a9a5584d3ae04a0c2fb644d6fb6352d9a59a75f405a0871328b19f8be39ec3b4f2e3565ae55a89b89a23bb6d8c8b130ffb7758197284d34fb9883d348f19126809afd60f59b33b08d2a3c098f02770f90a09b0aa8a7cb372b38d0072659ae61a7cb404cffad2f9b257ca1462bef75d8acb83e17c7fe12cc28511d991405ff216fa3b4358854a0c1fc957a8eff91511bbb8a4086533ea816d5c3bfaba505041ddd79acc6d2d7b709d2f3d5ebfca4be4cc1a68f9026b81a1d6804332e0948ea2";
    const DEPOSIT3: &str = "000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000002e0b6f8e2dcc206207bf3d7833cd5c07b1ec48e98c5bc562414b28478e105d5f3380300000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c0000000000000000000000000000000000000000000000000000000000000012000000000000000000000000000000000000000000000000000000000000001800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002a01c6a209a85d039182be85b85d69dae4796e3cd4068d8c21c9d9f7345a160b639c0100000000fdffffff0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000390210c99a3b00000000225120bafa392359558fab8049bfa4fa7d4e61a704f40a18f31f96c48aadb5e9a1e2d4f0000000000000000451024e730000000000000000000000000000000000000000000000000000000000000000000000000000cf0340fb13cfa2c34ff3437ad20838abd06e5e9e04580d3813097b376c0d9ee9d758c1449cb15883a61b3ee919b9e6c17deaa6be4cbd69d58433e014c6063e85edd97c4a2024280baf12b3532692fe42f41852b3122a509731c8f5462f88bc22391d7d7376ac00630663697472656114564cb100d2d5deceb792fe913b9185fcfb80871208000000003b9aca006841c193c7378d96518a75448821c4f7c8f4bae7ce60f804d03d1f0628dd5dd0f5de512c9e3733d03b3d7c3fa8c08b3674ea53ee85a4ce80d222f33c0f078ab7d6e648000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000017a6e000000000000000000000000000000000000000000000000000000000000047600000000000000000000000000000000000000000000000000000000000001602166a00ac5d0b00f69ddd836580439b478b03f0e64e47218467ee3a43ac72ef4fbd658cdd9a8c6251aef4791811151737337eeeffcd228364ab9a1e43bc3ed1bbd1b93524a6653fc0a87419a687cfcb7c5b65e1321266b87c8cc26cdcc65654cc6adeb3077a38c9ef8e11cff8627072c92b948302c91198b3a8e0c87fc406c18f6ac23091cc6e89fa9aa98ed92c4eb81dd5839918f074a666457d497bfd4f953f05832db2a718042d29edcf2275bfa963ae9a35e0e80765a9269488aa8308fd639fab1d475d548e42951d3245f06bab9841c71029c8cd04492d9438a8c88c364ccf02b418f92ca015327e96123bfe0d362c3c811018351a388cd922c95974a671a7cb404cffad2f9b257ca1462bef75d8acb83e17c7fe12cc28511d991405ff216fa3b4358854a0c1fc957a8eff91511bbb8a4086533ea816d5c3bfaba505041ddd79acc6d2d7b709d2f3d5ebfca4be4cc1a68f9026b81a1d6804332e0948ea2";

    #[test]
    fn test_add_deposit_tx_prevents_duplicates() {
        let mut mempool = DepositDataMempool::new();
        let deposit1 = hex::decode(DEPOSIT1).unwrap();
        let deposit2 = hex::decode(DEPOSIT2).unwrap();

        // First addition should succeed
        assert!(mempool.add_deposit_tx(deposit1.clone()).unwrap());
        assert_eq!(mempool.accepted_deposit_txs.len(), 1);
        assert_eq!(mempool.pending_deposits.len(), 1);

        // Second addition of the same deposit should fail
        assert!(!mempool.add_deposit_tx(deposit1.clone()).unwrap());
        assert_eq!(mempool.accepted_deposit_txs.len(), 1);
        assert_eq!(mempool.pending_deposits.len(), 1);

        // Adding a different deposit should succeed
        assert!(mempool.add_deposit_tx(deposit2).unwrap());
        assert_eq!(mempool.accepted_deposit_txs.len(), 2);
        assert_eq!(mempool.pending_deposits.len(), 2);
    }

    #[test]
    fn test_fetch_deposits_does_not_remove() {
        let mut mempool = DepositDataMempool::new();
        let deposit1 = hex::decode(DEPOSIT1).unwrap();
        let deposit2 = hex::decode(DEPOSIT2).unwrap();
        let deposit3 = hex::decode(DEPOSIT3).unwrap();

        // Add deposits
        assert!(mempool.add_deposit_tx(deposit1.clone()).unwrap());
        assert!(mempool.add_deposit_tx(deposit2.clone()).unwrap());
        assert!(mempool.add_deposit_tx(deposit3.clone()).unwrap());
        assert_eq!(mempool.pending_deposits.len(), 3);
        assert_eq!(mempool.accepted_deposit_txs.len(), 3);

        // Fetch 2 deposits
        let fetched = mempool.fetch_deposits(2);
        assert_eq!(fetched.len(), 2);
        assert_eq!(fetched[0], deposit1);
        assert_eq!(fetched[1], deposit2);

        // Check that fetched deposits are NOT removed
        assert_eq!(mempool.pending_deposits.len(), 3);
        assert_eq!(mempool.accepted_deposit_txs.len(), 3);

        // Cannot add same deposits again as they're still pending
        assert!(!mempool.add_deposit_tx(deposit1.clone()).unwrap());
        assert!(!mempool.add_deposit_tx(deposit2.clone()).unwrap());

        // Fetch again should return the same deposits
        let fetched_again = mempool.fetch_deposits(2);
        assert_eq!(fetched_again.len(), 2);
        assert_eq!(fetched_again[0], deposit1);
        assert_eq!(fetched_again[1], deposit2);
    }

    #[test]
    fn test_remove_deposits() {
        let mut mempool = DepositDataMempool::new();
        let deposit1 = hex::decode(DEPOSIT1).unwrap();
        let deposit2 = hex::decode(DEPOSIT2).unwrap();
        let deposit3 = hex::decode(DEPOSIT3).unwrap();

        // Add deposits
        assert!(mempool.add_deposit_tx(deposit1.clone()).unwrap());
        assert!(mempool.add_deposit_tx(deposit2.clone()).unwrap());
        assert!(mempool.add_deposit_tx(deposit3.clone()).unwrap());
        assert_eq!(mempool.pending_deposits.len(), 3);
        assert_eq!(mempool.accepted_deposit_txs.len(), 3);

        // Fetch 2 deposits
        let fetched = mempool.fetch_deposits(2);
        assert_eq!(fetched.len(), 2);

        // Remove the fetched deposits
        let removed_count = mempool.remove_deposits(&fetched);
        assert_eq!(removed_count, 2);

        // Check that only the removed deposits are gone
        assert_eq!(mempool.pending_deposits.len(), 1);
        assert_eq!(mempool.accepted_deposit_txs.len(), 1);

        // Now these deposits can be added again
        assert!(mempool.add_deposit_tx(deposit1.clone()).unwrap());
        assert!(mempool.add_deposit_tx(deposit2.clone()).unwrap());
        assert_eq!(mempool.pending_deposits.len(), 3);
        assert_eq!(mempool.accepted_deposit_txs.len(), 3);
    }

    #[test]
    fn test_deposit_lifecycle() {
        let mut mempool = DepositDataMempool::new();
        let deposit = hex::decode(DEPOSIT1).unwrap();

        // Add deposit
        assert!(mempool.add_deposit_tx(deposit.clone()).unwrap());

        // Cannot add duplicate
        assert!(!mempool.add_deposit_tx(deposit.clone()).unwrap());

        // Fetch the deposit
        let fetched = mempool.fetch_deposits(10);
        assert_eq!(fetched.len(), 1);
        assert_eq!(fetched[0], deposit);

        // Deposit is still in mempool after fetch
        assert_eq!(mempool.pending_deposits.len(), 1);
        assert_eq!(mempool.accepted_deposit_txs.len(), 1);

        // Still cannot add duplicate
        assert!(!mempool.add_deposit_tx(deposit.clone()).unwrap());

        // Remove the deposit
        let removed_count = mempool.remove_deposits(&fetched);
        assert_eq!(removed_count, 1);

        // Now the same deposit can be added again
        assert!(mempool.add_deposit_tx(deposit.clone()).unwrap());
        assert_eq!(mempool.pending_deposits.len(), 1);
        assert_eq!(mempool.accepted_deposit_txs.len(), 1);
    }

    #[test]
    fn test_calc_tx_id() {
        let data = hex::decode(DEPOSIT1).unwrap();

        assert_eq!(
            DepositDataMempool::calc_tx_id(&data).unwrap(),
            hex::decode("c1be1ce3ef6be11115274355dade79aad5b34814fccc3912c3cec2c08686fbee")
                .unwrap()
                .as_slice()
        );

        let data = hex::decode(DEPOSIT2).unwrap();

        assert_eq!(
            DepositDataMempool::calc_tx_id(&data).unwrap(),
            hex::decode("0d7e74f9cf18ae5bfce3855270b909a5142809a302a72093231345989aac9809")
                .unwrap()
                .as_slice()
        )
    }
}
