//! This module defines the UTXO struct and its conversion from ListUnspentResultEntry.

use bitcoin::address::NetworkUnchecked;
use bitcoin::{Address, Txid};
#[cfg(feature = "native")]
use bitcoincore_rpc::json::ListUnspentResultEntry;

/// Represents a UTXO (Unspent Transaction Output) in the Bitcoin network.
/// We use this struct instead of ListUnspentResultEntry because
/// we don't use all the fields from ListUnspentResultEntry.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct UTXO {
    /// The transaction ID of the UTXO.
    pub tx_id: Txid,
    /// The output index.
    pub vout: u32,
    /// The address associated with the UTXO, if available.
    pub address: Option<Address<NetworkUnchecked>>,
    /// The script public key.
    pub script_pubkey: String,
    /// The amount in satoshis.
    pub amount: u64,
    /// The number of confirmations for the UTXO.
    pub confirmations: u32,
    /// Whether the UTXO is spendable.
    pub spendable: bool,
    /// Whether the UTXO is solvable.
    pub solvable: bool,
}

#[cfg(feature = "native")]
impl From<ListUnspentResultEntry> for UTXO {
    fn from(v: ListUnspentResultEntry) -> Self {
        Self {
            tx_id: v.txid,
            vout: v.vout,
            address: v.address,
            script_pubkey: v.script_pub_key.to_hex_string(),
            amount: v.amount.to_sat(),
            confirmations: v.confirmations,
            spendable: v.spendable,
            solvable: v.solvable,
        }
    }
}
