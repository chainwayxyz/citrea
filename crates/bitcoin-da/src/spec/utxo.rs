use bitcoin::Txid;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct UTXO {
    pub tx_id: Txid,
    pub vout: u32,
    pub address: String,
    pub script_pubkey: String,
    pub amount: u64,
    pub confirmations: u64,
    pub spendable: bool,
    pub solvable: bool,
}

// Temporary struct to deserialize UTXO from JSON
#[derive(Deserialize)]
struct RawUTXO {
    txid: String,
    vout: u32,
    address: String,
    #[serde(rename = "scriptPubKey")]
    script_pub_key: String,
    amount: f64,
    confirmations: u64,
    spendable: bool,
    solvable: bool,
}

// Deserialize UTXO from JSON
impl<'de> serde::Deserialize<'de> for UTXO {
    fn deserialize<D>(deserializer: D) -> Result<UTXO, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw_utxo = RawUTXO::deserialize(deserializer)?;
        Ok(UTXO {
            tx_id: raw_utxo.txid.parse().unwrap(),
            vout: raw_utxo.vout,
            address: raw_utxo.address,
            script_pubkey: raw_utxo.script_pub_key,
            amount: (raw_utxo.amount * 100_000_000.0) as u64, // satoshis to bitcoin
            confirmations: raw_utxo.confirmations,
            spendable: raw_utxo.spendable,
            solvable: raw_utxo.solvable,
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ListUnspentEntry {
    pub txid: String,
    pub vout: u64,
    pub address: String,
    pub label: Option<String>,
    #[serde(rename = "scriptPubKey")]
    pub script_pub_key: String,
    pub amount: f64,
    pub confirmations: u64,
    #[serde(rename = "ancestorcount")]
    pub ancestor_count: Option<u64>,
    #[serde(rename = "ancestorsize")]
    pub ancestor_size: Option<u64>,
    #[serde(rename = "ancestorfees")]
    pub ancestor_fees: Option<u64>,
    pub spendable: bool,
    pub solvable: bool,
    pub desc: String,
    pub parent_descs: Option<Vec<String>>,
    pub safe: bool,
}
