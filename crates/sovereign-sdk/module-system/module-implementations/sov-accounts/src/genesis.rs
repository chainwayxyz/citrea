use core::result::Result;

use borsh::BorshDeserialize;
use hex::FromHex;
use serde::{Deserialize, Deserializer};
use sov_modules_api::default_signature::K256PublicKey;
use sov_modules_api::{Address, L2BlockHookError, PublicKey, StateMapAccessor, WorkingSet};

use crate::{Account, Accounts};

/// Initial configuration for sov-accounts module.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AccountConfig {
    /// Public keys to initialize the rollup.
    #[serde(deserialize_with = "deserialize_hex_vec")]
    pub pub_keys: Vec<Vec<u8>>,
}

/// Custom deserializer for converting Vec<String> of hex into Vec<Vec<u8>>
fn deserialize_hex_vec<'de, D>(deserializer: D) -> Result<Vec<Vec<u8>>, D::Error>
where
    D: Deserializer<'de>,
{
    let hex_strings: Vec<String> = Deserialize::deserialize(deserializer)?;
    hex_strings
        .into_iter()
        .map(|s| Vec::from_hex(&s).map_err(serde::de::Error::custom))
        .collect()
}

impl<C: sov_modules_api::Context> Accounts<C> {
    pub(crate) fn init_module(
        &self,
        config: &<Self as sov_modules_api::Module>::Config,
        working_set: &mut WorkingSet<C::Storage>,
    ) {
        for pub_key in config.pub_keys.iter() {
            // Called only in genesis so spec id should be Genesis
            self.create_default_account(pub_key, working_set)
                .expect("Accounts should create account in init_module");
        }
    }

    pub(crate) fn create_default_account(
        &self,
        pub_key: &[u8],
        working_set: &mut WorkingSet<C::Storage>,
    ) -> Result<Account, L2BlockHookError> {
        let default_address: Address = {
            let pub_key: K256PublicKey = K256PublicKey::try_from_slice(pub_key)
                // TODO: Update error handling
                .map_err(|_| L2BlockHookError::SovTxAccountNotFound)?;
            pub_key.to_address()
        };

        self.exit_if_address_exists(&default_address, working_set)?;

        let new_account = Account {
            addr: default_address,
            nonce: 0,
        };

        self.accounts.set(pub_key, &new_account, working_set);

        self.public_keys
            .set(&default_address, &pub_key.to_vec(), working_set);

        Ok(new_account)
    }

    fn exit_if_address_exists(
        &self,
        address: &Address,
        working_set: &mut WorkingSet<C::Storage>,
    ) -> Result<(), L2BlockHookError> {
        if self.public_keys.get(address, working_set).is_some() {
            return Err(L2BlockHookError::SovTxAccountAlreadyExists);
        }

        Ok(())
    }
}

#[cfg(all(test, feature = "native"))]
mod tests {
    use sov_modules_api::default_signature::DefaultPublicKey;
    use sov_modules_api::PublicKeyHex;

    use super::*;

    #[test]
    fn test_config_serialization() {
        let pub_key_hex = PublicKeyHex::try_from(
            "1cd4e2d9d5943e6f3d12589d31feee6bb6c11e7b8cd996a393623e207da72cbf",
        )
        .unwrap();

        let _ = DefaultPublicKey::try_from(&pub_key_hex).unwrap();

        let config = AccountConfig {
            pub_keys: vec![hex::decode(
                "1cd4e2d9d5943e6f3d12589d31feee6bb6c11e7b8cd996a393623e207da72cbf",
            )
            .unwrap()],
        };

        let data = r#"
        {
            "pub_keys":["1cd4e2d9d5943e6f3d12589d31feee6bb6c11e7b8cd996a393623e207da72cbf"]
        }"#;

        let parsed_config: AccountConfig = serde_json::from_str(data).unwrap();
        assert_eq!(parsed_config, config);
    }
}
