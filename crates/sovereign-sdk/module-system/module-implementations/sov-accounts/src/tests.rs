use sov_modules_api::default_context::DefaultContext;
use sov_modules_api::default_signature::private_key::DefaultPrivateKey;
use sov_modules_api::{AddressBech32, PrivateKey, PublicKey, Spec, WorkingSet};
use sov_prover_storage_manager::new_orphan_storage;

use crate::query::{self, Response};
use crate::{AccountConfig, Accounts};

type C = DefaultContext;

#[test]
fn test_config_account() {
    let priv_key = DefaultPrivateKey::generate();
    let init_pub_key = priv_key.pub_key();
    let init_pub_key_addr = init_pub_key.to_address::<<C as Spec>::Address>();

    let account_config = AccountConfig {
        pub_keys: vec![init_pub_key.clone()],
    };

    let accounts = &mut Accounts::<C>::default();
    let tmpdir = tempfile::tempdir().unwrap();
    let working_set = &mut WorkingSet::new(new_orphan_storage(tmpdir.path()).unwrap());

    accounts.init_module(&account_config, working_set);

    let query_response = accounts.get_account(init_pub_key, working_set).unwrap();

    assert_eq!(
        query_response,
        query::Response::AccountExists {
            addr: AddressBech32::from(&init_pub_key_addr),
            nonce: 0
        }
    )
}

#[test]
fn test_response_serialization() {
    let addr: Vec<u8> = (1..=32).collect();
    let nonce = 123456789;
    let response = Response::AccountExists {
        addr: AddressBech32::try_from(addr.as_slice()).unwrap(),
        nonce,
    };

    let json = serde_json::to_string(&response).unwrap();
    assert_eq!(
        json,
        r#"{"AccountExists":{"addr":"sov1qypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7rusqqsn6hm","nonce":123456789}}"#
    );
}

#[test]
fn test_response_deserialization() {
    let json = r#"{"AccountExists":{"addr":"sov1qypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7rusqqsn6hm","nonce":123456789}}"#;
    let response: Response = serde_json::from_str(json).unwrap();

    let expected_addr: Vec<u8> = (1..=32).collect();
    let expected_response = Response::AccountExists {
        addr: AddressBech32::try_from(expected_addr.as_slice()).unwrap(),
        nonce: 123456789,
    };

    assert_eq!(response, expected_response);
}

#[test]
fn test_response_deserialization_on_wrong_hrp() {
    let json = r#"{"AccountExists":{"addr":"hax1qypqx68ju0l","nonce":123456789}}"#;
    let response: Result<Response, serde_json::Error> = serde_json::from_str(json);
    match response {
        Ok(response) => panic!("Expected error, got {:?}", response),
        Err(err) => {
            assert_eq!(err.to_string(), "Wrong HRP: hax at line 1 column 42");
        }
    }
}
