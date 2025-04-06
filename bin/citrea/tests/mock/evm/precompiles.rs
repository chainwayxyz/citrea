use alloy::network::TransactionBuilder;
use alloy_primitives::{Address, Bytes, B256, U256};
use alloy_rpc_types::{TransactionInput, TransactionRequest};
use citrea_common::SequencerConfig;
use citrea_evm::precompiles::schnorr::SCHNORRVERIFY;
use citrea_stf::genesis_config::GenesisPaths;
use revm::precompile::secp256r1::P256VERIFY;

use super::init_test_rollup;
use crate::common::helpers::{
    create_default_rollup_config, start_rollup, tempdir_with_children, NodeMode,
};
use crate::common::TEST_DATA_GENESIS_PATH;

#[tokio::test(flavor = "multi_thread")]
async fn test_custom_precompiles() -> Result<(), anyhow::Error> {
    // citrea::initialize_logging(tracing::Level::DEBUG);

    let storage_dir = tempdir_with_children(&["DA", "sequencer", "full-node"]);
    let da_db_dir = storage_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = storage_dir.path().join("sequencer").to_path_buf();

    let (seq_port_tx, seq_port_rx) = tokio::sync::oneshot::channel();

    let rollup_config = create_default_rollup_config(
        true,
        &sequencer_db_dir,
        &da_db_dir,
        NodeMode::SequencerNode,
        None,
    );
    let sequencer_config = SequencerConfig::default();

    let seq_task = tokio::spawn(async {
        start_rollup(
            seq_port_tx,
            GenesisPaths::from_dir(TEST_DATA_GENESIS_PATH),
            None,
            None,
            rollup_config,
            Some(sequencer_config),
            None,
            false,
        )
        .await;
    });

    let seq_port = seq_port_rx.await.unwrap();

    let seq_test_client = init_test_rollup(seq_port).await;

    // p256 verify
    {
        // show eth_call uses the custom precompile
        let addr = P256VERIFY.address();

        // correct input
        let mut tx_req = TransactionRequest::default().to(*addr).input(
            TransactionInput::from(
                hex::decode("4cee90eb86eaa050036147a12d49004b6b9c72bd725d39d4785011fe190f0b4da73bd4903f0ce3b639bbbf6e8e80d16931ff4bcf5993d58468e8fb19086e8cac36dbcd03009df8c59286b162af3bd7fcc0450c9aa81be5d10d312af6c66b1d604aebd3099c618202fcfe16ae7770b0c49ab5eadf74b754204a3bb6060e44eff37618b065f9832de4ca6ca971a7a1adc826d0f7c00181a5fb2ddf79ae00b4e10e").unwrap()
            ));

        let res = seq_test_client.client.call(tx_req.clone()).await.unwrap();

        assert_eq!(res, Bytes::from(B256::with_last_byte(1).to_vec()));

        // incorrect input
        tx_req.set_input(hex::decode("3cee90eb86eaa050036147a12d49004b6b9c72bd725d39d4785011fe190f0b4da73bd4903f0ce3b639bbbf6e8e80d16931ff4bcf5993d58468e8fb19086e8cac36dbcd03009df8c59286b162af3bd7fcc0450c9aa81be5d10d312af6c66b1d604aebd3099c618202fcfe16ae7770b0c49ab5eadf74b754204a3bb6060e44eff37618b065f9832de4ca6ca971a7a1adc826d0f7c00181a5fb2ddf79ae00b4e10e").unwrap());

        let res = seq_test_client.client.call(tx_req.clone()).await.unwrap();

        assert_eq!(res, Bytes::new());

        // use empty bytes
        // the calls to the precompiles will fail but the gas will be charged
        // if we don't do this, because of EIP-7623 the gas for both calls will be the same
        tx_req.set_input(Bytes::new());

        // shows eth_estimate_gas uses the custom precompile
        let res = seq_test_client
            .client
            .estimate_gas(tx_req.clone())
            .await
            .unwrap();

        // send the same estimation to an empty adress
        let res_default = seq_test_client
            .client
            .estimate_gas(
                TransactionRequest::default()
                    .to(Address::random())
                    .input(tx_req.input.clone()),
            )
            .await
            .unwrap();

        assert!(res > res_default + 3450); // P256VERIFY_BASE = 3450

        // shows eth_createAccessList uses the custom precompile
        let res_access_list = seq_test_client
            .client
            .create_access_list(&tx_req)
            .await
            .unwrap();

        assert_eq!(res_access_list.gas_used, U256::from(res));
    }

    {
        let addr = SCHNORRVERIFY.address();

        // correct input
        let mut tx_req = TransactionRequest::default().to(*addr).input(TransactionInput::from(
            hex::decode("D69C3509BB99E412E68B0FE8544E72837DFA30746D8BE2AA65975F29D22DC7B94DF3C3F68FCC83B27E9D42C90431A72499F17875C81A599B566C9889B969670300000000000000000000003B78CE563F89A0ED9414F5AA28AD0D96D6795F9C6376AFB1548AF603B3EB45C9F8207DEE1060CB71C04E80F593060B07D28308D7F4").unwrap()
        ));

        let res = seq_test_client.client.call(tx_req.clone()).await.unwrap();
        assert_eq!(res, Bytes::from(B256::with_last_byte(1).to_vec()));

        // incorrect input
        tx_req.set_input(hex::decode("DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C891FA62E331EDBC21C394792D2AB1100A7B432B013DF3F6FF4F99FCB33E0E1515F28890B3EDB6E7189B630448B515CE4F8622A954CFE545735AAEA5134FCCDB2BD").unwrap());

        let res = seq_test_client.client.call(tx_req.clone()).await.unwrap();
        assert_eq!(res, Bytes::new());

        // use empty bytes
        // the calls to the precompiles will fail but the gas will be charged
        // if we don't do this, because of EIP-7623 the gas for both calls will be the same
        tx_req.set_input(Bytes::new());

        // shows eth_estimateGas uses the custom precompile
        let res = seq_test_client
            .client
            .estimate_gas(tx_req.clone())
            .await
            .unwrap();

        // send the same estimation to an empty adress
        let res_default = seq_test_client
            .client
            .estimate_gas(
                TransactionRequest::default()
                    .to(Address::random())
                    .input(tx_req.input.clone()),
            )
            .await
            .unwrap();

        assert!(res > res_default + 4600); // SCHNORRVERIFY_BASE = 4600

        // shows eth_createAccessList uses the custom precompile
        let res_access_list = seq_test_client
            .client
            .create_access_list(&tx_req)
            .await
            .unwrap();

        assert_eq!(res_access_list.gas_used, U256::from(res));
    }

    seq_task.abort();
    Ok(())
}
