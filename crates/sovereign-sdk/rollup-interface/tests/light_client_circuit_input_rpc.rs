#![cfg(feature = "native")]

use alloy_primitives::U64;
use sov_rollup_interface::rpc::LightClientCircuitInputRpcResponse;

#[test]
fn test_light_client_circuit_input_assumptions_hex_roundtrip() {
    for assumptions in [vec![], vec![vec![0x00, 0xab, 0xff], vec![], vec![0x12]]] {
        let response = LightClientCircuitInputRpcResponse {
            assumptions: assumptions.clone(),
            l1_height: U64::from(42),
            l1_hash: [0xab; 32],
            input: vec![0x00, 0xab, 0xff],
        };
        let json = serde_json::to_value(&response).unwrap();
        let expected = if assumptions.is_empty() {
            serde_json::json!([])
        } else {
            serde_json::json!(["0x00abff", "0x", "0x12"])
        };
        assert_eq!(json["assumptions"], expected);
        assert_eq!(json["input"], "0x00abff");

        let decoded: LightClientCircuitInputRpcResponse = serde_json::from_value(json).unwrap();
        assert_eq!(decoded.assumptions, assumptions);
        assert_eq!(decoded.l1_height, response.l1_height);
        assert_eq!(decoded.l1_hash, response.l1_hash);
        assert_eq!(decoded.input, response.input);
    }
}

#[test]
fn test_light_client_circuit_input_assumptions_hex_decoding() {
    let mut json = serde_json::json!({
        "assumptions": ["00AbFF", "0x12"],
        "l1Height": "0x2a",
        "l1Hash": format!("0x{}", "ab".repeat(32)),
        "input": "0x"
    });
    let decoded: LightClientCircuitInputRpcResponse = serde_json::from_value(json.clone()).unwrap();
    assert_eq!(
        decoded.assumptions,
        vec![vec![0x00, 0xab, 0xff], vec![0x12]]
    );

    for invalid in [
        serde_json::json!([[0, 171, 255]]),
        serde_json::json!(["0xgg"]),
        serde_json::json!(["0x0"]),
    ] {
        json["assumptions"] = invalid;
        assert!(
            serde_json::from_value::<LightClientCircuitInputRpcResponse>(json.clone()).is_err()
        );
    }
}
