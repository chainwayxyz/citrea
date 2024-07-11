use borsh::{BorshDeserialize, BorshSerialize};
use sov_risc0_adapter::host::Risc0Host;
use sov_rollup_interface::zk::{ZkvmGuest, ZkvmHost};

#[derive(BorshDeserialize, BorshSerialize, Debug, PartialEq)]
struct TestStruct {
    ints: Vec<i32>,
    string: String,
}

#[test]
fn test_hints_roundtrip() {
    let mut host = Risc0Host::new(&[]);

    let hint_a = TestStruct {
        ints: vec![0, 1, 2, 3, 4],
        string: "hello".to_string(),
    };
    let hint_b = TestStruct {
        ints: vec![5, 6, 7, 8, 9],
        string: "world".to_string(),
    };

    host.add_hint(&hint_a);
    host.add_hint(&hint_b);

    let guest = host.simulate_with_hints();

    let mut received;
    received = guest.read_from_host();
    assert_eq!(hint_a, received);
    received = guest.read_from_host();
    assert_eq!(hint_b, received);
}
