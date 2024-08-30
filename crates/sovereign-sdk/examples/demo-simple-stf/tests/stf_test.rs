use demo_simple_stf::CheckHashPreimageStf;
use sov_mock_da::verifier::MockDaSpec;
use sov_mock_da::{MockAddress, MockBlob, MockBlockHeader, MockValidityCond};
use sov_mock_zkvm::MockZkvm;
use sov_rollup_interface::spec::SpecId;
use sov_rollup_interface::stf::StateTransitionFunction;

#[test]
fn test_stf_success() {
    let address = MockAddress::from([1; 32]);

    let stf = &mut CheckHashPreimageStf::<MockValidityCond>::default();
    StateTransitionFunction::<MockZkvm<MockValidityCond>, MockDaSpec>::init_chain(stf, (), ());

    let mut blobs = {
        let incorrect_preimage = vec![1; 32];
        let correct_preimage = vec![0; 32];

        [
            MockBlob::new(incorrect_preimage, address, [0; 32]),
            MockBlob::new(correct_preimage, address, [0; 32]),
        ]
    };

    // Pretend we are in native code and progress the blobs to the verified state.
    for blob in &mut blobs {
        blob.data.advance(blob.data.total_len());
    }

    let result = StateTransitionFunction::<MockZkvm<MockValidityCond>, MockDaSpec>::apply_slot(
        stf,
        SpecId::Genesis,
        &[],
        (),
        (),
        &MockBlockHeader::default(),
        &MockValidityCond::default(),
        &mut blobs,
    );

    assert_eq!(2, result.batch_receipts.len());
}
