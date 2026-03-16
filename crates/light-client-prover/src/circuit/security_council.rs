use alloy_primitives::{Address, B256};
use alloy_sol_types::sol;
use serde::Serialize;
use sov_rollup_interface::da::{
    AddSecurityCouncilMemberV1Body, BatchProofMethodIdBody, RemoveBatchProofMethodIdV1Body,
    RemoveSecurityCouncilMemberV1Body, ReplaceSecurityCouncilMemberV1Body,
    SetLcpToPreviousStateV1Body, UpdateBatchProverDaPubKeyV1Body,
    UpdateSecurityCouncilThresholdV1Body, UpdateSequencerDaPubKeyV1Body,
};

/// Converts an array of 8 u32 values to an array of 32 u8 values in little-endian order.
fn convert_u32_8_to_u8_32(value: [u32; 8]) -> [u8; 32] {
    let mut output = [0u8; 32];
    for (i, &val) in value.iter().enumerate() {
        output[i * 4..(i + 1) * 4].copy_from_slice(&val.to_le_bytes());
    }
    output
}

sol! {
    #[derive(Debug, Serialize)]
    struct BatchProofMethodIdUpdate {
        uint64 activationL2Height;
        bytes32 batchProofMethodId;
        uint64 nonce;
    }
}

impl From<BatchProofMethodIdBody> for BatchProofMethodIdUpdate {
    fn from(batch_proof_method_id_body: BatchProofMethodIdBody) -> Self {
        BatchProofMethodIdUpdate {
            activationL2Height: batch_proof_method_id_body.activation_l2_height,
            batchProofMethodId: B256::from_slice(
                convert_u32_8_to_u8_32(batch_proof_method_id_body.method_id).as_slice(),
            ),
            nonce: batch_proof_method_id_body.nonce,
        }
    }
}

sol! {
    #[derive(Debug, Serialize)]
    struct AddSecurityCouncilMember {
        address newMember;
        uint32 newThreshold;
        uint64 nonce;
    }
}

impl From<AddSecurityCouncilMemberV1Body> for AddSecurityCouncilMember {
    fn from(body: AddSecurityCouncilMemberV1Body) -> Self {
        AddSecurityCouncilMember {
            newMember: Address::from_slice(&body.new_member),
            newThreshold: body.new_threshold,
            nonce: body.nonce,
        }
    }
}

sol! {
    #[derive(Debug, Serialize)]
    struct RemoveSecurityCouncilMember {
        address memberToBeRemoved;
        uint32 newThreshold;
        uint64 nonce;
    }
}

impl From<RemoveSecurityCouncilMemberV1Body> for RemoveSecurityCouncilMember {
    fn from(body: RemoveSecurityCouncilMemberV1Body) -> Self {
        RemoveSecurityCouncilMember {
            memberToBeRemoved: Address::from_slice(&body.member_to_be_removed),
            newThreshold: body.new_threshold,
            nonce: body.nonce,
        }
    }
}

sol! {
    #[derive(Debug, Serialize)]
    struct UpdateSecurityCouncilThreshold {
        uint32 newThreshold;
        uint64 nonce;
    }
}

impl From<UpdateSecurityCouncilThresholdV1Body> for UpdateSecurityCouncilThreshold {
    fn from(body: UpdateSecurityCouncilThresholdV1Body) -> Self {
        UpdateSecurityCouncilThreshold {
            newThreshold: body.new_threshold,
            nonce: body.nonce,
        }
    }
}

sol! {
    #[derive(Debug, Serialize)]
    struct ReplaceSecurityCouncilMember {
        address toBeReplaced;
        address newMember;
        uint64 nonce;
    }
}

impl From<ReplaceSecurityCouncilMemberV1Body> for ReplaceSecurityCouncilMember {
    fn from(body: ReplaceSecurityCouncilMemberV1Body) -> Self {
        ReplaceSecurityCouncilMember {
            toBeReplaced: Address::from_slice(&body.to_be_replaced),
            newMember: Address::from_slice(&body.new_member),
            nonce: body.nonce,
        }
    }
}

sol! {
    #[derive(Debug, Serialize)]
    struct UpdateSequencerDaPubKey {
        bytes newPubKey;
        uint64 nonce;
    }
}

impl From<UpdateSequencerDaPubKeyV1Body> for UpdateSequencerDaPubKey {
    fn from(body: UpdateSequencerDaPubKeyV1Body) -> Self {
        UpdateSequencerDaPubKey {
            newPubKey: body.new_pub_key.to_vec().into(),
            nonce: body.nonce,
        }
    }
}

sol! {
    #[derive(Debug, Serialize)]
    struct UpdateBatchProverDaPubKey {
        bytes newPubKey;
        uint64 nonce;
    }
}

impl From<UpdateBatchProverDaPubKeyV1Body> for UpdateBatchProverDaPubKey {
    fn from(body: UpdateBatchProverDaPubKeyV1Body) -> Self {
        UpdateBatchProverDaPubKey {
            newPubKey: body.new_pub_key.to_vec().into(),
            nonce: body.nonce,
        }
    }
}

sol! {
    #[derive(Debug, Serialize)]
    struct RemoveBatchProofMethodId {
        uint32 methodIdIndex;
        bytes32 batchProofMethodId;
        uint64 l2ActivationHeight;
        uint64 nonce;
    }
}

impl From<RemoveBatchProofMethodIdV1Body> for RemoveBatchProofMethodId {
    fn from(body: RemoveBatchProofMethodIdV1Body) -> Self {
        RemoveBatchProofMethodId {
            methodIdIndex: body.method_id_index,
            batchProofMethodId: B256::from_slice(
                convert_u32_8_to_u8_32(body.batch_proof_method_id).as_slice(),
            ),
            l2ActivationHeight: body.l2_activation_height,
            nonce: body.nonce,
        }
    }
}

sol! {
    #[derive(Debug, Serialize)]
    struct SetLcpToPreviousState {
        bytes32 preStateRoot;
        uint32 index;
        uint64 lastL2Height;
        bytes32 merkleRoot;
        uint64 nonce;
    }
}

impl From<SetLcpToPreviousStateV1Body> for SetLcpToPreviousState {
    fn from(body: SetLcpToPreviousStateV1Body) -> Self {
        SetLcpToPreviousState {
            preStateRoot: B256::from_slice(&body.pre_state_root),
            index: body.index,
            lastL2Height: body.last_l2_height,
            merkleRoot: B256::from_slice(&body.merkle_root),
            nonce: body.nonce,
        }
    }
}
