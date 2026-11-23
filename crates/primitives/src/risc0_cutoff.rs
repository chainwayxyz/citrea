//! Hand-over from RISC0 to SP1 proving on networks that were proven with RISC0.
//!
//! `L0` is an L1 checkpoint chosen while RISC0 proving is still running, and `P0` is the RISC0
//! light client proof output at `L0`. The first SP1 light client proof, at `L0 + 1`, has no
//! previous proof and continues from `P0` as its previous output, and the SP1 batch proof
//! covers every L2 block after `P0.last_l2_height`.

use sov_rollup_interface::da::LatestDaState;
use sov_rollup_interface::zk::light_client_proof::output::LightClientCircuitOutput;
use sov_rollup_interface::Network;

/// `P0`, the RISC0 light client proof output at `L0` that SP1 proving continues from.
///
/// It has every field of the output except the RISC0 light client proof method ID.
#[derive(Clone, Debug, PartialEq)]
pub struct Risc0Cutoff {
    /// `P0.latest_da_state`, the Bitcoin header chain state of `L0`
    pub da_state: LatestDaState,
    /// `P0.l2_state_root`
    pub l2_state_root: [u8; 32],
    /// `P0.last_l2_height`
    pub last_l2_height: u64,
    /// `P0.last_sequencer_commitment_index`
    pub last_sequencer_commitment_index: u32,
    /// `P0.lcp_state_root`, the light client JMT root the first SP1 light client proof builds on.
    pub lc_state_root: [u8; 32],
}

impl Risc0Cutoff {
    /// `L0`, the RISC0 L1 checkpoint from which the SP1 light client starts.
    pub const fn l1_height(&self) -> u64 {
        self.da_state.block_height
    }

    /// `P0` as the previous light client proof output of the first SP1 light client proof,
    /// with the SP1 light client proof method ID instead of the RISC0 one.
    pub const fn light_client_proof_output(
        self,
        light_client_proof_method_id: [u32; 8],
    ) -> LightClientCircuitOutput {
        LightClientCircuitOutput {
            l2_state_root: self.l2_state_root,
            light_client_proof_method_id,
            latest_da_state: self.da_state,
            last_l2_height: self.last_l2_height,
            lcp_state_root: self.lc_state_root,
            last_sequencer_commitment_index: self.last_sequencer_commitment_index,
        }
    }
}

// Deployment placeholders: replace each network's None with Some(Risc0Cutoff { ... })
// using the fields above, copied from the journal of the chosen L0's P0. Never use zero-filled
// P0 values. The initial values of the light client (INITIAL_*_STATE, genesis root and initial
// batch proof method IDs) stay as they are: the first SP1 light client proof starts from P0.
// P0's JMT keeps the RISC0 batch proof method IDs, so after L0 the security council must add
// the SP1 batch key with activation height P0.last_l2_height before the first SP1 batch proof.
// Also replace the network's u64::MAX V3 activation height in forks.rs.
// Rebuild and pin the network's SP1 guests after filling these constants.
// Mainnet P0: light client proof output at L0 = 977169.
const MAINNET_RISC0_CUTOFF: Option<Risc0Cutoff> = Some(Risc0Cutoff {
    da_state: LatestDaState {
        block_hash: [
            127, 132, 28, 190, 152, 194, 195, 162, 126, 108, 128, 97, 43, 123, 251, 29, 101, 191,
            255, 52, 88, 216, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ],
        block_height: 977169,
        total_work: [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 90, 209, 128, 193, 4, 177,
            88, 87, 87, 228, 25, 88,
        ],
        current_target_bits: 0x17021673,
        epoch_start_time: 1794632570,
        prev_11_timestamps: [
            1795416100, 1795418363, 1795418631, 1795419250, 1795419490, 1795419467, 1795419825,
            1795414665, 1795414858, 1795415527, 1795415256,
        ],
    },
    l2_state_root: [
        219, 111, 40, 239, 2, 21, 172, 25, 10, 177, 3, 222, 186, 177, 216, 68, 176, 66, 250, 147,
        124, 28, 232, 129, 121, 210, 25, 172, 197, 118, 74, 213,
    ],
    last_l2_height: 15656000,
    last_sequencer_commitment_index: 15656,
    lc_state_root: [
        70, 19, 121, 12, 233, 231, 163, 133, 3, 138, 234, 225, 158, 5, 217, 87, 184, 101, 124, 184,
        7, 62, 157, 201, 216, 243, 84, 131, 65, 180, 204, 234,
    ],
});
// Testnet P0: light client proof output at L0 = 161766.
const TESTNET_RISC0_CUTOFF: Option<Risc0Cutoff> = Some(Risc0Cutoff {
    da_state: LatestDaState {
        block_hash: [
            254, 162, 80, 42, 65, 145, 11, 32, 200, 59, 140, 227, 174, 225, 157, 94, 127, 229, 202,
            228, 45, 138, 90, 113, 131, 6, 67, 0, 0, 0, 0, 0,
        ],
        block_height: 161766,
        total_work: [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 15, 143, 185, 227, 1,
            38, 112, 72, 255, 142,
        ],
        current_target_bits: 0x1902a986,
        epoch_start_time: 1794654888,
        prev_11_timestamps: [
            1794872381, 1794866043, 1794867244, 1794868445, 1794869646, 1794867257, 1794868701,
            1794869947, 1794868445, 1794869979, 1794871180,
        ],
    },
    l2_state_root: [
        11, 180, 14, 214, 211, 199, 31, 209, 163, 125, 230, 42, 241, 166, 178, 232, 132, 172, 185,
        10, 128, 236, 63, 196, 56, 106, 85, 182, 16, 191, 114, 91,
    ],
    last_l2_height: 33985925,
    last_sequencer_commitment_index: 26711,
    lc_state_root: [
        48, 151, 254, 71, 87, 109, 11, 197, 149, 14, 216, 227, 244, 178, 52, 215, 210, 184, 158,
        105, 165, 90, 141, 19, 54, 177, 142, 242, 66, 12, 46, 54,
    ],
});
// Devnet P0: light client proof output at L0 = 4213905.
const DEVNET_RISC0_CUTOFF: Option<Risc0Cutoff> = Some(Risc0Cutoff {
    da_state: LatestDaState {
        block_hash: [
            12, 17, 250, 9, 209, 14, 93, 215, 241, 35, 118, 15, 52, 227, 138, 236, 136, 192, 65,
            10, 136, 161, 195, 234, 182, 94, 129, 188, 37, 2, 0, 0,
        ],
        block_height: 4213905,
        total_work: [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 18, 178,
            87, 220, 144, 168,
        ],
        current_target_bits: 0x1e0377ae,
        epoch_start_time: 1794648006,
        prev_11_timestamps: [
            1794652792, 1794652802, 1794652813, 1794652824, 1794652721, 1794652731, 1794652741,
            1794652751, 1794652761, 1794652771, 1794652782,
        ],
    },
    l2_state_root: [
        56, 163, 53, 79, 129, 148, 188, 98, 186, 183, 16, 201, 33, 231, 125, 252, 4, 189, 85, 124,
        34, 128, 203, 54, 227, 42, 193, 4, 110, 207, 140, 246,
    ],
    last_l2_height: 24771035,
    last_sequencer_commitment_index: 24905,
    lc_state_root: [
        230, 122, 65, 127, 119, 126, 220, 88, 146, 163, 78, 33, 100, 116, 194, 123, 64, 188, 76,
        31, 185, 137, 232, 67, 121, 116, 217, 184, 151, 155, 67, 26,
    ],
});

/// Returns the RISC0 cutoff of the network, `None` if it is not set or the network has no RISC0 history.
pub const fn risc0_cutoff(network: Network) -> Option<Risc0Cutoff> {
    match network {
        Network::Mainnet => MAINNET_RISC0_CUTOFF,
        Network::Testnet => TESTNET_RISC0_CUTOFF,
        Network::Devnet => DEVNET_RISC0_CUTOFF,
        Network::Nightly => None,
    }
}

/// Returns true if the network has proofs produced with RISC0.
pub const fn has_risc0_history(network: Network) -> bool {
    matches!(
        network,
        Network::Mainnet | Network::Testnet | Network::Devnet
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// P0 is the RISC0 output without its method ID: it is the previous output of the first
    /// SP1 light client proof, field for field, with the SP1 light client proof method ID.
    #[test]
    fn light_client_proof_output_is_p0() {
        let risc0_output = LightClientCircuitOutput {
            l2_state_root: [1; 32],
            lcp_state_root: [2; 32],
            light_client_proof_method_id: [3; 8],
            latest_da_state: LatestDaState {
                block_hash: [4; 32],
                block_height: 5,
                total_work: [6; 32],
                current_target_bits: 7,
                epoch_start_time: 8,
                prev_11_timestamps: [9; 11],
            },
            last_l2_height: 10,
            last_sequencer_commitment_index: 11,
        };
        let p0 = Risc0Cutoff {
            da_state: risc0_output.latest_da_state.clone(),
            l2_state_root: risc0_output.l2_state_root,
            last_l2_height: risc0_output.last_l2_height,
            last_sequencer_commitment_index: risc0_output.last_sequencer_commitment_index,
            lc_state_root: risc0_output.lcp_state_root,
        };
        assert_eq!(p0.l1_height(), 5);
        assert_eq!(
            p0.light_client_proof_output([12; 8]),
            LightClientCircuitOutput {
                light_client_proof_method_id: [12; 8],
                ..risc0_output
            }
        );
    }
}
