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
// TODO(mainnet): fill L0 and P0 before releasing v3.
const MAINNET_RISC0_CUTOFF: Option<Risc0Cutoff> = None;
// TODO(testnet): fill L0 and P0 before releasing v3.
const TESTNET_RISC0_CUTOFF: Option<Risc0Cutoff> = None;
// TODO(devnet): fill L0 and P0 before releasing v3.
const DEVNET_RISC0_CUTOFF: Option<Risc0Cutoff> = None;

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
