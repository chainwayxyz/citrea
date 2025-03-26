use std::collections::VecDeque;

use anyhow::Context;
use citrea_primitives::forks::fork_from_block_number;
use citrea_stf::runtime::{CitreaRuntime, DefaultContext};
use short_header_proof_provider::SHORT_HEADER_PROOF_PROVIDER;
use sov_db::ledger_db::BatchProverLedgerOps;
use sov_db::schema::types::L2BlockNumber;
use sov_keys::default_signature::K256PublicKey;
use sov_modules_api::L2Block;
use sov_modules_stf_blueprint::StfBlueprint;
use sov_prover_storage_manager::ProverStorageManager;
use sov_rollup_interface::da::SequencerCommitment;
use sov_rollup_interface::services::da::DaService;
use sov_state::Witness;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::layer::SubscriberExt;

const MAX_CUMULATIVE_CACHE_SIZE: usize = 128 * 1024 * 1024;

type CommitmentStateTransitionData = (
    VecDeque<Vec<u8>>,
    VecDeque<Vec<(Witness, Witness)>>,
    Vec<u64>,
    VecDeque<Vec<L2Block>>,
    Witness,
);

#[allow(clippy::too_many_arguments)]
pub(crate) async fn get_batch_proof_circuit_input_from_commitments<
    Da: DaService,
    DB: BatchProverLedgerOps,
>(
    first_l2_height_of_commitments: u64,
    sequencer_commitments: &[SequencerCommitment],
    ledger_db: &DB,
    storage_manager: &ProverStorageManager,
    sequencer_pub_key: &K256PublicKey,
) -> Result<CommitmentStateTransitionData, anyhow::Error> {
    let mut committed_l2_blocks = VecDeque::with_capacity(sequencer_commitments.len());

    for (idx, sequencer_commitment) in sequencer_commitments.iter().enumerate() {
        // get the l2 height ranges of each seq_commitments

        let start_l2 = if idx == 0 {
            first_l2_height_of_commitments
        } else {
            sequencer_commitments[idx - 1].l2_end_block_number + 1
        };
        let end_l2 = sequencer_commitment.l2_end_block_number;

        let l2_blocks_in_commitment = ledger_db
            .get_l2_block_range(&(L2BlockNumber(start_l2)..=L2BlockNumber(end_l2)))
            .context("Failed to get l2 blocks")?;
        assert_eq!(
            l2_blocks_in_commitment
                .last()
                .expect("at least one must exist")
                .height,
            end_l2,
            "Should not try to create circuit input without ensuring the prover is synced"
        );

        let mut l2_blocks = Vec::with_capacity(l2_blocks_in_commitment.len());

        for l2_block in l2_blocks_in_commitment {
            let l2_block: L2Block = l2_block
                .try_into()
                .context("Failed to parse transactions")?;

            l2_blocks.push(l2_block);
        }
        committed_l2_blocks.push_back(l2_blocks);
    }

    // Replay transactions in the commitment blocks and collect cumulative witnesses
    let (
        state_transition_witnesses,
        cache_prune_l2_heights,
        short_header_proofs,
        last_l1_hash_witness,
    ) = generate_cumulative_witness::<Da, _>(
        &committed_l2_blocks,
        ledger_db,
        storage_manager,
        sequencer_pub_key,
    )
    .await?;

    Ok((
        short_header_proofs,
        state_transition_witnesses,
        cache_prune_l2_heights,
        committed_l2_blocks,
        last_l1_hash_witness,
    ))
}

async fn generate_cumulative_witness<Da: DaService, DB: BatchProverLedgerOps>(
    committed_l2_blocks: &VecDeque<Vec<L2Block>>,
    ledger_db: &DB,
    storage_manager: &ProverStorageManager,
    sequencer_pub_key: &K256PublicKey,
) -> anyhow::Result<(
    VecDeque<Vec<(Witness, Witness)>>,
    Vec<u64>,
    VecDeque<Vec<u8>>,
    Witness, // last hash witness
)> {
    let mut short_header_proofs: VecDeque<Vec<u8>> = VecDeque::new();

    let mut state_transition_witnesses = VecDeque::with_capacity(committed_l2_blocks.len());

    let mut init_state_root = ledger_db
        .get_l2_state_root(committed_l2_blocks[0][0].height() - 1)?
        .expect("L2 state root must exist");

    let mut cumulative_state_log = None;
    let mut cumulative_offchain_log = None;
    let mut cache_prune_l2_heights = vec![];

    let mut stf =
        StfBlueprint::<DefaultContext, Da::Spec, CitreaRuntime<DefaultContext, Da::Spec>>::new();

    let last_l2_height = committed_l2_blocks
        .back()
        .expect("must have at least one commitment")
        .last()
        .expect("must have at least one l2 block")
        .height();

    for l2_blocks_in_commitment in committed_l2_blocks {
        let mut witnesses = Vec::with_capacity(l2_blocks_in_commitment.len());

        SHORT_HEADER_PROOF_PROVIDER
            .get()
            .unwrap()
            .clear_queried_hashes();

        for l2_block in l2_blocks_in_commitment {
            let l2_height = l2_block.height();

            let pre_state = storage_manager.create_storage_for_l2_height(l2_height);
            let current_spec = fork_from_block_number(l2_height).spec_id;

            let silent_subscriber = tracing_subscriber::registry().with(LevelFilter::OFF);
            let l2_block_result = tracing::subscriber::with_default(silent_subscriber, || {
                stf.apply_l2_block(
                    current_spec,
                    sequencer_pub_key,
                    &init_state_root,
                    pre_state,
                    cumulative_state_log.take(),
                    cumulative_offchain_log.take(),
                    Default::default(),
                    Default::default(),
                    l2_block,
                )
            })?;

            assert_eq!(
                l2_block.state_root(),
                l2_block_result.state_root_transition.final_root,
                "State root mismatch when regenerating witnesses"
            );

            init_state_root = l2_block_result.state_root_transition.final_root;

            let mut state_log = l2_block_result.state_log;
            let mut offchain_log = l2_block_result.offchain_log;

            // If cache grew too large, zkvm will error with OOM, hence, we pass
            // when to prune as hint
            if state_log.estimated_cache_size() + offchain_log.estimated_cache_size()
                > MAX_CUMULATIVE_CACHE_SIZE
            {
                state_log.prune_half();
                offchain_log.prune_half();
                cache_prune_l2_heights.push(l2_height);
            }

            cumulative_state_log = Some(state_log);
            cumulative_offchain_log = Some(offchain_log);

            witnesses.push((l2_block_result.witness, l2_block_result.offchain_witness));
        }

        let new_hashes = SHORT_HEADER_PROOF_PROVIDER
            .get()
            .unwrap()
            .take_queried_hashes(
                l2_blocks_in_commitment[0].height()
                    ..=l2_blocks_in_commitment
                        .last()
                        .expect("must have at least one")
                        .height(),
            );

        for hash in new_hashes {
            let serialized_shp = ledger_db
                .get_short_header_proof_by_l1_hash(&hash)?
                .expect("Should exist");

            short_header_proofs.push_back(serialized_shp);
        }

        state_transition_witnesses.push_back(witnesses);
    }

    let mut last_l1_hash_witness = Witness::default();
    // if post fork2 we always need to read the last L1 hash on Bitcoin Light Client contract
    // if the provider have some hashes, circuit will use that.
    if short_header_proofs.is_empty() {
        let cumulative_state_log = cumulative_state_log.unwrap();
        let prover_storage = storage_manager.create_storage_for_l2_height(last_l2_height + 1);

        // we don't care about the return here
        // we only care about the last hash witness getting filled (or not)
        let _ = citrea_stf::verifier::get_last_l1_hash_on_contract::<DefaultContext>(
            cumulative_state_log,
            prover_storage,
            &mut last_l1_hash_witness,
            [0u8; 32], // final state root is only needed for JMT proof verification
        );
    }

    Ok((
        state_transition_witnesses,
        cache_prune_l2_heights,
        short_header_proofs,
        last_l1_hash_witness,
    ))
}
