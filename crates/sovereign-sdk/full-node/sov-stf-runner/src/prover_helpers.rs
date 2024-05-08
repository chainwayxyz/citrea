use sequencer_client::SequencerClient;
use sov_modules_api::DaSpec;

pub(crate) async fn get_initial_slot_height<Da: DaSpec>(client: &SequencerClient) -> u64 {
    client
        .get_soft_batch::<Da>(1)
        .await
        .expect("Failed to get the soft confirmaiton #1 from sequencer.")
        .unwrap()
        .da_slot_height
}
