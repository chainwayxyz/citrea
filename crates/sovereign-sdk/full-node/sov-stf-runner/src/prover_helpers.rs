use sequencer_client::SequencerClient;
use sov_modules_api::DaSpec;

pub(crate) async fn get_initial_slot_height<Da: DaSpec>(client: &SequencerClient) -> u64 {
    loop {
        match client.get_soft_batch::<Da>(1).await {
            Ok(Some(batch)) => return batch.da_slot_height,
            _ => {
                // sleep 1
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                continue;
            }
        }
    }
}
