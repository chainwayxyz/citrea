use anyhow::bail;
use async_trait::async_trait;
use bitcoincore_rpc::RpcApi;

use crate::bitcoin_e2e::framework::TestFramework;
use crate::bitcoin_e2e::node::L2Node;
use crate::bitcoin_e2e::test_case::{TestCase, TestCaseRunner};
use crate::bitcoin_e2e::Result;

struct BasicSequencerTest;

#[async_trait]
impl TestCase for BasicSequencerTest {
    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let Some(sequencer) = &f.sequencer else {
            anyhow::bail!("Sequencer not running. Set TestCaseConfig with_sequencer to true")
        };

        let Some(da) = f.bitcoin_nodes.get(0) else {
            bail!("bitcoind not running. Test cannot run with bitcoind runnign as DA")
        };

        let seq_height0 = sequencer.client.eth_block_number().await;
        assert_eq!(seq_height0, 0);

        sequencer.client.send_publish_batch_request().await;
        da.generate(1, None).await?;

        sequencer.wait_for_l2_height(1, None).await;
        let seq_height1 = sequencer.client.eth_block_number().await;
        assert_eq!(seq_height1, 1);

        Ok(())
    }
}

#[tokio::test]
async fn basic_sequencer_test() -> Result<()> {
    TestCaseRunner::new(BasicSequencerTest).run().await
}
