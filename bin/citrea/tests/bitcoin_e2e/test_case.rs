//! This module provides the TestCaseRunner and TestCase trait for running and defining test cases.
//! It handles setup, execution, and cleanup of test environments.

use std::panic::{self};
use std::sync::Arc;
use std::time::Duration;

use anyhow::anyhow;
use async_trait::async_trait;
use citrea_sequencer::SequencerConfig;
use sov_stf_runner::ProverConfig;
use tokio::task;

use super::config::BitcoinConfig;
use super::config::TestCaseConfig;
use super::config::TestConfig;
use super::config::{default_rollup_config, default_sequencer_config};
use super::framework::TestFramework;
use super::sequencer::Sequencer;
use super::Result;
use crate::bitcoin_e2e::node::Node;

// TestCaseRunner manages the lifecycle of a test case, including setup, execution, and cleanup.
/// It creates a test framework with the associated configs, spawns required nodes, connects them,
/// runs the test case, and performs cleanup afterwards. The `run` method handles any panics that
/// might occur during test execution and takes care of cleaning up and stopping the child processes.
pub struct TestCaseRunner<T: TestCase>(Arc<T>);

impl<T: TestCase> TestCaseRunner<T> {
    /// Creates a new TestCaseRunner with the given test case.
    pub fn new(test_case: T) -> Self {
        Self(Arc::new(test_case))
    }

    /// Internal method to set up connect the nodes, wait for the nodes to be ready and run the test.
    async fn run_test_case(&self, framework: &mut TestFramework) -> Result<()> {
        framework.bitcoin_nodes.connect_nodes().await?;

        if let Some(sequencer) = &framework.sequencer {
            sequencer.wait_for_ready(Duration::from_secs(5)).await?;
            println!("Sequencer is ready");
        }

        self.0.run_test(framework).await
    }

    /// Executes the test case, handling any panics and performing cleanup.
    ///
    /// This method spawns a blocking task to run the test, sets up the framework,
    /// executes the test, and ensures cleanup is performed even if a panic occurs.
    pub async fn run(self) -> Result<()> {
        let result = task::spawn_blocking(move || {
            let mut framework = None;
            let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
                futures::executor::block_on(async {
                    framework = Some(
                        TestFramework::new(TestConfig {
                            test_case: T::test_config(),
                            bitcoin: vec![T::bitcoin_config()],
                            sequencer: T::sequencer_config(),
                            prover: T::prover_config(),
                            prover_rollup: default_rollup_config(),
                            sequencer_rollup: default_rollup_config(),
                            full_node_rollup: default_rollup_config(),
                        })
                        .await?,
                    );
                    self.run_test_case(framework.as_mut().unwrap()).await
                })
            }));

            // Always attempt to stop the framework, even if a panic occurred
            if let Some(mut f) = framework {
                let _ = futures::executor::block_on(f.stop());
            }
            result
        })
        .await
        .expect("Task panicked");

        match result {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(e),
            Err(panic_error) => {
                let panic_msg = panic_error
                    .downcast_ref::<String>()
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "Unknown panic".to_string());
                Err(anyhow!("Test panicked: {}", panic_msg))
            }
        }
    }
}

/// Defines the interface for implementing test cases.
///
/// This trait should be implemented by every test case to define the configuration
/// and inner test logic. It provides default configurations that should be sane for most test cases,
/// which can be overridden by implementing the associated methods.
#[async_trait]
pub trait TestCase: Send + Sync + 'static {
    /// Returns the test case configuration.
    /// Override this method to provide custom test configurations.
    fn test_config() -> TestCaseConfig {
        TestCaseConfig::default()
    }

    /// Returns the Bitcoin configuration for the test.
    /// Override this method to provide a custom Bitcoin configuration.
    fn bitcoin_config() -> BitcoinConfig {
        BitcoinConfig::default()
    }

    /// Returns the sequencer configuration for the test.
    /// Override this method to provide a custom sequencer configuration.
    fn sequencer_config() -> SequencerConfig {
        default_sequencer_config()
    }

    /// Returns the prover configuration for the test.
    /// Override this method to provide a custom prover configuration.
    fn prover_config() -> ProverConfig {
        ProverConfig::default()
    }

    /// Implements the actual test logic.
    ///
    /// This method is where the test case should be implemented. It receives
    /// a reference to the TestFramework, which provides access to the test environment.
    ///
    /// # Arguments
    /// * `framework` - A reference to the TestFramework instance
    async fn run_test(&self, framework: &TestFramework) -> Result<()>;
}
