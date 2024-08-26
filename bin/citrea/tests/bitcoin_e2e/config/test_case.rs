use std::path::PathBuf;
use std::time::Duration;

use tempfile::TempDir;

#[derive(Clone)]
pub struct TestCaseConfig {
    pub num_nodes: usize,
    pub with_sequencer: bool,
    pub with_full_node: bool,
    pub with_prover: bool,
    #[allow(unused)]
    pub timeout: Duration,
    pub dir: PathBuf,
    pub docker: bool,
}

impl Default for TestCaseConfig {
    fn default() -> Self {
        TestCaseConfig {
            num_nodes: 1,
            with_sequencer: true,
            with_prover: false,
            with_full_node: false,
            timeout: Duration::from_secs(60),
            dir: TempDir::new()
                .expect("Failed to create temporary directory")
                .into_path(),
            docker: true,
        }
    }
}
