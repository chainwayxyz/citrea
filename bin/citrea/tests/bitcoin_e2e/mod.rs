mod bitcoin;
pub mod config;
mod docker;
pub mod framework;
mod full_node;
pub mod node;
mod prover;
mod sequencer;
pub mod test_case;

mod tests;

mod utils;

pub(crate) type Result<T> = anyhow::Result<T>;
