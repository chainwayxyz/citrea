pub mod config;
pub mod postgres_connector;
mod tables;

pub use config::OffchainDbConfig;
pub use postgres_connector::PostgresConnector;

pub(crate) fn get_table_extension() -> String {
    let thread = std::thread::current();
    let mut thread_name = format!("_{}", thread.name().unwrap_or("unnamed"));
    if thread_name == "tokio-runtime-worker" {
        thread_name = "".to_string();
    }
    thread_name.replace(":", "_")
}
