use std::net::TcpListener;
use std::path::{Path, PathBuf};

use super::Result;

pub fn get_available_port() -> Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    Ok(listener.local_addr()?.port())
}

fn get_workspace_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .ancestors()
        .nth(2)
        .expect("Failed to find workspace root")
        .to_path_buf()
}

/// Get genesis path from resources
/// TODO: assess need for customable genesis path in e2e tests
pub fn get_genesis_path() -> PathBuf {
    let workspace_root = get_workspace_root();
    let mut path = workspace_root.to_path_buf();
    path.push("resources");
    path.push("genesis");
    path.push("bitcoin-regtest");
    path
}

/// Get citrea path from CITREA env or resolves to debug build.
pub fn get_citrea_path() -> PathBuf {
    std::env::var("CITREA").map_or_else(
        |_| {
            let workspace_root = get_workspace_root();
            let mut path = workspace_root.to_path_buf();
            path.push("target");
            path.push("debug");
            path.push("citrea");
            path
        },
        PathBuf::from,
    )
}

pub fn get_stdout_path(dir: &Path) -> PathBuf {
    dir.join("stdout")
}

pub fn get_stderr_path(dir: &Path) -> PathBuf {
    dir.join("stderr")
}
