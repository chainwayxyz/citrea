use std::fs::File;
use std::future::Future;
use std::io::{BufRead, BufReader};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::{fs, io};

use anyhow::bail;
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use tokio::time::{sleep, Duration, Instant};

use super::Result;

pub fn get_available_port() -> Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    Ok(listener.local_addr()?.port())
}

pub fn get_workspace_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .ancestors()
        .nth(2)
        .expect("Failed to find workspace root")
        .to_path_buf()
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
    dir.join("stdout.log")
}

pub fn get_stderr_path(dir: &Path) -> PathBuf {
    dir.join("stderr.log")
}

/// Get genesis path from resources
/// TODO: assess need for customable genesis path in e2e tests
pub fn get_default_genesis_path() -> PathBuf {
    let workspace_root = get_workspace_root();
    let mut path = workspace_root.to_path_buf();
    path.push("resources");
    path.push("genesis");
    path.push("bitcoin-regtest");
    path
}

pub fn get_genesis_path(dir: &Path) -> PathBuf {
    dir.join("genesis")
}

pub fn generate_test_id() -> String {
    thread_rng()
        .sample_iter(&Alphanumeric)
        .take(10)
        .map(char::from)
        .collect()
}

pub fn copy_directory(src: impl AsRef<Path>, dst: impl AsRef<Path>) -> io::Result<()> {
    let src = src.as_ref();
    let dst = dst.as_ref();

    if !dst.exists() {
        fs::create_dir_all(dst)?;
    }

    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        let file_name = entry.file_name();
        let src_path = src.join(&file_name);
        let dst_path = dst.join(&file_name);

        if ty.is_dir() {
            copy_directory(&src_path, &dst_path)?;
        } else {
            fs::copy(&src_path, &dst_path)?;
        }
    }

    Ok(())
}

pub(crate) async fn retry<F, Fut, T>(f: F, timeout: Option<Duration>) -> Result<T>
where
    F: Fn() -> Fut,
    Fut: Future<Output = Result<T>>,
{
    let start = Instant::now();
    let timeout = start + timeout.unwrap_or_else(|| Duration::from_secs(5));

    loop {
        match tokio::time::timeout_at(timeout, f()).await {
            Ok(Ok(result)) => return Ok(result),
            Ok(Err(e)) => {
                if Instant::now() >= timeout {
                    return Err(e);
                }
                sleep(Duration::from_millis(500)).await;
            }
            Err(elapsed) => bail!("Timeout expired {elapsed}"),
        }
    }
}

pub fn tail_file(path: &Path, lines: usize) -> Result<()> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut last_lines = Vec::with_capacity(lines);

    for line in reader.lines() {
        let line = line?;
        if last_lines.len() >= lines {
            last_lines.remove(0);
        }
        last_lines.push(line);
    }

    for line in last_lines {
        println!("{}", line);
    }

    Ok(())
}

pub fn get_tx_backup_dir() -> String {
    let workspace_root = get_workspace_root();
    let mut path = workspace_root.to_path_buf();
    path.push("resources");
    path.push("bitcoin");
    path.push("inscription_txs");
    path.to_str().expect("Failed to convert path").to_string()
}
