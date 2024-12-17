use std::fs;
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use std::process::{Command, ExitStatus};
use std::str::FromStr;

fn main() {
    let is_risczero_installed = Command::new("cargo")
        .args(["risczero", "help"])
        .status()
        .unwrap_or(ExitStatus::from_raw(1)); // If we can't execute the command, assume risczero isn't installed since duplicate install attempts are no-ops.

    if !is_risczero_installed.success() {
        // If installation fails, just exit silently. The user can try again.
        let _ = Command::new("cargo")
            .args(["install", "cargo-risczero"])
            .status();
    }

    build_sp1_guest();
}

fn build_sp1_guest() {
    println!("cargo:rerun-if-env-changed=BUILD_SP1_GUEST");

    let bitcoin_program_path = "guests/sp1/batch-prover-bitcoin";

    let build_args = sp1_helper::BuildArgs {
        elf_name: "zkvm-elf".to_string(),
        ..Default::default()
    };

    match std::env::var("BUILD_SP1_GUEST") {
        Ok(value) => match value.as_str() {
            "1" | "true" => {
                println!("cargo:warning=Building SP1 guest");
                sp1_helper::build_program_with_args(bitcoin_program_path, build_args);
                return;
            }
            "0" | "false" => {
                println!("cargo:warning=Skipping SP1 guest build");
            }
            _ => {
                println!("cargo:warning=Invalid value for BUILD_SP1_GUEST: '{}'. Expected '0', '1', 'true', or 'false'. Defaulting to skipping SP1 guest build.", value);
            }
        },
        Err(std::env::VarError::NotPresent) => {
            println!("cargo:warning=BUILD_SP1_GUEST not set. Skipping SP1 guest build.");
        }
        Err(std::env::VarError::NotUnicode(_)) => {
            println!("cargo:warning=BUILD_SP1_GUEST contains invalid Unicode. Defaulting to skipping guest build.");
        }
    };

    // Create an empty elf file if the build is skipped
    let elf_path = PathBuf::from_str(bitcoin_program_path)
        .unwrap()
        .join(build_args.output_directory)
        .join(build_args.elf_name);
    fs::create_dir_all(elf_path.parent().unwrap()).unwrap();
    fs::write(elf_path, []).unwrap();
}
