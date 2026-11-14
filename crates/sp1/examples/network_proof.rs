//! Proves a batch proof input on Succinct's prover network, to try the requester account, the
//! default prices and the request flow with a real proof before the batch prover uses them.
//!
//! Without `--submit` it only executes the guest locally and prints the quote, so it spends nothing.
//! `--submit` proves through the batch prover's own code at the default prices; `RUST_LOG=info`
//! shows its request IDs, offers and retries.
//!
//! ```sh
//! NETWORK_PRIVATE_KEY=0x... RUST_LOG=info cargo run -p citrea-sp1 --features native --example network_proof -- \
//!     --elf resources/guests/sp1/<network>/batch-proof-<index>.elf \
//!     (--stdin <stdin.bin> | --input <input.bin>) \
//!     [--submit]
//! ```
//!
//! Inputs are what the batch prover writes to `TX_BACKUP_DIR`: `--stdin <job-id>-sp1-stdin.bin`
//! when it proves, or `--input <nanos>-rpc-proof-input-<i>.bin` from
//! `batchProver_createCircuitInput`. The ELF must be the batch guest of the network the input came
//! from.
use std::path::PathBuf;
use std::time::Instant;

use anyhow::Context;
use citrea_common::sp1::NetworkRequestConfig;
use citrea_sp1::{offered_price, prove_on_network, SP1Proof, FIRST_OFFER_PERCENT};
use clap::Parser;
use sp1_sdk::network::proto::GetProofRequestParamsResponse;
use sp1_sdk::{Elf, HashableKey, Prover, ProverClient, ProvingKey, SP1ProofMode, SP1Stdin};

#[derive(Parser)]
struct Args {
    /// Batch guest ELF, e.g. resources/guests/sp1/<network>/batch-proof-<index>.elf.
    #[arg(long)]
    elf: PathBuf,
    /// Complete guest stdin a proving job saved to TX_BACKUP_DIR, used as is.
    #[arg(long, required_unless_present = "input", conflicts_with = "input")]
    stdin: Option<PathBuf>,
    /// Raw circuit input from TX_BACKUP_DIR.
    #[arg(long)]
    input: Option<PathBuf>,
    /// Request the proof as the batch prover does. Without it nothing is sent and nothing is
    /// spent.
    #[arg(long)]
    submit: bool,
    /// Where to save the proof.
    #[arg(long)]
    out: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    sp1_sdk::utils::setup_logger();
    let args = Args::parse();
    let elf = std::fs::read(&args.elf).context("reading --elf")?;
    let stdin: SP1Stdin = if let Some(path) = &args.stdin {
        bincode::deserialize(&std::fs::read(path).context("reading --stdin")?)?
    } else {
        let path = args
            .input
            .as_ref()
            .expect("clap requires --stdin or --input");
        // Same stdin layout as SP1Host::run.
        let mut stdin = SP1Stdin::new();
        stdin.write_vec(std::fs::read(path).context("reading --input")?);
        stdin
    };

    let client = ProverClient::builder().network().build().await;

    // Executing first gives the gas the deadline and cost follow. Passing both limits below also
    // stops the SDK from executing the guest a second time before requesting.
    let (_, report) = client
        .execute(Elf::from(elf.clone()), stdin.clone())
        .calculate_gas(true)
        .await?;
    anyhow::ensure!(
        report.exit_code == 0,
        "guest exited with code {}",
        report.exit_code
    );
    let cycles = report.total_instruction_count();
    let gas = report.gas().context("executor reported no gas")?;
    println!(
        "cycles: {cycles}  gas: {gas} PGU  gas/cycles: {:.3}",
        gas as f64 / cycles as f64
    );

    let GetProofRequestParamsResponse::Auction(params) = client
        .get_proof_request_params(SP1ProofMode::Groth16)
        .await?
    else {
        anyhow::bail!("network returned no auction parameters");
    };
    let base_fee: u128 = params.base_fee.parse()?;
    let suggested: u64 = params.max_price_per_pgu.parse()?;
    // Empty on RPCs that predate the field.
    let floor: u64 = params.network_floor_price_per_pgu.parse().unwrap_or(0);

    let config = NetworkRequestConfig::default();
    let first = offered_price(suggested, FIRST_OFFER_PERCENT, floor, params.tick_size);
    let highest = offered_price(suggested, config.max_price_percent, floor, params.tick_size);

    let balance_before = client.get_balance().await?;
    println!(
        "network: floor {floor}, suggested {suggested}, tick {} wei/PGU",
        params.tick_size
    );
    println!(
        "offer: {first} wei/PGU ({} PROVE per billion PGU), raised up to {highest} while no prover bids",
        prove(first as u128 * 1_000_000_000)
    );
    println!(
        "cost: base fee {} + gas, so {} PROVE at the floor, {} PROVE at the first offer, {} PROVE at most",
        prove(base_fee),
        prove(base_fee + gas as u128 * floor as u128),
        prove(base_fee + gas as u128 * first as u128),
        prove(base_fee + gas as u128 * highest as u128),
    );
    println!("balance: {} PROVE", prove(balance_before.to::<u128>()));

    if !args.submit {
        println!("dry run: pass --submit to request the proof");
        return Ok(());
    }

    let pk = client.setup(Elf::from(elf.clone())).await?;
    let started = Instant::now();
    // Executes the guest again for its gas, then prices, requests and retries as the batch
    // prover does, on a blocking thread as the batch prover runs it.
    let (proof, session, client, pk) = tokio::task::spawn_blocking(move || {
        prove_on_network(&client, &pk, stdin, SP1ProofMode::Groth16, &config)
            .map(|(proof, session)| (proof, session, client, pk))
    })
    .await??;
    println!("fulfilled after {:.0?}", started.elapsed());
    println!("session: {session:#?}");

    client.verify(&proof, pk.verifying_key(), None)?;
    // The check Citrea runs on a batch proof it receives.
    SP1Proof::Groth16 {
        proof: proof.bytes(),
        public_values: proof.public_values.to_vec(),
    }
    .verify(&pk.verifying_key().hash_u32(), false)?;
    println!("proof verified by the SDK and by Citrea's verifier");

    // The balance can lag the fulfillment while the network settles.
    println!(
        "balance: {} PROVE, was {}",
        prove(client.get_balance().await?.to::<u128>()),
        prove(balance_before.to::<u128>())
    );

    if let Some(out) = &args.out {
        proof.save(out)?;
        println!("saved {}", out.display());
    }
    Ok(())
}

/// PROVE has 18 decimals.
fn prove(wei: u128) -> String {
    format!("{:.4}", wei as f64 / 1e18)
}
