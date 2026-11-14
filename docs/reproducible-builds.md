# Reproducible Builds

Citrea release binaries are produced by a pinned [Nix](https://nixos.org/) build (`nix/flake.nix`) in the `release` GitHub Actions workflow. Every tagged release publishes:

- `citrea-<tag>-<platform>` — fullnode binary
- `citrea-cli-<tag>-<platform>` — citrea CLI
- `SHA256SUMS.txt` — SHA-256 manifest for all release binaries
- `SHA256SUMS.txt.sigstore.json` — Sigstore bundle for the checksum manifest
- A Sigstore provenance attestation binding the artifacts to the workflow, commit, and runner identity

Supported platforms: `linux-amd64`, `linux-arm64`, `osx-arm64`.

## Reproducible SP1 guests

SP1's [production build](https://docs.succinct.xyz/docs/sp1/writing-programs/compiling#production-builds) uses `cargo prove build --docker`. Citrea enables this with `REPR_GUEST_BUILD=1` and pins the image to `v6.10.0`:

```bash
make install-sp1
CITREA_NETWORK=nightly make build-reproducible
```

This runs `cargo build --release --locked` with Docker guest compilation. The host binaries are written to `target/release/`; this command makes the **guests** reproducible. Native host-binary reproducibility is handled separately by the existing Nix release workflow. `make build-release` uses native guest compilation for development.

The release workflow embeds committed Bitcoin DA guests from `resources/guests/sp1/<network>/`, one `<guest>-<index>` pin per guest version a fork runs. Before a release, regenerate and commit the matching ELFs and Rust constants for each changed network:

```bash
python3 tools/pin-sp1-guests.py --network mainnet --guest batch-proof --index 0
python3 tools/pin-sp1-guests.py --network mainnet --guest light-client-proof --index 0
```

The pinning script always uses the pinned Docker image and clears development overrides. It works on macOS as well as Linux; native builds must not be used for pinning. `--network` (`mainnet`, `testnet`, or `devnet`), `--guest` (`batch-proof` or `light-client-proof`) and `--index` are all required. `--index` is the pin to write: the guest's highest index to rebuild it, or the next one for a fork that changes the guest (see [SP1 proving](sp1.md#building-guests)). Nightly guests are not pinned; they are built with the binary.

To independently rebuild and compare the full ELF bytes and program keys of a network's latest pins, pass each guest's highest index:

```bash
python3 tools/pin-sp1-guests.py --network mainnet --guest batch-proof --index 0
python3 tools/pin-sp1-guests.py --network mainnet --guest light-client-proof --index 0
git diff --exit-code resources/guests/sp1/mainnet
```

Pins with a lower index belong to earlier forks; rebuild them from the commit that pinned them.

Use a fresh, clean checkout to avoid reusing local guest compilation artifacts. See [SP1 proving](sp1.md#building-guests) for prerequisites and the batch/light-client build dependency.

## Verifying a downloaded release

Three independent checks, from cheapest to strongest.

### 1. Provenance attestation (recommended)

Requires the [`gh` CLI](https://cli.github.com/). Confirms the binary was produced by the `release` workflow on `chainwayxyz/citrea` at a specific commit, recorded in the public Sigstore transparency log.

```bash
gh attestation verify citrea-v1.2.3-linux-amd64 \
  --repo chainwayxyz/citrea
```

### 2. Published hashes

Requires [`cosign`](https://docs.sigstore.dev/cosign/system_config/installation/).

```bash
cosign verify-blob SHA256SUMS.txt \
  --bundle SHA256SUMS.txt.sigstore.json \
  --certificate-identity "https://github.com/chainwayxyz/citrea/.github/workflows/release.yml@refs/tags/v1.2.3" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
```

Then check your downloaded artifact against the signed manifest:

```bash
grep '  citrea-v1.2.3-linux-amd64$' SHA256SUMS.txt | shasum -a 256 -c -
```

Pair this with (1) — a hash manifest is only useful if you verify its signature.

### 3. Rebuild from source

The strongest claim: you rebuild from the tagged commit and obtain byte-identical binaries. Requires [Nix with flakes](https://nixos.org/download.html).

```bash
git clone https://github.com/chainwayxyz/citrea.git
cd citrea
git checkout v1.2.3
nix build ./nix#citrea --no-update-lock-file
shasum -a 256 ./result/bin/citrea ./result/bin/citrea-cli
```

The hashes must match the corresponding entries in `SHA256SUMS.txt` from the release. If they don't, something is wrong — file an issue.

## macOS: Gatekeeper quarantine

Release binaries are ad-hoc signed (needed to run on Apple Silicon) but **not** notarized by Apple. macOS quarantines them on download:

```bash
xattr -dr com.apple.quarantine ./citrea
xattr -dr com.apple.quarantine ./citrea-cli
```

Or: Finder → right-click the binary → Open → confirm in the dialog.
