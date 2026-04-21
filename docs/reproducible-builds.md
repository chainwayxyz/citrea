# Reproducible Builds

Citrea release binaries are produced by a pinned [Nix](https://nixos.org/) build (`nix/flake.nix`) in the `Reproducible Build` GitHub Actions workflow. Every tagged release publishes:

- `citrea-<tag>-<platform>-reproducible` — fullnode binary
- `citrea-cli-<tag>-<platform>-reproducible` — citrea CLI
- `SHA256SUMS.txt` — SHA-256 manifest for all release binaries
- `SHA256SUMS.txt.sigstore.json` — Sigstore bundle for the checksum manifest
- A Sigstore provenance attestation binding the artifacts to the workflow, commit, and runner identity

Supported platforms: `linux-amd64`, `linux-arm64`, `osx-arm64`.

## Verifying a downloaded release

Three independent checks, from cheapest to strongest.

### 1. Provenance attestation (recommended)

Requires the [`gh` CLI](https://cli.github.com/). Confirms the binary was produced by the `Reproducible Build` workflow on `chainwayxyz/citrea` at a specific commit, recorded in the public Sigstore transparency log.

```bash
gh attestation verify citrea-v1.2.3-linux-amd64-reproducible \
  --repo chainwayxyz/citrea
```

### 2. Published hashes

This is the Sigstore/keyless equivalent of a traditional `SHA256SUMS.asc`: the checksum manifest is signed, but without a long-lived GPG key to distribute and rotate. Requires [`cosign`](https://docs.sigstore.dev/cosign/system_config/installation/).

```bash
cosign verify-blob SHA256SUMS.txt \
  --bundle SHA256SUMS.txt.sigstore.json \
  --certificate-identity "https://github.com/chainwayxyz/citrea/.github/workflows/reproducible-build.yml@refs/tags/v1.2.3" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
```

Then check your downloaded artifact against the signed manifest:

```bash
grep '  citrea-v1.2.3-linux-amd64-reproducible$' SHA256SUMS.txt | shasum -a 256 -c -
```

Pair this with (1) — a hash manifest is only useful if you verify its signature.

### 3. Rebuild from source

The strongest claim: you rebuild from the tagged commit and obtain byte-identical binaries. Requires [Nix with flakes](https://nixos.org/download.html).

```bash
git clone https://github.com/chainwayxyz/citrea.git
cd citrea
git checkout v1.2.3
nix build ./nix#citrea
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
