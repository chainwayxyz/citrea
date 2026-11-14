#!/usr/bin/env bash
# Checks the succinct Rust toolchain that `sp1up --version v6.10.0` installed against pinned
# hashes. Run it after sp1up and before any guest build.
#
# `cargo prove install-toolchain` finds the archive by tag in succinctlabs/rust's releases,
# which are not immutable, and does not check what it downloads. It leaves the archive in
# ~/.sp1 after unpacking it, so the archive the toolchain came from can be checked here.
# (cargo-prove always uses ~/.sp1 for the toolchain, whatever SP1_DIR is.)
#
# To update, take the tag from LATEST_SUPPORTED_TOOLCHAIN_VERSION_TAG in SP1's
# crates/cli/src/lib.rs at the pinned release, then read the digests:
#   curl -s https://api.github.com/repos/succinctlabs/rust/releases/tags/<tag> | grep -E '"name"|"digest"'
set -euo pipefail

# succinctlabs/rust release succinct-1.96.0-64bit-v3, used by SP1 v6.10.0
case "$(uname -s)-$(uname -m)" in
  Linux-x86_64)
    target=x86_64-unknown-linux-gnu
    expected=23905647c8ba007bed72e9207ceada06d08023f4dca73c87a122acbe7468ce07 ;;
  Linux-aarch64 | Linux-arm64)
    target=aarch64-unknown-linux-gnu
    expected=0feb8467a2f3452873f95d03d02f8e1e4b615ae3e0648d59af9307ad8f625adb ;;
  Darwin-arm64)
    target=aarch64-apple-darwin
    expected=a8e9e9695af87d8d1277e7febb8ca238004d634ff489158b32fe04e71fea63b3 ;;
  Darwin-x86_64)
    target=x86_64-apple-darwin
    expected=ba35922f614206035bb487f1179f720eea11ebb035c1cf7a9913ed30b18f74dc ;;
  *)
    echo "No pinned succinct toolchain hash for $(uname -s)-$(uname -m)" >&2
    exit 1 ;;
esac

archive="$HOME/.sp1/rust-toolchain-${target}.tar.gz"
if [ ! -f "$archive" ]; then
  echo "succinct toolchain archive not found at $archive; run sp1up first" >&2
  exit 1
fi

actual="$(shasum -a 256 "$archive" | cut -d' ' -f1)"
if [ "$actual" != "$expected" ]; then
  echo "succinct toolchain hash mismatch for $archive: expected $expected, got $actual" >&2
  # Unlink it so nothing builds with it.
  rustup toolchain remove succinct >/dev/null 2>&1 || true
  exit 1
fi
echo "Verified succinct toolchain archive for $target"
