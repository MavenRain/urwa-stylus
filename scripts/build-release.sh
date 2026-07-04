#!/usr/bin/env bash
# Build deployable, size-optimized Stylus WASM for every contract in the workspace.
#
# The plain `cargo build --release` output exceeds the 24 KB compressed Stylus
# limit once metadata / ERC-1155 code is included. Getting under the limit needs
# two extra steps, both applied here:
#   1. build-std with the `immediate-abort` panic strategy, which strips Rust's
#      panic-formatting machinery (the single biggest size win).
#   2. wasm-opt -Oz (binaryen), which trims the module further.
#
# Requirements: a nightly toolchain with the `rust-src` component, the
# `wasm32-unknown-unknown` target, `wasm-opt` (binaryen), and `cargo-stylus`.
#   rustup component add rust-src
#   rustup target add wasm32-unknown-unknown
#   brew install binaryen   # or your platform's binaryen package
#   cargo install cargo-stylus
set -euo pipefail

cd "$(dirname "$0")/.."
OUT="target/wasm32-unknown-unknown/release"
ENDPOINT="${STYLUS_ENDPOINT:-https://sepolia-rollup.arbitrum.io/rpc}"

echo ">> build-std + immediate-abort release build"
RUSTFLAGS="-Zunstable-options -Cpanic=immediate-abort" cargo build \
  -Z build-std=std,panic_abort \
  --release --target wasm32-unknown-unknown --workspace --lib

for c in urwa20 urwa1155 urwa721; do
  echo ">> wasm-opt $c"
  # Enable ONLY the WASM features Stylus supports. Do NOT use `-all`: it enables
  # reference-types, which wasm-opt then emits and Stylus rejects at activation
  # ("reference types support is not enabled").
  wasm-opt -Oz \
    --enable-bulk-memory --enable-sign-ext --enable-mutable-globals --enable-nontrapping-float-to-int \
    --strip-debug "$OUT/$c.wasm" -o "$OUT/$c.opt.wasm"
  echo ">> cargo stylus check $c (compressed size must be <= 24 KB)"
  cargo stylus check --wasm-file "$OUT/$c.opt.wasm" --endpoint "$ENDPOINT" 2>&1 \
    | grep -iE 'contract size|data fee' || true
done

echo ">> deployable artifacts:"
ls -la "$OUT"/urwa20.opt.wasm "$OUT"/urwa1155.opt.wasm "$OUT"/urwa721.opt.wasm
