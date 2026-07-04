#!/usr/bin/env bash
# Deploy a uRWA contract to Arbitrum Sepolia, then call its one-time initialize().
#
# Stylus #[constructor]s do NOT run when deploying a prebuilt wasm with
# `cargo stylus deploy --wasm-file` (the only path that fits the 24 KB size limit),
# so these contracts use a guarded initialize() instead. This script does both:
#   1. deploy the wasm (no constructor), and
#   2. send one initialize() transaction granting every role to <admin-address>.
#
# Usage:
#   ./scripts/deploy-sepolia.sh <urwa20|urwa721|urwa1155> <admin-address> [key-path]
#
# [key-path] defaults to ~/.urwa-deploy.key (a file containing just the 0x private key).
# Run ./scripts/build-release.sh first if the .opt.wasm files are missing.
set -euo pipefail
cd "$(dirname "$0")/.."

CONTRACT="${1:?usage: deploy-sepolia.sh <urwa20|urwa721|urwa1155> <admin-address> [key-path]}"
ADMIN="${2:?error: admin address required as the 2nd argument}"
KEY="${3:-$HOME/.urwa-deploy.key}"
WASM="target/wasm32-unknown-unknown/release/${CONTRACT}.opt.wasm"
ENDPOINT="${STYLUS_ENDPOINT:-https://sepolia-rollup.arbitrum.io/rpc}"
MAXFEE="${MAXFEE:-0.1}"

case "$CONTRACT" in
  urwa20)
    INIT_SIG="initialize(string,string,address)"
    INIT_ARGS=("uRWA Property" "uRWA" "$ADMIN")
    ;;
  urwa721)
    INIT_SIG="initialize(string,string,string,address)"
    INIT_ARGS=("uRWA Deed" "DEED" "ipfs://deeds/" "$ADMIN")
    ;;
  urwa1155)
    INIT_SIG="initialize(string,address)"
    INIT_ARGS=("ipfs://props/{id}.json" "$ADMIN")
    ;;
  *)
    echo "error: unknown contract '$CONTRACT' (expected urwa20, urwa721, or urwa1155)" >&2
    exit 1
    ;;
esac

[ -f "$WASM" ] || { echo "error: missing $WASM (run ./scripts/build-release.sh)" >&2; exit 1; }
[ -f "$KEY" ]  || { echo "error: missing key file $KEY" >&2; exit 1; }

echo ">> 1/2 deploying $CONTRACT (raw wasm, no constructor) to $ENDPOINT"
# Capture without letting `set -e` swallow the error before we can print it.
set +e
DEPLOY_OUT=$(cargo stylus deploy \
  --wasm-file "$WASM" \
  --endpoint "$ENDPOINT" \
  --private-key-path "$KEY" \
  --no-verify \
  --max-fee-per-gas-gwei "$MAXFEE" 2>&1)
DEPLOY_RC=$?
set -e
echo "$DEPLOY_OUT"
[ "$DEPLOY_RC" -eq 0 ] || { echo "error: cargo stylus deploy failed (exit $DEPLOY_RC); see output above" >&2; exit 1; }

ADDR=$(printf '%s' "$DEPLOY_OUT" | perl -pe 's/\x1b\[[0-9;]*m//g' | grep -oiE 'deployed code at address:? *0x[0-9a-fA-F]{40}' | grep -oiE '0x[0-9a-fA-F]{40}' | head -1)
[ -n "$ADDR" ] || { echo "error: could not parse the deployed address from the output above" >&2; exit 1; }
echo ">> deployed at $ADDR"

echo ">> 2/2 initializing (admin = $ADMIN)"
cast send "$ADDR" "$INIT_SIG" "${INIT_ARGS[@]}" \
  --rpc-url "$ENDPOINT" \
  --private-key "$(cat "$KEY")" >/dev/null
echo ">> initialized"

echo ""
echo "============================================================"
echo "  $CONTRACT  deployed + initialized"
echo "  address: $ADDR"
echo "  admin:   $ADMIN"
echo "============================================================"
echo "(if step 2 failed, the contract is deployed but uninitialized; re-initialize with:"
echo "  cast send $ADDR \"$INIT_SIG\" ${INIT_ARGS[*]} --rpc-url $ENDPOINT --private-key \"\$(cat $KEY)\")"
