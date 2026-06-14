# uRWA-Stylus

Implementations of [ERC-7943](https://eips.ethereum.org/EIPS/eip-7943) (the "uRWA" Universal Real World Asset interface, Final as of 2026-05-27) in Rust for [Arbitrum Stylus](https://docs.arbitrum.io/stylus/gentle-introduction), built on the audited [`openzeppelin-stylus`](https://github.com/OpenZeppelin/rust-contracts-stylus) primitives.

RWA compliance checks (allowlists, freeze accounting) run on every transfer, mint, burn, and forced transfer, which is exactly the workload where Stylus WASM execution beats EVM bytecode on gas.

## Contracts

| Crate | Standard | ERC-7943 surface | Compressed size |
|-------|----------|------------------|-----------------|
| [`urwa20`](crates/urwa20) | ERC-20 + metadata | fungible (fractional shares) | 17.3 KB |
| [`urwa721`](crates/urwa721) | ERC-721 + metadata | non-fungible (deed / title) | 23.3 KB |
| [`urwa1155`](crates/urwa1155) | ERC-1155 + metadata URI | multi-token | 24.0 KB |

Both are under the 24 KB compressed Stylus limit and were validated against the live Arbitrum Sepolia network (`cargo stylus check`).

Each implements send/receive allowlists, role-gated mint/burn (`AccessControl`), per-position freezing, `forcedTransfer` for compliance/recovery, and the `canSend` / `canReceive` / `getFrozenTokens` / `canTransfer` views.

### Divergences from the Solidity reference (deliberate fixes)

These close findings from an independent review of the ERC-7943 Solidity reference implementation:

- **uRWA1155 `safe_batch_transfer_from`** validates each token id against the *accumulated* amount requested for that id across the whole batch. In the reference, repeating an id in one batch bypasses the per-id frozen check and drains frozen tokens; that bug is absent here (test: `duplicate_id_batch_cannot_bypass_freeze`).
- **`forced_transfer`** is a no-op when `from == to`, so a self-directed seizure cannot zero the freeze accounting while the holder keeps the tokens.
- **`can_transfer`** reflects true feasibility (unfrozen balance / ownership), so it never disagrees with what an actual transfer does.
- **uRWA721 `forced_transfer`** seizes via the base `_update` with no receiver-acceptance check, so a compliance seizure into an allowlisted custody destination cannot be blocked by that destination failing to implement `onERC721Received`.

## License

Business Source License 1.1 (`BUSL-1.1`); see [`LICENSE`](LICENSE).

- **Change Date:** 2029-06-13. **Change License:** Apache-2.0.
- Non-commercial, evaluation, research, and testnet use are free. Production/commercial use requires a commercial license from the licensor until the Change Date.
- **Funding intent:** upon receiving grant funding for this work, the licensor intends to relicense under the permissive dual **MIT OR Apache-2.0** terms ahead of the Change Date.

## Toolchain

```bash
rustup component add rust-src
rustup target add wasm32-unknown-unknown
brew install binaryen        # provides wasm-opt
cargo install cargo-stylus
```

> No `Cargo.lock` is committed. The two transitive dependencies that would otherwise break the build are pinned exactly in the manifests (`ruint = 1.14.0`, needed by `stylus-sdk 0.9.0`; `arbitrary` / `derive_arbitrary = 1.4.1`, needed by the test build), so a fresh `cargo` resolve always works.

## Test

```bash
cargo test
```

31 behavioral tests via the `motsu` host VM (14 for `urwa20`, 9 for `urwa721`, 8 for `urwa1155`), covering role-gating, allowlist enforcement, freeze semantics, the duplicate-id batch fix, the self-forced-transfer hardening, forced-transfer ownership checks, and metadata. Tests return `Result` and propagate with `?` (no `assert!`/`unwrap`).

## Build (deployable)

A plain `cargo build --release` exceeds the 24 KB Stylus limit once metadata / ERC-1155 code is included. The deployable build needs build-std with the `immediate-abort` panic strategy plus `wasm-opt`; both are wrapped in:

```bash
./scripts/build-release.sh
```

This produces `target/wasm32-unknown-unknown/release/urwa20.opt.wasm` and `urwa1155.opt.wasm` and prints each compressed size.

## Deploy (Arbitrum Sepolia testnet)

Requires a funded Arbitrum Sepolia account. The constructor grants the initial admin every role (admin, minter, burner, freezing, whitelist, force-transfer).

uRWA-20 (`constructor(string name, string symbol, address admin)`):

```bash
cargo stylus deploy \
  --wasm-file target/wasm32-unknown-unknown/release/urwa20.opt.wasm \
  --constructor-signature "constructor(string,string,address)" \
  --constructor-args "uRWA Property" "uRWA" <INITIAL_ADMIN_ADDRESS> \
  --endpoint https://sepolia-rollup.arbitrum.io/rpc \
  --private-key <YOUR_TESTNET_KEY> \
  --no-verify
```

uRWA-1155 (`constructor(string uri, address admin)`):

```bash
cargo stylus deploy \
  --wasm-file target/wasm32-unknown-unknown/release/urwa1155.opt.wasm \
  --constructor-signature "constructor(string,address)" \
  --constructor-args "ipfs://your-cdn/{id}.json" <INITIAL_ADMIN_ADDRESS> \
  --endpoint https://sepolia-rollup.arbitrum.io/rpc \
  --private-key <YOUR_TESTNET_KEY> \
  --no-verify
```

uRWA-721 (`constructor(string name, string symbol, string baseURI, address admin)`):

```bash
cargo stylus deploy \
  --wasm-file target/wasm32-unknown-unknown/release/urwa721.opt.wasm \
  --constructor-signature "constructor(string,string,string,address)" \
  --constructor-args "uRWA Deed" "DEED" "ipfs://your-cdn/deeds/" <INITIAL_ADMIN_ADDRESS> \
  --endpoint https://sepolia-rollup.arbitrum.io/rpc \
  --private-key <YOUR_TESTNET_KEY> \
  --no-verify
```

## Known follow-ups

- A differential-test harness (Rust vs the Solidity reference).
- `urwa1155` omits `mintBatch` / `burnBatch` (not interface methods) so the URI metadata fits under the 24 KB limit (it lands at 24.0 KB). Restore them by trimming elsewhere if batch mint/burn is needed.
- Migrate off the deprecated `stylus_sdk::evm::log` / `msg::sender` helpers to the `.vm()` host API.
