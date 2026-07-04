# uRWA-Stylus

Implementations of [ERC-7943](https://eips.ethereum.org/EIPS/eip-7943) (the "uRWA" Universal Real World Asset interface, Final as of 2026-05-27) in Rust for [Arbitrum Stylus](https://docs.arbitrum.io/stylus/gentle-introduction), built on the audited [`openzeppelin-stylus`](https://github.com/OpenZeppelin/rust-contracts-stylus) primitives.

RWA compliance checks (allowlists, freeze accounting) run on every transfer, mint, burn, and forced transfer, which is exactly the workload where Stylus WASM execution beats EVM bytecode on gas.

## Contracts

| Crate | Standard | ERC-7943 surface | Compressed size |
|-------|----------|------------------|-----------------|
| [`urwa20`](crates/urwa20) | ERC-20 + metadata | fungible (fractional shares) | 17.3 KB |
| [`urwa721`](crates/urwa721) | ERC-721 + metadata | non-fungible (deed / title) | 23.4 KB |
| [`urwa1155`](crates/urwa1155) | ERC-1155 + metadata URI | multi-token | 23.9 KB |

All three are under the 24 KB compressed Stylus limit and are **deployed and initialized on Arbitrum Sepolia** (chain 421614):

| Contract | Address |
|----------|---------|
| uRWA20 | [`0x735d109388684a400d83439ade432d8eb449db6a`](https://sepolia.arbiscan.io/address/0x735d109388684a400d83439ade432d8eb449db6a) |
| uRWA721 | [`0xaa9e84f4cf3d1c4ff0a6c629dc06334ca959f769`](https://sepolia.arbiscan.io/address/0xaa9e84f4cf3d1c4ff0a6c629dc06334ca959f769) |
| uRWA1155 | [`0x43afd2e684a9236ba04198f6c19236eb915fef16`](https://sepolia.arbiscan.io/address/0x43afd2e684a9236ba04198f6c19236eb915fef16) |

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

35 behavioral tests via the `motsu` host VM (16 for `urwa20`, 9 for `urwa721`, 10 for `urwa1155`), covering role-gating, allowlist enforcement, freeze semantics, the duplicate-id batch fix, the self-forced-transfer hardening, forced-transfer ownership checks, and metadata. Tests return `Result` and propagate with `?` (no `assert!`/`unwrap`).

`urwa20` and `urwa1155` additionally carry a **differential harness**: a faithful Rust model of the Solidity reference is driven alongside the real contract through a long seeded random op-sequence (800 and 700 steps respectively), asserting identical success/revert and state at every step. Dedicated tests show the harness catching the deliberate divergences (the self-forced-transfer hardening, and the duplicate-id frozen-bypass that this port fixes). The models run in the host VM rather than the EVM; their fidelity to the actual `.sol` source is what makes the comparison meaningful, so it was checked separately.

## Build (deployable)

A plain `cargo build --release` exceeds the 24 KB Stylus limit once metadata / ERC-1155 code is included. The deployable build needs build-std with the `immediate-abort` panic strategy plus `wasm-opt`; both are wrapped in:

```bash
./scripts/build-release.sh
```

This produces `target/wasm32-unknown-unknown/release/urwa20.opt.wasm` and `urwa1155.opt.wasm` and prints each compressed size.

## Deploy (Arbitrum Sepolia testnet)

Requires a funded Arbitrum Sepolia account, with its `0x`-prefixed private key in a file (e.g. `~/.urwa-deploy.key`, `chmod 600`).

Stylus `#[constructor]`s do **not** run when deploying a prebuilt wasm with `cargo stylus deploy --wasm-file` (the only path that fits the 24 KB limit), so each contract uses a guarded one-time `initialize()` instead. `scripts/deploy-sepolia.sh` does both steps: it deploys the wasm, then sends one `initialize` transaction granting every role (admin, minter, burner, freezing, whitelist, force-transfer) to `<admin>`:

```bash
./scripts/build-release.sh                          # produce the .opt.wasm artifacts
./scripts/deploy-sepolia.sh urwa20   <admin-address>
./scripts/deploy-sepolia.sh urwa721  <admin-address>
./scripts/deploy-sepolia.sh urwa1155 <admin-address>
```

Gotchas the script already handles, worth knowing if you deploy by hand:

- Pass `--max-fee-per-gas-gwei` with headroom; cargo-stylus's one-shot gas estimate otherwise races the block base fee and the node rejects the tx.
- Put `--constructor-args` (here, none) last; it greedily swallows any flags that follow it.
- The optimized wasm uses only the Stylus-supported wasm features, never `wasm-opt -all`, which injects reference types that fail activation.

## Known follow-ups

- A differential harness for `urwa721` (the ERC-20 and ERC-1155 variants have one).
- `urwa1155` omits `mintBatch` / `burnBatch` (not interface methods) so the URI metadata fits under the 24 KB limit (it lands at 24.0 KB). Restore them by trimming elsewhere if batch mint/burn is needed.
- Migrate off the deprecated `stylus_sdk::evm::log` / `msg::sender` helpers to the `.vm()` host API.
