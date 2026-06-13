# uRWA-Stylus

The first implementation of [ERC-7943](https://eips.ethereum.org/EIPS/eip-7943) (the "uRWA" Universal Real World Asset interface, Final as of 2026-05-27) in Rust for [Arbitrum Stylus](https://docs.arbitrum.io/stylus/gentle-introduction).

Built on the audited [`openzeppelin-stylus`](https://github.com/OpenZeppelin/rust-contracts-stylus) primitives (`Erc20` + `AccessControl`). RWA compliance checks (allowlists, freeze accounting) run on every transfer, mint, burn, and forced transfer, which is exactly the workload where Stylus WASM execution beats EVM bytecode on gas.

## Status

- `uRWA20` (fungible) implemented. ERC-721 and ERC-1155 variants are planned next.
- Hardened against two findings from an independent review of the Solidity reference implementation (see `../REPORT.md`):
  - `forced_transfer` is a no-op when `from == to` (does not corrupt freeze accounting).
  - `can_transfer` checks the unfrozen balance unconditionally (no view/execution divergence).
- ERC-20 metadata (name/symbol/decimals) is a planned follow-up; the core compliance logic is implemented first.

## License

This project is licensed under the **Business Source License 1.1** (`BUSL-1.1`); see `LICENSE`.

- **Change Date:** 2029-06-13. **Change License:** Apache-2.0.
- Non-commercial, evaluation, research, and testnet use are free. Production/commercial use requires a commercial license from the licensor until the Change Date.
- **Funding intent:** upon receiving grant funding for this work, the licensor intends to relicense the Licensed Work under the permissive dual **MIT OR Apache-2.0** terms ahead of the Change Date.

## Build status

Compiles to a **22.2 KB** deployable Stylus contract (under the 24 KB on-chain limit), validated against the live Arbitrum Sepolia network (activation data fee ~0.000149 ETH).

> Keep `Cargo.lock`: it pins `ruint = 1.14.0`. With the resolver's default `ruint 1.18`, `stylus-sdk 0.9.0` fails to compile (a `to_be_bytes::<32>` const-eval panic).

## Build

```bash
cargo build --release --target wasm32-unknown-unknown
```

## Test

13 behavioral tests (via the `motsu` host VM) cover the compliance guarantees and both hardenings:

```bash
cargo test
```

Coverage includes: role-gated mint/burn/freeze/forced-transfer, send/receive allowlist enforcement, freeze blocking over-unfrozen transfers, `frozen > balance` handling, the F2 hardening (a self-directed `forced_transfer` does not wipe the freeze), and the F3 hardening (`can_transfer` agrees with execution on over-balance amounts). Tests return `Result` and propagate with `?` (no `assert!`/`unwrap`).

## Validate deployability

```bash
cargo stylus check \
  --wasm-file target/wasm32-unknown-unknown/release/urwa_stylus.wasm \
  --endpoint https://sepolia-rollup.arbitrum.io/rpc
```

The `--wasm-file` flag validates the prebuilt artifact and skips cargo-stylus's `-Z build-std` reproducible rebuild (which is unrelated to deployability and is not needed for testnet).

## Deploy (Arbitrum Sepolia testnet)

Requires a funded Arbitrum Sepolia account (get testnet ETH from an Arbitrum Sepolia faucet). The constructor takes the initial admin address and grants it every role (admin, minter, burner, freezing, whitelist, force-transfer):

```bash
cargo stylus deploy \
  --wasm-file target/wasm32-unknown-unknown/release/urwa_stylus.wasm \
  --constructor-signature "constructor(address)" \
  --constructor-args <INITIAL_ADMIN_ADDRESS> \
  --endpoint https://sepolia-rollup.arbitrum.io/rpc \
  --private-key <YOUR_TESTNET_KEY> \
  --no-verify
```

## Known follow-ups

- ERC-20 metadata (name/symbol/decimals) extension.
- ERC-721 and ERC-1155 uRWA variants.
- Migrate off the now-deprecated `stylus_sdk::evm::log` / `msg::sender` helpers to the `.vm()` host API (currently 7 deprecation warnings, non-blocking).
