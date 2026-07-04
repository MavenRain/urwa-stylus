#![cfg_attr(not(any(test, feature = "export-abi")), no_main)]
//! uRWA-20: an ERC-7943 (uRWA) fungible Real World Asset token for Arbitrum Stylus.
//!
//! Built on the audited `openzeppelin-stylus` primitives (`Erc20` + `AccessControl`).
//! Implements the ERC-7943 fungible interface: send/receive allowlists, role-gated
//! mint/burn, per-account freezing, and privileged forced transfer for compliance
//! and recovery.
//!
//! Two divergences from the Solidity reference implementation are deliberate
//! hardenings, each closing a finding from the accompanying review of that
//! reference (see REPORT.md in the parent project):
//!   * `forced_transfer` is a no-op when `from == to`, so a self-directed seizure
//!     cannot zero the freeze accounting while the holder keeps the tokens (F2).
//!   * `can_transfer` checks the unfrozen balance unconditionally, so it never
//!     reports `true` for an amount the account cannot actually move (F3).
extern crate alloc;

use alloc::{string::String, vec::Vec};

use alloy_sol_types::sol;
use openzeppelin_stylus::{
    access::control::{self, AccessControl, IAccessControl},
    token::erc20::{
        self,
        extensions::{Erc20Metadata, IErc20Metadata},
        Erc20, IErc20,
    },
    utils::introspection::erc165::IErc165,
};
use stylus_sdk::{
    alloy_primitives::{aliases::B32, Address, B256, U8, U256},
    evm, msg,
    prelude::*,
    storage::{StorageBool, StorageMap, StorageU256},
};

sol! {
    /// Emitted when an account's send-allowlist status changes.
    event SendWhitelisted(address indexed account, bool status);
    /// Emitted when an account's receive-allowlist status changes.
    event ReceiveWhitelisted(address indexed account, bool status);
    /// Emitted when the frozen amount for an account changes.
    event Frozen(address indexed account, uint256 amount);
    /// Emitted when tokens are seized from one account and moved to another.
    event ForcedTransfer(address indexed from, address indexed to, uint256 amount);

    /// The account is not allowed to send tokens.
    error ERC7943CannotSend(address account);
    /// The account is not allowed to receive tokens.
    error ERC7943CannotReceive(address account);
    /// The transfer is disallowed by token rules.
    error ERC7943CannotTransfer(address from, address to, uint256 amount);
    /// The amount exceeds the account's unfrozen balance.
    error ERC7943InsufficientUnfrozenBalance(address account, uint256 amount, uint256 unfrozen);

    /// `initialize` has already been called.
    error AlreadyInitialized();
}

/// Aggregated error type surfaced by the contract's external methods.
#[derive(SolidityError)]
enum Error {
    UnauthorizedAccount(control::AccessControlUnauthorizedAccount),
    BadConfirmation(control::AccessControlBadConfirmation),
    InsufficientBalance(erc20::ERC20InsufficientBalance),
    InvalidSender(erc20::ERC20InvalidSender),
    InvalidReceiver(erc20::ERC20InvalidReceiver),
    InsufficientAllowance(erc20::ERC20InsufficientAllowance),
    InvalidSpender(erc20::ERC20InvalidSpender),
    InvalidApprover(erc20::ERC20InvalidApprover),
    CannotSend(ERC7943CannotSend),
    CannotReceive(ERC7943CannotReceive),
    CannotTransfer(ERC7943CannotTransfer),
    InsufficientUnfrozenBalance(ERC7943InsufficientUnfrozenBalance),
    AlreadyInitialized(AlreadyInitialized),
}

impl From<control::Error> for Error {
    fn from(value: control::Error) -> Self {
        match value {
            control::Error::UnauthorizedAccount(e) => Error::UnauthorizedAccount(e),
            control::Error::BadConfirmation(e) => Error::BadConfirmation(e),
        }
    }
}

impl From<erc20::Error> for Error {
    fn from(value: erc20::Error) -> Self {
        match value {
            erc20::Error::InsufficientBalance(e) => Error::InsufficientBalance(e),
            erc20::Error::InvalidSender(e) => Error::InvalidSender(e),
            erc20::Error::InvalidReceiver(e) => Error::InvalidReceiver(e),
            erc20::Error::InsufficientAllowance(e) => Error::InsufficientAllowance(e),
            erc20::Error::InvalidSpender(e) => Error::InvalidSpender(e),
            erc20::Error::InvalidApprover(e) => Error::InvalidApprover(e),
        }
    }
}

/// Role identifiers, matching the Solidity reference's `keccak256("...")` constants.
pub const MINTER_ROLE: [u8; 32] =
    keccak_const::Keccak256::new().update(b"MINTER_ROLE").finalize();
pub const BURNER_ROLE: [u8; 32] =
    keccak_const::Keccak256::new().update(b"BURNER_ROLE").finalize();
pub const FREEZING_ROLE: [u8; 32] =
    keccak_const::Keccak256::new().update(b"FREEZING_ROLE").finalize();
pub const WHITELIST_ROLE: [u8; 32] =
    keccak_const::Keccak256::new().update(b"WHITELIST_ROLE").finalize();
pub const FORCE_TRANSFER_ROLE: [u8; 32] =
    keccak_const::Keccak256::new().update(b"FORCE_TRANSFER_ROLE").finalize();

#[entrypoint]
#[storage]
struct URWA20 {
    erc20: Erc20,
    access: AccessControl,
    metadata: Erc20Metadata,
    initialized: StorageBool,
    send_whitelist: StorageMap<Address, StorageBool>,
    receive_whitelist: StorageMap<Address, StorageBool>,
    frozen: StorageMap<Address, StorageU256>,
}

#[public]
#[implements(IErc20<Error = Error>, IErc20Metadata, IAccessControl<Error = control::Error>, IErc165)]
impl URWA20 {
    /// One-time initializer: sets metadata and grants every role to `initial_admin`.
    /// Used instead of a Stylus `#[constructor]` because constructors do not run when
    /// deploying the prebuilt wasm via `cargo stylus deploy --wasm-file` (the only path that
    /// fits the 24 KB size limit). Call this once, immediately after deployment.
    fn initialize(&mut self, name: String, symbol: String, initial_admin: Address) -> Result<(), Error> {
        (!self.initialized.get())
            .then_some(())
            .ok_or(Error::AlreadyInitialized(AlreadyInitialized {}))?;
        self.initialized.set(true);
        self.metadata.constructor(name, symbol);
        self.access._grant_role(AccessControl::DEFAULT_ADMIN_ROLE.into(), initial_admin);
        self.access._grant_role(MINTER_ROLE.into(), initial_admin);
        self.access._grant_role(BURNER_ROLE.into(), initial_admin);
        self.access._grant_role(FREEZING_ROLE.into(), initial_admin);
        self.access._grant_role(WHITELIST_ROLE.into(), initial_admin);
        self.access._grant_role(FORCE_TRANSFER_ROLE.into(), initial_admin);
        Ok(())
    }

    /// Whether `account` may send tokens (send-allowlist membership).
    fn can_send(&self, account: Address) -> bool {
        self.send_whitelist.get(account)
    }

    /// Whether `account` may receive tokens (receive-allowlist membership).
    fn can_receive(&self, account: Address) -> bool {
        self.receive_whitelist.get(account)
    }

    /// The frozen token amount for `account` (may exceed its balance, by design).
    fn get_frozen_tokens(&self, account: Address) -> U256 {
        self.frozen.get(account)
    }

    /// Whether an ordinary transfer of `amount` from `from` to `to` would be allowed.
    /// Reflects true feasibility (unfrozen balance and both allowlists), so it never
    /// disagrees with what `transfer`/`transfer_from` actually do.
    fn can_transfer(&self, from: Address, to: Address, amount: U256) -> bool {
        amount <= self.unfrozen_balance(from) && self.can_send(from) && self.can_receive(to)
    }

    /// Set the send-allowlist status for `account`. Requires `WHITELIST_ROLE`.
    fn change_send_whitelist(&mut self, account: Address, status: bool) -> Result<(), Error> {
        self.access.only_role(WHITELIST_ROLE.into())?;
        self.send_whitelist.setter(account).set(status);
        evm::log(SendWhitelisted { account, status });
        Ok(())
    }

    /// Set the receive-allowlist status for `account`. Requires `WHITELIST_ROLE`.
    fn change_receive_whitelist(&mut self, account: Address, status: bool) -> Result<(), Error> {
        self.access.only_role(WHITELIST_ROLE.into())?;
        self.receive_whitelist.setter(account).set(status);
        evm::log(ReceiveWhitelisted { account, status });
        Ok(())
    }

    /// Mint `amount` to `to`. Requires `MINTER_ROLE` and `to` on the receive-allowlist.
    fn mint(&mut self, to: Address, amount: U256) -> Result<(), Error> {
        self.access.only_role(MINTER_ROLE.into())?;
        self.can_receive(to)
            .then_some(())
            .ok_or(Error::CannotReceive(ERC7943CannotReceive { account: to }))?;
        self.erc20._mint(to, amount)?;
        Ok(())
    }

    /// Burn `amount` from the caller. Requires `BURNER_ROLE` and caller on the send-allowlist.
    fn burn(&mut self, amount: U256) -> Result<(), Error> {
        self.access.only_role(BURNER_ROLE.into())?;
        let from = msg::sender();
        self.can_send(from)
            .then_some(())
            .ok_or(Error::CannotSend(ERC7943CannotSend { account: from }))?;
        self.excess_frozen_update(from, amount);
        self.erc20._burn(from, amount)?;
        Ok(())
    }

    /// Overwrite the frozen amount for `account`. Requires `FREEZING_ROLE`.
    fn set_frozen_tokens(&mut self, account: Address, amount: U256) -> Result<(), Error> {
        self.access.only_role(FREEZING_ROLE.into())?;
        self.frozen.setter(account).set(amount);
        evm::log(Frozen { account, amount });
        Ok(())
    }

    /// Seize `amount` from `from` and deliver to `to`, bypassing send rules.
    /// Requires `FORCE_TRANSFER_ROLE` and `to` on the receive-allowlist.
    fn forced_transfer(&mut self, from: Address, to: Address, amount: U256) -> Result<(), Error> {
        self.access.only_role(FORCE_TRANSFER_ROLE.into())?;
        (!to.is_zero())
            .then_some(())
            .ok_or(Error::InvalidReceiver(erc20::ERC20InvalidReceiver { receiver: Address::ZERO }))?;
        (!from.is_zero())
            .then_some(())
            .ok_or(Error::InvalidSender(erc20::ERC20InvalidSender { sender: Address::ZERO }))?;
        self.can_receive(to)
            .then_some(())
            .ok_or(Error::CannotReceive(ERC7943CannotReceive { account: to }))?;
        // Hardening (F2): a self-directed seizure moves nothing and must not corrupt
        // the freeze accounting, so skip both the freeze adjustment and the no-op move.
        (from != to)
            .then(|| {
                self.excess_frozen_update(from, amount);
                self.erc20._update(from, to, amount)
            })
            .transpose()?;
        evm::log(ForcedTransfer { from, to, amount });
        Ok(())
    }
}

impl URWA20 {
    /// Balance minus frozen amount, saturating at zero.
    fn unfrozen_balance(&self, account: Address) -> U256 {
        let balance = self.erc20.balance_of(account);
        let frozen = self.frozen.get(account);
        balance.checked_sub(frozen).unwrap_or(U256::ZERO)
    }

    /// Reduce the frozen counter when `amount` leaves `account` beyond its unfrozen
    /// balance (forced transfer or burn), keeping frozen consistent with the new balance.
    fn excess_frozen_update(&mut self, account: Address, amount: U256) {
        let unfrozen = self.unfrozen_balance(account);
        let balance = self.erc20.balance_of(account);
        (amount > unfrozen && amount <= balance)
            .then(|| {
                let current = self.frozen.get(account);
                let next = current.checked_sub(amount - unfrozen).unwrap_or(U256::ZERO);
                self.frozen.setter(account).set(next);
                evm::log(Frozen { account, amount: next });
            });
    }

    /// Enforce ordinary-transfer rules: unfrozen balance, then both allowlists.
    fn enforce_transfer(&self, from: Address, to: Address, amount: U256) -> Result<(), Error> {
        let unfrozen = self.unfrozen_balance(from);
        match (amount <= unfrozen, self.can_send(from), self.can_receive(to)) {
            (false, _, _) => Err(Error::InsufficientUnfrozenBalance(
                ERC7943InsufficientUnfrozenBalance { account: from, amount, unfrozen },
            )),
            (true, false, _) => Err(Error::CannotSend(ERC7943CannotSend { account: from })),
            (true, true, false) => Err(Error::CannotReceive(ERC7943CannotReceive { account: to })),
            (true, true, true) => Ok(()),
        }
    }
}

#[public]
impl IErc20 for URWA20 {
    type Error = Error;

    fn total_supply(&self) -> U256 {
        self.erc20.total_supply()
    }

    fn balance_of(&self, account: Address) -> U256 {
        self.erc20.balance_of(account)
    }

    fn transfer(&mut self, to: Address, value: U256) -> Result<bool, Error> {
        let from = msg::sender();
        self.enforce_transfer(from, to, value)?;
        Ok(self.erc20.transfer(to, value)?)
    }

    fn allowance(&self, owner: Address, spender: Address) -> U256 {
        self.erc20.allowance(owner, spender)
    }

    fn approve(&mut self, spender: Address, value: U256) -> Result<bool, Error> {
        Ok(self.erc20.approve(spender, value)?)
    }

    fn transfer_from(&mut self, from: Address, to: Address, value: U256) -> Result<bool, Error> {
        self.enforce_transfer(from, to, value)?;
        Ok(self.erc20.transfer_from(from, to, value)?)
    }
}

#[public]
impl IErc20Metadata for URWA20 {
    fn name(&self) -> String {
        self.metadata.name()
    }

    fn symbol(&self) -> String {
        self.metadata.symbol()
    }

    fn decimals(&self) -> U8 {
        self.metadata.decimals()
    }
}

#[public]
impl IAccessControl for URWA20 {
    type Error = control::Error;

    fn has_role(&self, role: B256, account: Address) -> bool {
        self.access.has_role(role, account)
    }

    fn only_role(&self, role: B256) -> Result<(), Self::Error> {
        self.access.only_role(role)
    }

    fn get_role_admin(&self, role: B256) -> B256 {
        self.access.get_role_admin(role)
    }

    fn grant_role(&mut self, role: B256, account: Address) -> Result<(), Self::Error> {
        let admin_role = self.access.get_role_admin(role);
        self.access.only_role(admin_role)?;
        self.access._grant_role(role, account);
        Ok(())
    }

    fn revoke_role(&mut self, role: B256, account: Address) -> Result<(), Self::Error> {
        let admin_role = self.access.get_role_admin(role);
        self.access.only_role(admin_role)?;
        self.access._revoke_role(role, account);
        Ok(())
    }

    #[allow(deprecated)]
    fn renounce_role(&mut self, role: B256, confirmation: Address) -> Result<(), Self::Error> {
        (msg::sender() == confirmation)
            .then_some(())
            .ok_or(control::Error::BadConfirmation(control::AccessControlBadConfirmation {}))?;
        self.access._revoke_role(role, confirmation);
        Ok(())
    }
}

#[public]
impl IErc165 for URWA20 {
    fn supports_interface(&self, interface_id: B32) -> bool {
        self.access.supports_interface(interface_id)
            || self.erc20.supports_interface(interface_id)
            || self.metadata.supports_interface(interface_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use motsu::prelude::*;

    /// Test-local failure type so tests propagate with `?` instead of panicking,
    /// honoring the no-panic-in-tests convention (no assert!/unwrap/expect).
    #[derive(Debug)]
    #[allow(dead_code)]
    struct TestErr(&'static str);

    /// Assert a condition without panicking.
    fn ensure(cond: bool, msg: &'static str) -> Result<(), TestErr> {
        cond.then_some(()).ok_or(TestErr(msg))
    }

    /// Convert any contract error into a test failure, discarding the (non-Debug) inner error.
    trait OrTest<T> {
        fn ortest(self, msg: &'static str) -> Result<T, TestErr>;
    }
    impl<T, E> OrTest<T> for Result<T, E> {
        fn ortest(self, msg: &'static str) -> Result<T, TestErr> {
            self.map_err(|_| TestErr(msg))
        }
    }

    fn n(x: u64) -> U256 {
        U256::from(x)
    }

    /// Initialize the contract and allowlist `who` for both send and receive.
    fn setup_allowlisted(
        contract: &Contract<URWA20>,
        admin: Address,
        who: Address,
    ) -> Result<(), TestErr> {
        // Idempotent: the first call initializes (granting admin the roles); later calls
        // harmlessly hit AlreadyInitialized, which we ignore so the helper works per-address.
        let _ = contract.sender(admin).initialize("uRWA Test".into(), "URWA".into(), admin);
        contract.sender(admin).change_send_whitelist(who, true).ortest("send wl")?;
        contract.sender(admin).change_receive_whitelist(who, true).ortest("recv wl")?;
        Ok(())
    }

    #[motsu::test]
    fn constructor_grants_all_roles(contract: Contract<URWA20>, admin: Address) -> Result<(), TestErr> {
        contract.sender(admin).initialize("uRWA Test".into(), "URWA".into(), admin).ortest("init")?;
        let c = contract.sender(admin);
        ensure(c.has_role(MINTER_ROLE.into(), admin), "MINTER")?;
        ensure(c.has_role(BURNER_ROLE.into(), admin), "BURNER")?;
        ensure(c.has_role(FREEZING_ROLE.into(), admin), "FREEZING")?;
        ensure(c.has_role(WHITELIST_ROLE.into(), admin), "WHITELIST")?;
        ensure(c.has_role(FORCE_TRANSFER_ROLE.into(), admin), "FORCE_TRANSFER")?;
        ensure(c.has_role(AccessControl::DEFAULT_ADMIN_ROLE.into(), admin), "DEFAULT_ADMIN")?;
        Ok(())
    }

    #[motsu::test]
    fn metadata_is_set(contract: Contract<URWA20>, admin: Address) -> Result<(), TestErr> {
        contract.sender(admin).initialize("uRWA Real Estate".into(), "uRWA".into(), admin).ortest("init")?;
        ensure(contract.sender(admin).name() == "uRWA Real Estate", "name")?;
        ensure(contract.sender(admin).symbol() == "uRWA", "symbol")?;
        ensure(contract.sender(admin).decimals() == U8::from(18), "decimals 18")?;
        Ok(())
    }

    #[motsu::test]
    fn whitelisted_transfer_succeeds(
        contract: Contract<URWA20>,
        admin: Address,
        holder: Address,
        dest: Address,
    ) -> Result<(), TestErr> {
        setup_allowlisted(&contract, admin, holder)?;
        setup_allowlisted(&contract, admin, dest)?;
        contract.sender(admin).mint(holder, n(100)).ortest("mint")?;
        contract.sender(holder).transfer(dest, n(40)).ortest("transfer")?;
        ensure(contract.sender(admin).balance_of(holder) == n(60), "holder 60")?;
        ensure(contract.sender(admin).balance_of(dest) == n(40), "dest 40")?;
        Ok(())
    }

    #[motsu::test]
    fn transfer_from_non_send_whitelisted_reverts(
        contract: Contract<URWA20>,
        admin: Address,
        holder: Address,
        dest: Address,
    ) -> Result<(), TestErr> {
        contract.sender(admin).initialize("uRWA Test".into(), "URWA".into(), admin).ortest("init")?;
        // holder can receive (so it can be minted to) but is NOT send-allowlisted.
        contract.sender(admin).change_receive_whitelist(holder, true).ortest("recv wl")?;
        setup_allowlisted(&contract, admin, dest)?;
        contract.sender(admin).mint(holder, n(100)).ortest("mint")?;
        ensure(contract.sender(holder).transfer(dest, n(10)).is_err(), "send-blocked transfer must revert")?;
        ensure(contract.sender(admin).balance_of(holder) == n(100), "balance unchanged")?;
        Ok(())
    }

    #[motsu::test]
    fn transfer_to_non_receive_whitelisted_reverts(
        contract: Contract<URWA20>,
        admin: Address,
        holder: Address,
        dest: Address,
    ) -> Result<(), TestErr> {
        setup_allowlisted(&contract, admin, holder)?;
        contract.sender(admin).mint(holder, n(100)).ortest("mint")?;
        // dest is not receive-allowlisted.
        ensure(contract.sender(holder).transfer(dest, n(10)).is_err(), "transfer to non-allowlisted must revert")?;
        Ok(())
    }

    #[motsu::test]
    fn freeze_blocks_over_unfrozen_transfer(
        contract: Contract<URWA20>,
        admin: Address,
        holder: Address,
        dest: Address,
    ) -> Result<(), TestErr> {
        setup_allowlisted(&contract, admin, holder)?;
        setup_allowlisted(&contract, admin, dest)?;
        contract.sender(admin).mint(holder, n(100)).ortest("mint")?;
        contract.sender(admin).set_frozen_tokens(holder, n(50)).ortest("freeze")?;
        // 60 > unfrozen 50 reverts; 50 succeeds.
        ensure(contract.sender(holder).transfer(dest, n(60)).is_err(), "over-unfrozen reverts")?;
        contract.sender(holder).transfer(dest, n(50)).ortest("at-unfrozen ok")?;
        ensure(contract.sender(admin).balance_of(holder) == n(50), "holder 50 left")?;
        ensure(contract.sender(admin).get_frozen_tokens(holder) == n(50), "still frozen 50")?;
        Ok(())
    }

    /// Hardening F3: `can_transfer` must agree with execution, including the
    /// over-balance case when nothing is frozen (the Solidity reference returns
    /// true here while the transfer reverts).
    #[motsu::test]
    fn can_transfer_matches_execution_over_balance(
        contract: Contract<URWA20>,
        admin: Address,
        holder: Address,
        dest: Address,
    ) -> Result<(), TestErr> {
        setup_allowlisted(&contract, admin, holder)?;
        setup_allowlisted(&contract, admin, dest)?;
        contract.sender(admin).mint(holder, n(50)).ortest("mint")?;
        // frozen == 0, balance == 50.
        ensure(!contract.sender(holder).can_transfer(holder, dest, n(100)), "can_transfer(100) false")?;
        ensure(contract.sender(holder).transfer(dest, n(100)).is_err(), "transfer(100) reverts")?;
        ensure(contract.sender(holder).can_transfer(holder, dest, n(50)), "can_transfer(50) true")?;
        Ok(())
    }

    /// Hardening F2: a self-directed forced transfer is a no-op that must NOT
    /// wipe the freeze (the Solidity reference zeroes the frozen counter here).
    #[motsu::test]
    fn self_forced_transfer_preserves_freeze(
        contract: Contract<URWA20>,
        admin: Address,
        holder: Address,
        dest: Address,
    ) -> Result<(), TestErr> {
        setup_allowlisted(&contract, admin, holder)?;
        setup_allowlisted(&contract, admin, dest)?;
        contract.sender(admin).mint(holder, n(100)).ortest("mint")?;
        contract.sender(admin).set_frozen_tokens(holder, n(80)).ortest("freeze")?;
        // Self-seizure: must change nothing.
        contract.sender(admin).forced_transfer(holder, holder, n(80)).ortest("self forced")?;
        ensure(contract.sender(admin).get_frozen_tokens(holder) == n(80), "freeze intact (not zeroed)")?;
        ensure(contract.sender(admin).balance_of(holder) == n(100), "balance intact")?;
        // The freeze is still enforced: only 20 is movable.
        ensure(contract.sender(holder).transfer(dest, n(21)).is_err(), "freeze still binds (>20 reverts)")?;
        contract.sender(holder).transfer(dest, n(20)).ortest("20 unfrozen ok")?;
        Ok(())
    }

    #[motsu::test]
    fn forced_transfer_seizes_from_blocked_holder(
        contract: Contract<URWA20>,
        admin: Address,
        holder: Address,
        dest: Address,
    ) -> Result<(), TestErr> {
        setup_allowlisted(&contract, admin, holder)?;
        setup_allowlisted(&contract, admin, dest)?;
        contract.sender(admin).mint(holder, n(100)).ortest("mint")?;
        // Blocklist the holder's send rights; a normal transfer now fails.
        contract.sender(admin).change_send_whitelist(holder, false).ortest("blocklist")?;
        ensure(contract.sender(holder).transfer(dest, n(10)).is_err(), "blocked holder cannot send")?;
        // But the operator can still seize.
        contract.sender(admin).forced_transfer(holder, dest, n(100)).ortest("seize")?;
        ensure(contract.sender(admin).balance_of(holder) == n(0), "holder seized to 0")?;
        ensure(contract.sender(admin).balance_of(dest) == n(100), "dest received 100")?;
        Ok(())
    }

    #[motsu::test]
    fn forced_transfer_requires_receive_whitelist_on_to(
        contract: Contract<URWA20>,
        admin: Address,
        holder: Address,
        dest: Address,
    ) -> Result<(), TestErr> {
        setup_allowlisted(&contract, admin, holder)?;
        contract.sender(admin).mint(holder, n(100)).ortest("mint")?;
        // dest is not receive-allowlisted.
        ensure(contract.sender(admin).forced_transfer(holder, dest, n(10)).is_err(), "to must be allowlisted")?;
        Ok(())
    }

    #[motsu::test]
    fn privileged_actions_are_role_gated(
        contract: Contract<URWA20>,
        admin: Address,
        holder: Address,
        mallory: Address,
    ) -> Result<(), TestErr> {
        setup_allowlisted(&contract, admin, holder)?;
        contract.sender(admin).mint(holder, n(100)).ortest("mint")?;
        // mallory holds no roles.
        ensure(contract.sender(mallory).set_frozen_tokens(holder, n(10)).is_err(), "freeze gated")?;
        ensure(contract.sender(mallory).forced_transfer(holder, holder, n(10)).is_err(), "force gated")?;
        ensure(contract.sender(mallory).change_send_whitelist(mallory, true).is_err(), "whitelist gated")?;
        ensure(contract.sender(mallory).mint(mallory, n(10)).is_err(), "mint gated")?;
        Ok(())
    }

    #[motsu::test]
    fn mint_requires_receive_whitelist(
        contract: Contract<URWA20>,
        admin: Address,
        holder: Address,
    ) -> Result<(), TestErr> {
        contract.sender(admin).initialize("uRWA Test".into(), "URWA".into(), admin).ortest("init")?;
        // holder not allowlisted yet: mint must fail.
        ensure(contract.sender(admin).mint(holder, n(100)).is_err(), "mint to non-allowlisted reverts")?;
        contract.sender(admin).change_receive_whitelist(holder, true).ortest("recv wl")?;
        contract.sender(admin).mint(holder, n(100)).ortest("mint ok")?;
        ensure(contract.sender(admin).balance_of(holder) == n(100), "minted 100")?;
        Ok(())
    }

    #[motsu::test]
    fn burn_clears_excess_frozen(
        contract: Contract<URWA20>,
        admin: Address,
        holder: Address,
    ) -> Result<(), TestErr> {
        setup_allowlisted(&contract, admin, holder)?;
        contract.sender(admin).mint(holder, n(100)).ortest("mint")?;
        contract.sender(admin).set_frozen_tokens(holder, n(100)).ortest("freeze all")?;
        // admin holds BURNER_ROLE and is send-allowlisted via... admin is not allowlisted; burn uses caller.
        // Grant the holder BURNER_ROLE so it can burn its own (already send-allowlisted) tokens.
        contract.sender(admin).grant_role(BURNER_ROLE.into(), holder).ortest("grant burner")?;
        contract.sender(holder).burn(n(100)).ortest("burn")?;
        ensure(contract.sender(admin).balance_of(holder) == n(0), "burned to 0")?;
        ensure(contract.sender(admin).get_frozen_tokens(holder) == n(0), "frozen cleared on empty")?;
        Ok(())
    }

    #[motsu::test]
    fn set_frozen_may_exceed_balance(
        contract: Contract<URWA20>,
        admin: Address,
        holder: Address,
        dest: Address,
    ) -> Result<(), TestErr> {
        setup_allowlisted(&contract, admin, holder)?;
        setup_allowlisted(&contract, admin, dest)?;
        contract.sender(admin).mint(holder, n(50)).ortest("mint")?;
        // Spec permits frozen > balance.
        contract.sender(admin).set_frozen_tokens(holder, n(80)).ortest("over-freeze")?;
        ensure(contract.sender(admin).get_frozen_tokens(holder) == n(80), "frozen 80")?;
        ensure(!contract.sender(holder).can_transfer(holder, dest, n(1)), "nothing transferable")?;
        ensure(contract.sender(holder).transfer(dest, n(1)).is_err(), "even 1 reverts")?;
        Ok(())
    }

    // ---------------------------------------------------------------------------------
    // Differential harness: the real uRWA20 (run via motsu) vs a faithful Rust model of
    // the Solidity reference `uRWA20.sol`. A seeded random op-sequence is applied to both;
    // they must agree on success/revert and resulting state at every step. The walk stays
    // in the "equivalence region" (it never generates a self-directed forced transfer, the
    // one documented hardening); that divergence is asserted explicitly afterwards.
    // ---------------------------------------------------------------------------------

    use alloc::collections::{BTreeMap, BTreeSet};

    /// Tiny deterministic LCG so runs are reproducible without an external rng dependency.
    struct Lcg(u64);
    impl Lcg {
        fn new(seed: u64) -> Self {
            Lcg(seed)
        }
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            self.0 >> 16
        }
        fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }
    }

    #[derive(Clone, Copy)]
    enum Op {
        SetSendWl { acct: Address, status: bool, by: Address },
        SetRecvWl { acct: Address, status: bool, by: Address },
        Mint { to: Address, amt: u128, by: Address },
        Freeze { acct: Address, amt: u128, by: Address },
        Transfer { from: Address, to: Address, amt: u128 },
        TransferFrom { spender: Address, from: Address, to: Address, amt: u128 },
        Approve { owner: Address, spender: Address, amt: u128 },
        ForcedTransfer { from: Address, to: Address, amt: u128, by: Address },
        Burn { amt: u128, by: Address },
    }

    /// Faithful model of the Solidity reference `uRWA20`. Only `admin` holds roles.
    struct Ref20 {
        admin: Address,
        bal: BTreeMap<Address, u128>,
        frozen: BTreeMap<Address, u128>,
        allow: BTreeMap<(Address, Address), u128>,
        send: BTreeSet<Address>,
        recv: BTreeSet<Address>,
    }

    impl Ref20 {
        fn new(admin: Address) -> Self {
            Ref20 {
                admin,
                bal: BTreeMap::new(),
                frozen: BTreeMap::new(),
                allow: BTreeMap::new(),
                send: BTreeSet::new(),
                recv: BTreeSet::new(),
            }
        }
        fn b(&self, a: Address) -> u128 {
            *self.bal.get(&a).unwrap_or(&0)
        }
        fn f(&self, a: Address) -> u128 {
            *self.frozen.get(&a).unwrap_or(&0)
        }
        fn unfrozen(&self, a: Address) -> u128 {
            let (bal, frz) = (self.b(a), self.f(a));
            if bal < frz { 0 } else { bal - frz }
        }
        fn allowance(&self, owner: Address, spender: Address) -> u128 {
            *self.allow.get(&(owner, spender)).unwrap_or(&0)
        }
        /// The reference's `_excessFrozenUpdate`: reduce frozen by the amount leaving beyond unfrozen.
        fn excess_frozen_update(&mut self, a: Address, amt: u128) {
            let unfrozen = self.unfrozen(a);
            let bal = self.b(a);
            if amt > unfrozen && amt <= bal {
                let next = self.f(a) - (amt - unfrozen);
                self.frozen.insert(a, next);
            }
        }
        /// Apply `op`; returns whether the Solidity reference would succeed, mutating only on success.
        fn apply(&mut self, op: Op) -> bool {
            match op {
                Op::SetSendWl { acct, status, by } => {
                    if by != self.admin {
                        false
                    } else {
                        if status { self.send.insert(acct); } else { self.send.remove(&acct); }
                        true
                    }
                }
                Op::SetRecvWl { acct, status, by } => {
                    if by != self.admin {
                        false
                    } else {
                        if status { self.recv.insert(acct); } else { self.recv.remove(&acct); }
                        true
                    }
                }
                Op::Mint { to, amt, by } => {
                    if by != self.admin || !self.recv.contains(&to) {
                        false
                    } else {
                        self.bal.insert(to, self.b(to) + amt);
                        true
                    }
                }
                Op::Freeze { acct, amt, by } => {
                    if by != self.admin {
                        false
                    } else {
                        self.frozen.insert(acct, amt);
                        true
                    }
                }
                Op::Transfer { from, to, amt } => {
                    if amt > self.unfrozen(from) || !self.send.contains(&from) || !self.recv.contains(&to) {
                        false
                    } else {
                        self.bal.insert(from, self.b(from) - amt);
                        self.bal.insert(to, self.b(to) + amt);
                        true
                    }
                }
                Op::TransferFrom { spender, from, to, amt } => {
                    if self.allowance(from, spender) < amt
                        || amt > self.unfrozen(from)
                        || !self.send.contains(&from)
                        || !self.recv.contains(&to)
                    {
                        false
                    } else {
                        self.allow.insert((from, spender), self.allowance(from, spender) - amt);
                        self.bal.insert(from, self.b(from) - amt);
                        self.bal.insert(to, self.b(to) + amt);
                        true
                    }
                }
                Op::Approve { owner, spender, amt } => {
                    self.allow.insert((owner, spender), amt);
                    true
                }
                Op::ForcedTransfer { from, to, amt, by } => {
                    // The generator guarantees from != to (the equivalence region).
                    if by != self.admin || !self.recv.contains(&to) || self.b(from) < amt {
                        false
                    } else {
                        self.excess_frozen_update(from, amt);
                        self.bal.insert(from, self.b(from) - amt);
                        self.bal.insert(to, self.b(to) + amt);
                        true
                    }
                }
                Op::Burn { amt, by } => {
                    if by != self.admin || !self.send.contains(&by) || self.b(by) < amt {
                        false
                    } else {
                        self.excess_frozen_update(by, amt);
                        self.bal.insert(by, self.b(by) - amt);
                        true
                    }
                }
            }
        }
    }

    fn gen_op(rng: &mut Lcg, actors: &[Address; 4]) -> Op {
        let admin = actors[0];
        let amt = rng.below(120) as u128;
        // mostly admin for privileged ops, occasionally a non-admin to exercise role-gating (both revert).
        let by = if rng.below(5) == 0 { actors[rng.below(4) as usize] } else { admin };
        match rng.below(9) {
            0 => Op::SetSendWl { acct: actors[rng.below(4) as usize], status: rng.below(2) == 1, by },
            1 => Op::SetRecvWl { acct: actors[rng.below(4) as usize], status: rng.below(2) == 1, by },
            2 => Op::Mint { to: actors[rng.below(4) as usize], amt, by },
            3 => Op::Freeze { acct: actors[rng.below(4) as usize], amt, by },
            4 => Op::Transfer { from: actors[rng.below(4) as usize], to: actors[rng.below(4) as usize], amt },
            5 => Op::Approve { owner: actors[rng.below(4) as usize], spender: actors[rng.below(4) as usize], amt },
            6 => Op::TransferFrom {
                spender: actors[rng.below(4) as usize],
                from: actors[rng.below(4) as usize],
                to: actors[rng.below(4) as usize],
                amt,
            },
            7 => {
                let fi = rng.below(4) as usize;
                let ti0 = rng.below(4) as usize;
                let ti = if ti0 == fi { (fi + 1) % 4 } else { ti0 };
                Op::ForcedTransfer { from: actors[fi], to: actors[ti], amt, by }
            }
            _ => Op::Burn { amt, by },
        }
    }

    fn apply_real(c: &Contract<URWA20>, op: Op) -> bool {
        match op {
            Op::SetSendWl { acct, status, by } => c.sender(by).change_send_whitelist(acct, status).is_ok(),
            Op::SetRecvWl { acct, status, by } => c.sender(by).change_receive_whitelist(acct, status).is_ok(),
            Op::Mint { to, amt, by } => c.sender(by).mint(to, U256::from(amt)).is_ok(),
            Op::Freeze { acct, amt, by } => c.sender(by).set_frozen_tokens(acct, U256::from(amt)).is_ok(),
            Op::Transfer { from, to, amt } => c.sender(from).transfer(to, U256::from(amt)).is_ok(),
            Op::TransferFrom { spender, from, to, amt } => {
                c.sender(spender).transfer_from(from, to, U256::from(amt)).is_ok()
            }
            Op::Approve { owner, spender, amt } => c.sender(owner).approve(spender, U256::from(amt)).is_ok(),
            Op::ForcedTransfer { from, to, amt, by } => {
                c.sender(by).forced_transfer(from, to, U256::from(amt)).is_ok()
            }
            Op::Burn { amt, by } => c.sender(by).burn(U256::from(amt)).is_ok(),
        }
    }

    fn compare(c: &Contract<URWA20>, m: &Ref20, actors: &[Address; 4]) -> Result<(), TestErr> {
        actors.iter().try_for_each(|&a| {
            ensure(c.sender(actors[0]).balance_of(a) == U256::from(m.b(a)), "balance mismatch")?;
            ensure(c.sender(actors[0]).get_frozen_tokens(a) == U256::from(m.f(a)), "frozen mismatch")?;
            Ok(())
        })?;
        let total: u128 = actors.iter().map(|&a| m.b(a)).sum();
        ensure(c.sender(actors[0]).total_supply() == U256::from(total), "supply mismatch")?;
        actors.iter().try_for_each(|&owner| {
            actors.iter().try_for_each(|&spender| {
                ensure(
                    c.sender(actors[0]).allowance(owner, spender) == U256::from(m.allowance(owner, spender)),
                    "allowance mismatch",
                )
            })
        })
    }

    #[motsu::test]
    fn differential_vs_reference_model(
        contract: Contract<URWA20>,
        admin: Address,
        a: Address,
        b: Address,
        c: Address,
    ) -> Result<(), TestErr> {
        contract.sender(admin).initialize("Diff".into(), "DIF".into(), admin).ortest("init")?;
        let actors = [admin, a, b, c];
        let mut model = Ref20::new(admin);
        let mut rng = Lcg::new(0x9E3779B97F4A7C15);
        (0..800u64).try_for_each(|_| {
            let op = gen_op(&mut rng, &actors);
            let real_ok = apply_real(&contract, op);
            let model_ok = model.apply(op);
            ensure(real_ok == model_ok, "success/revert divergence vs reference")?;
            compare(&contract, &model, &actors)
        })
    }

    /// Demonstrates the harness catching the F2 hardening: at a self-directed forced
    /// transfer the reference model reduces the freeze, while the hardened contract does not.
    #[motsu::test]
    fn differential_flags_self_forced_divergence(
        contract: Contract<URWA20>,
        admin: Address,
        holder: Address,
    ) -> Result<(), TestErr> {
        setup_allowlisted(&contract, admin, holder)?;
        contract.sender(admin).mint(holder, n(100)).ortest("mint")?;
        contract.sender(admin).set_frozen_tokens(holder, n(80)).ortest("freeze")?;

        // What the Solidity reference does for forcedTransfer(holder, holder, 80): its
        // _excessFrozenUpdate runs before a no-op move, dropping frozen by (80 - unfrozen 20) = 60.
        let mut model = Ref20::new(admin);
        model.bal.insert(holder, 100);
        model.frozen.insert(holder, 80);
        model.excess_frozen_update(holder, 80);
        ensure(model.f(holder) == 20, "reference model would drop frozen to 20")?;

        // The hardened contract makes it a no-op: the freeze is preserved.
        contract.sender(admin).forced_transfer(holder, holder, n(80)).ortest("self forced")?;
        ensure(contract.sender(admin).get_frozen_tokens(holder) == n(80), "contract preserves frozen 80")?;
        Ok(())
    }
}
