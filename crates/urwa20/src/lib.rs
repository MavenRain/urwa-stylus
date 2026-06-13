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
    send_whitelist: StorageMap<Address, StorageBool>,
    receive_whitelist: StorageMap<Address, StorageBool>,
    frozen: StorageMap<Address, StorageU256>,
}

#[public]
#[implements(IErc20<Error = Error>, IErc20Metadata, IAccessControl<Error = control::Error>, IErc165)]
impl URWA20 {
    #[constructor]
    fn constructor(&mut self, name: String, symbol: String, initial_admin: Address) {
        self.metadata.constructor(name, symbol);
        self.access._grant_role(AccessControl::DEFAULT_ADMIN_ROLE.into(), initial_admin);
        self.access._grant_role(MINTER_ROLE.into(), initial_admin);
        self.access._grant_role(BURNER_ROLE.into(), initial_admin);
        self.access._grant_role(FREEZING_ROLE.into(), initial_admin);
        self.access._grant_role(WHITELIST_ROLE.into(), initial_admin);
        self.access._grant_role(FORCE_TRANSFER_ROLE.into(), initial_admin);
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
        contract.sender(admin).constructor("uRWA Test".into(), "URWA".into(), admin);
        contract.sender(admin).change_send_whitelist(who, true).ortest("send wl")?;
        contract.sender(admin).change_receive_whitelist(who, true).ortest("recv wl")?;
        Ok(())
    }

    #[motsu::test]
    fn constructor_grants_all_roles(contract: Contract<URWA20>, admin: Address) -> Result<(), TestErr> {
        contract.sender(admin).constructor("uRWA Test".into(), "URWA".into(), admin);
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
        contract.sender(admin).constructor("uRWA Real Estate".into(), "uRWA".into(), admin);
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
        contract.sender(admin).constructor("uRWA Test".into(), "URWA".into(), admin);
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
        contract.sender(admin).constructor("uRWA Test".into(), "URWA".into(), admin);
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
}
