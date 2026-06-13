#![cfg_attr(not(any(test, feature = "export-abi")), no_main)]
//! uRWA-1155: an ERC-7943 (uRWA) multi-token Real World Asset implementation for Arbitrum Stylus.
//!
//! Built on the audited `openzeppelin-stylus` primitives (`Erc1155` + `AccessControl`).
//! Implements the ERC-7943 multi-token interface: send/receive allowlists, role-gated
//! mint/burn, per-(account, id) freezing, and privileged forced transfer.
//!
//! The headline divergence from the Solidity reference implementation is a fix, not a
//! port: `safe_batch_transfer_from` validates each token id against the *accumulated*
//! amount requested for that id across the whole batch, so repeating an id in one batch
//! can no longer move more than the unfrozen balance. (In the Solidity reference, a
//! duplicate-id batch bypasses the per-id frozen check entirely; that bug is absent here.)
//!
//! As in uRWA-20, a self-directed `forced_transfer` (`from == to`) is a no-op and does
//! not corrupt freeze accounting, and `can_transfer` reflects true feasibility.
extern crate alloc;

use alloc::vec::Vec;

use alloy_sol_types::sol;
use openzeppelin_stylus::{
    access::control::{self, AccessControl, IAccessControl},
    token::erc1155::{self, Erc1155, IErc1155},
    utils::introspection::erc165::IErc165,
};
use stylus_sdk::{
    abi::Bytes,
    alloy_primitives::{aliases::B32, Address, B256, U256},
    evm, msg,
    prelude::*,
    storage::{StorageBool, StorageMap, StorageU256},
};

sol! {
    /// Emitted when an account's send-allowlist status changes.
    event SendWhitelisted(address indexed account, bool status);
    /// Emitted when an account's receive-allowlist status changes.
    event ReceiveWhitelisted(address indexed account, bool status);
    /// Emitted when the frozen amount of `tokenId` for `account` changes.
    event Frozen(address indexed account, uint256 indexed tokenId, uint256 amount);
    /// Emitted when tokens are seized from one account and moved to another.
    event ForcedTransfer(address indexed from, address indexed to, uint256 indexed tokenId, uint256 amount);

    /// The account is not allowed to send tokens.
    error ERC7943CannotSend(address account);
    /// The account is not allowed to receive tokens.
    error ERC7943CannotReceive(address account);
    /// The transfer is disallowed by token rules.
    error ERC7943CannotTransfer(address from, address to, uint256 tokenId, uint256 amount);
    /// The amount exceeds the account's unfrozen balance of `tokenId`.
    error ERC7943InsufficientUnfrozenBalance(address account, uint256 tokenId, uint256 amount, uint256 unfrozen);
}

/// Aggregated error type surfaced by the contract's external methods.
#[derive(SolidityError)]
enum Error {
    UnauthorizedAccount(control::AccessControlUnauthorizedAccount),
    BadConfirmation(control::AccessControlBadConfirmation),
    InsufficientBalance(erc1155::ERC1155InsufficientBalance),
    InvalidSender(erc1155::ERC1155InvalidSender),
    InvalidReceiver(erc1155::ERC1155InvalidReceiver),
    InvalidReceiverWithReason(erc1155::InvalidReceiverWithReason),
    MissingApprovalForAll(erc1155::ERC1155MissingApprovalForAll),
    InvalidApprover(erc1155::ERC1155InvalidApprover),
    InvalidOperator(erc1155::ERC1155InvalidOperator),
    InvalidArrayLength(erc1155::ERC1155InvalidArrayLength),
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

impl From<erc1155::Error> for Error {
    fn from(value: erc1155::Error) -> Self {
        match value {
            erc1155::Error::InsufficientBalance(e) => Error::InsufficientBalance(e),
            erc1155::Error::InvalidSender(e) => Error::InvalidSender(e),
            erc1155::Error::InvalidReceiver(e) => Error::InvalidReceiver(e),
            erc1155::Error::InvalidReceiverWithReason(e) => Error::InvalidReceiverWithReason(e),
            erc1155::Error::MissingApprovalForAll(e) => Error::MissingApprovalForAll(e),
            erc1155::Error::InvalidApprover(e) => Error::InvalidApprover(e),
            erc1155::Error::InvalidOperator(e) => Error::InvalidOperator(e),
            erc1155::Error::InvalidArrayLength(e) => Error::InvalidArrayLength(e),
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

/// Empty call data for mints performed during a forced transfer.
fn empty_data() -> Bytes {
    Vec::new().into()
}

#[entrypoint]
#[storage]
struct URWA1155 {
    erc1155: Erc1155,
    access: AccessControl,
    send_whitelist: StorageMap<Address, StorageBool>,
    receive_whitelist: StorageMap<Address, StorageBool>,
    frozen: StorageMap<Address, StorageMap<U256, StorageU256>>,
}

#[public]
#[implements(IErc1155<Error = Error>, IAccessControl<Error = control::Error>, IErc165)]
impl URWA1155 {
    #[constructor]
    fn constructor(&mut self, initial_admin: Address) {
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

    /// The frozen amount of `token_id` for `account` (may exceed its balance, by design).
    fn get_frozen_tokens(&self, account: Address, token_id: U256) -> U256 {
        self.frozen.get(account).get(token_id)
    }

    /// Whether an ordinary transfer of `amount` of `token_id` from `from` to `to` is allowed.
    fn can_transfer(&self, from: Address, to: Address, token_id: U256, amount: U256) -> bool {
        amount <= self.unfrozen_balance(from, token_id) && self.can_send(from) && self.can_receive(to)
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

    /// Mint `amount` of `id` to `to`. Requires `MINTER_ROLE` and `to` on the receive-allowlist.
    fn mint(&mut self, to: Address, id: U256, amount: U256) -> Result<(), Error> {
        self.access.only_role(MINTER_ROLE.into())?;
        self.can_receive(to)
            .then_some(())
            .ok_or(Error::CannotReceive(ERC7943CannotReceive { account: to }))?;
        self.erc1155._mint(to, id, amount, &empty_data())?;
        Ok(())
    }

    /// Batched [`mint`]. Requires `MINTER_ROLE` and `to` on the receive-allowlist.
    fn mint_batch(&mut self, to: Address, ids: Vec<U256>, amounts: Vec<U256>) -> Result<(), Error> {
        self.access.only_role(MINTER_ROLE.into())?;
        self.can_receive(to)
            .then_some(())
            .ok_or(Error::CannotReceive(ERC7943CannotReceive { account: to }))?;
        self.erc1155._mint_batch(to, ids, amounts, &empty_data())?;
        Ok(())
    }

    /// Burn `amount` of `id` from the caller. Requires `BURNER_ROLE` and caller on the send-allowlist.
    fn burn(&mut self, id: U256, amount: U256) -> Result<(), Error> {
        self.access.only_role(BURNER_ROLE.into())?;
        let from = msg::sender();
        self.can_send(from)
            .then_some(())
            .ok_or(Error::CannotSend(ERC7943CannotSend { account: from }))?;
        self.excess_frozen_update(from, id, amount);
        self.erc1155._burn(from, id, amount)?;
        Ok(())
    }

    /// Batched [`burn`]. Requires `BURNER_ROLE` and caller on the send-allowlist.
    fn burn_batch(&mut self, ids: Vec<U256>, amounts: Vec<U256>) -> Result<(), Error> {
        self.access.only_role(BURNER_ROLE.into())?;
        let from = msg::sender();
        self.can_send(from)
            .then_some(())
            .ok_or(Error::CannotSend(ERC7943CannotSend { account: from }))?;
        ids.iter()
            .zip(amounts.iter())
            .for_each(|(&id, &amount)| self.excess_frozen_update(from, id, amount));
        self.erc1155._burn_batch(from, ids, amounts)?;
        Ok(())
    }

    /// Overwrite the frozen amount of `token_id` for `account`. Requires `FREEZING_ROLE`.
    fn set_frozen_tokens(&mut self, account: Address, token_id: U256, amount: U256) -> Result<(), Error> {
        self.access.only_role(FREEZING_ROLE.into())?;
        self.frozen.setter(account).setter(token_id).set(amount);
        evm::log(Frozen { account, tokenId: token_id, amount });
        Ok(())
    }

    /// Seize `amount` of `id` from `from` and deliver to `to`, bypassing send rules.
    /// Requires `FORCE_TRANSFER_ROLE` and `to` on the receive-allowlist. Implemented as
    /// burn-from-source then mint-to-destination, since the authorized public transfer
    /// path cannot move another account's tokens without approval.
    fn forced_transfer(&mut self, from: Address, to: Address, id: U256, amount: U256) -> Result<(), Error> {
        self.access.only_role(FORCE_TRANSFER_ROLE.into())?;
        (!to.is_zero())
            .then_some(())
            .ok_or(Error::InvalidReceiver(erc1155::ERC1155InvalidReceiver { receiver: Address::ZERO }))?;
        (!from.is_zero())
            .then_some(())
            .ok_or(Error::InvalidSender(erc1155::ERC1155InvalidSender { sender: Address::ZERO }))?;
        self.can_receive(to)
            .then_some(())
            .ok_or(Error::CannotReceive(ERC7943CannotReceive { account: to }))?;
        // Hardening (F2): a self-directed seizure moves nothing and must not corrupt freeze accounting.
        if from != to {
            self.excess_frozen_update(from, id, amount);
            self.erc1155._burn(from, id, amount)?;
            self.erc1155._mint(to, id, amount, &empty_data())?;
        }
        evm::log(ForcedTransfer { from, to, tokenId: id, amount });
        Ok(())
    }
}

impl URWA1155 {
    /// Balance of `id` minus its frozen amount, saturating at zero.
    fn unfrozen_balance(&self, account: Address, id: U256) -> U256 {
        let balance = self.erc1155.balance_of(account, id);
        let frozen = self.frozen.get(account).get(id);
        balance.checked_sub(frozen).unwrap_or(U256::ZERO)
    }

    /// Reduce the frozen counter for `id` when `amount` leaves `account` beyond its
    /// unfrozen balance (forced transfer or burn).
    fn excess_frozen_update(&mut self, account: Address, id: U256, amount: U256) {
        let unfrozen = self.unfrozen_balance(account, id);
        let balance = self.erc1155.balance_of(account, id);
        if amount > unfrozen && amount <= balance {
            let current = self.frozen.get(account).get(id);
            let next = current.checked_sub(amount - unfrozen).unwrap_or(U256::ZERO);
            self.frozen.setter(account).setter(id).set(next);
            evm::log(Frozen { account, tokenId: id, amount: next });
        }
    }
}

#[public]
impl IErc1155 for URWA1155 {
    type Error = Error;

    fn balance_of(&self, account: Address, id: U256) -> U256 {
        self.erc1155.balance_of(account, id)
    }

    fn balance_of_batch(&self, accounts: Vec<Address>, ids: Vec<U256>) -> Result<Vec<U256>, Error> {
        Ok(self.erc1155.balance_of_batch(accounts, ids)?)
    }

    fn set_approval_for_all(&mut self, operator: Address, approved: bool) -> Result<(), Error> {
        Ok(self.erc1155.set_approval_for_all(operator, approved)?)
    }

    fn is_approved_for_all(&self, account: Address, operator: Address) -> bool {
        self.erc1155.is_approved_for_all(account, operator)
    }

    fn safe_transfer_from(
        &mut self,
        from: Address,
        to: Address,
        id: U256,
        value: U256,
        data: Bytes,
    ) -> Result<(), Error> {
        self.can_send(from)
            .then_some(())
            .ok_or(Error::CannotSend(ERC7943CannotSend { account: from }))?;
        self.can_receive(to)
            .then_some(())
            .ok_or(Error::CannotReceive(ERC7943CannotReceive { account: to }))?;
        let unfrozen = self.unfrozen_balance(from, id);
        (value <= unfrozen).then_some(()).ok_or(Error::InsufficientUnfrozenBalance(
            ERC7943InsufficientUnfrozenBalance { account: from, tokenId: id, amount: value, unfrozen },
        ))?;
        Ok(self.erc1155.safe_transfer_from(from, to, id, value, data)?)
    }

    fn safe_batch_transfer_from(
        &mut self,
        from: Address,
        to: Address,
        ids: Vec<U256>,
        values: Vec<U256>,
        data: Bytes,
    ) -> Result<(), Error> {
        self.can_send(from)
            .then_some(())
            .ok_or(Error::CannotSend(ERC7943CannotSend { account: from }))?;
        self.can_receive(to)
            .then_some(())
            .ok_or(Error::CannotReceive(ERC7943CannotReceive { account: to }))?;
        // Batch-safe freeze check: validate each id against the TOTAL amount requested for
        // that id across the whole batch. This closes the duplicate-id bypass present in the
        // Solidity reference (where each element is checked against a fresh, un-decremented
        // unfrozen balance). Lengths are checked by the delegate below; a mismatch reverts
        // there before any state changes, so the truncating zip here cannot leak value.
        let violation = ids.iter().find_map(|&id| {
            let total = ids
                .iter()
                .zip(values.iter())
                .filter(|(&other, _)| other == id)
                .map(|(_, &v)| v)
                .fold(U256::ZERO, |acc, v| acc + v);
            let unfrozen = self.unfrozen_balance(from, id);
            (total > unfrozen).then_some((id, total, unfrozen))
        });
        violation.map_or(Ok(()), |(id, total, unfrozen)| {
            Err(Error::InsufficientUnfrozenBalance(ERC7943InsufficientUnfrozenBalance {
                account: from,
                tokenId: id,
                amount: total,
                unfrozen,
            }))
        })?;
        Ok(self.erc1155.safe_batch_transfer_from(from, to, ids, values, data)?)
    }
}

#[public]
impl IAccessControl for URWA1155 {
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
impl IErc165 for URWA1155 {
    fn supports_interface(&self, interface_id: B32) -> bool {
        self.access.supports_interface(interface_id) || self.erc1155.supports_interface(interface_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use motsu::prelude::*;

    #[derive(Debug)]
    #[allow(dead_code)]
    struct TestErr(&'static str);

    fn ensure(cond: bool, msg: &'static str) -> Result<(), TestErr> {
        cond.then_some(()).ok_or(TestErr(msg))
    }

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

    const ID: u64 = 1;

    fn setup_allowlisted(
        contract: &Contract<URWA1155>,
        admin: Address,
        who: Address,
    ) -> Result<(), TestErr> {
        contract.sender(admin).constructor(admin);
        contract.sender(admin).change_send_whitelist(who, true).ortest("send wl")?;
        contract.sender(admin).change_receive_whitelist(who, true).ortest("recv wl")?;
        Ok(())
    }

    #[motsu::test]
    fn single_transfer_respects_freeze(
        contract: Contract<URWA1155>,
        admin: Address,
        holder: Address,
        dest: Address,
    ) -> Result<(), TestErr> {
        setup_allowlisted(&contract, admin, holder)?;
        setup_allowlisted(&contract, admin, dest)?;
        contract.sender(admin).mint(holder, n(ID), n(100)).ortest("mint")?;
        contract.sender(admin).set_frozen_tokens(holder, n(ID), n(50)).ortest("freeze")?;
        ensure(contract.sender(holder).safe_transfer_from(holder, dest, n(ID), n(60), Vec::new().into()).is_err(), "60 reverts")?;
        contract.sender(holder).safe_transfer_from(holder, dest, n(ID), n(50), Vec::new().into()).ortest("50 ok")?;
        ensure(contract.sender(admin).balance_of(holder, n(ID)) == n(50), "holder 50")?;
        Ok(())
    }

    /// The headline fix: a duplicate-id batch must NOT bypass the per-id frozen check.
    #[motsu::test]
    fn duplicate_id_batch_cannot_bypass_freeze(
        contract: Contract<URWA1155>,
        admin: Address,
        holder: Address,
        dest: Address,
    ) -> Result<(), TestErr> {
        setup_allowlisted(&contract, admin, holder)?;
        setup_allowlisted(&contract, admin, dest)?;
        contract.sender(admin).mint(holder, n(ID), n(100)).ortest("mint")?;
        contract.sender(admin).set_frozen_tokens(holder, n(ID), n(50)).ortest("freeze 50")?;

        // [id, id] x [50, 50]: in the Solidity reference this drains all 100; here it must revert.
        let ids = alloc::vec![n(ID), n(ID)];
        let vals = alloc::vec![n(50), n(50)];
        ensure(
            contract.sender(holder).safe_batch_transfer_from(holder, dest, ids, vals, Vec::new().into()).is_err(),
            "duplicate-id batch must revert (freeze not bypassable)",
        )?;
        // Nothing moved.
        ensure(contract.sender(admin).balance_of(holder, n(ID)) == n(100), "holder still 100")?;
        ensure(contract.sender(admin).balance_of(dest, n(ID)) == n(0), "dest still 0")?;
        Ok(())
    }

    /// A legitimate multi-id batch within the unfrozen budget still works.
    #[motsu::test]
    fn distinct_id_batch_within_budget_succeeds(
        contract: Contract<URWA1155>,
        admin: Address,
        holder: Address,
        dest: Address,
    ) -> Result<(), TestErr> {
        setup_allowlisted(&contract, admin, holder)?;
        setup_allowlisted(&contract, admin, dest)?;
        contract.sender(admin).mint(holder, n(1), n(100)).ortest("mint 1")?;
        contract.sender(admin).mint(holder, n(2), n(100)).ortest("mint 2")?;
        contract.sender(admin).set_frozen_tokens(holder, n(1), n(40)).ortest("freeze 1")?;

        let ids = alloc::vec![n(1), n(2)];
        let vals = alloc::vec![n(60), n(100)]; // 60 <= unfrozen(1)=60, 100 <= unfrozen(2)=100
        contract.sender(holder).safe_batch_transfer_from(holder, dest, ids, vals, Vec::new().into()).ortest("batch ok")?;
        ensure(contract.sender(admin).balance_of(dest, n(1)) == n(60), "dest id1 60")?;
        ensure(contract.sender(admin).balance_of(dest, n(2)) == n(100), "dest id2 100")?;
        Ok(())
    }

    #[motsu::test]
    fn transfer_blocked_by_allowlists(
        contract: Contract<URWA1155>,
        admin: Address,
        holder: Address,
        dest: Address,
    ) -> Result<(), TestErr> {
        contract.sender(admin).constructor(admin);
        contract.sender(admin).change_receive_whitelist(holder, true).ortest("holder recv")?;
        contract.sender(admin).mint(holder, n(ID), n(100)).ortest("mint")?;
        // holder not send-allowlisted, dest not receive-allowlisted.
        ensure(contract.sender(holder).safe_transfer_from(holder, dest, n(ID), n(1), Vec::new().into()).is_err(), "send blocked")?;
        contract.sender(admin).change_send_whitelist(holder, true).ortest("holder send")?;
        ensure(contract.sender(holder).safe_transfer_from(holder, dest, n(ID), n(1), Vec::new().into()).is_err(), "recv blocked")?;
        Ok(())
    }

    #[motsu::test]
    fn forced_transfer_seizes_and_self_is_noop(
        contract: Contract<URWA1155>,
        admin: Address,
        holder: Address,
        dest: Address,
    ) -> Result<(), TestErr> {
        setup_allowlisted(&contract, admin, holder)?;
        setup_allowlisted(&contract, admin, dest)?;
        contract.sender(admin).mint(holder, n(ID), n(100)).ortest("mint")?;
        contract.sender(admin).set_frozen_tokens(holder, n(ID), n(80)).ortest("freeze 80")?;

        // F2: self-directed forced transfer must not wipe the freeze.
        contract.sender(admin).forced_transfer(holder, holder, n(ID), n(80)).ortest("self forced")?;
        ensure(contract.sender(admin).get_frozen_tokens(holder, n(ID)) == n(80), "freeze intact")?;
        ensure(contract.sender(admin).balance_of(holder, n(ID)) == n(100), "balance intact")?;

        // Real seizure moves tokens even though the freeze would block a normal transfer.
        contract.sender(admin).forced_transfer(holder, dest, n(ID), n(100)).ortest("seize")?;
        ensure(contract.sender(admin).balance_of(holder, n(ID)) == n(0), "holder 0")?;
        ensure(contract.sender(admin).balance_of(dest, n(ID)) == n(100), "dest 100")?;
        Ok(())
    }

    #[motsu::test]
    fn privileged_actions_are_role_gated(
        contract: Contract<URWA1155>,
        admin: Address,
        holder: Address,
        mallory: Address,
    ) -> Result<(), TestErr> {
        setup_allowlisted(&contract, admin, holder)?;
        contract.sender(admin).mint(holder, n(ID), n(100)).ortest("mint")?;
        ensure(contract.sender(mallory).set_frozen_tokens(holder, n(ID), n(10)).is_err(), "freeze gated")?;
        ensure(contract.sender(mallory).forced_transfer(holder, holder, n(ID), n(10)).is_err(), "force gated")?;
        ensure(contract.sender(mallory).mint(mallory, n(ID), n(10)).is_err(), "mint gated")?;
        ensure(contract.sender(mallory).change_send_whitelist(mallory, true).is_err(), "whitelist gated")?;
        Ok(())
    }

    #[motsu::test]
    fn can_transfer_matches_execution(
        contract: Contract<URWA1155>,
        admin: Address,
        holder: Address,
        dest: Address,
    ) -> Result<(), TestErr> {
        setup_allowlisted(&contract, admin, holder)?;
        setup_allowlisted(&contract, admin, dest)?;
        contract.sender(admin).mint(holder, n(ID), n(50)).ortest("mint")?;
        ensure(!contract.sender(holder).can_transfer(holder, dest, n(ID), n(100)), "over-balance false")?;
        ensure(contract.sender(holder).can_transfer(holder, dest, n(ID), n(50)), "exact true")?;
        Ok(())
    }
}
