#![cfg_attr(not(any(test, feature = "export-abi")), no_main)]
//! uRWA-721: an ERC-7943 (uRWA) non-fungible Real World Asset implementation for Arbitrum Stylus.
//!
//! The 1-of-1 deed/title primitive: each token is a unique on-chain claim to a specific
//! property. Built on the audited `openzeppelin-stylus` primitives (`Erc721` +
//! `AccessControl`). Implements the ERC-7943 non-fungible interface: send/receive
//! allowlists, role-gated mint/burn, per-(owner, tokenId) freezing, and privileged
//! forced transfer.
//!
//! As in the other variants, a self-directed `forced_transfer` (`from == to`) is a no-op
//! that does not clear the freeze, and `can_transfer` reflects true feasibility. A
//! forced transfer seizes via the base `_update` with no receiver-acceptance check, so a
//! compliance seizure into an allowlisted destination cannot be blocked by that
//! destination failing to implement `onERC721Received`.
extern crate alloc;

use alloc::vec::Vec;

use alloy_sol_types::sol;
use openzeppelin_stylus::{
    access::control::{self, AccessControl, IAccessControl},
    token::erc721::{self, Erc721, IErc721},
    utils::introspection::erc165::IErc165,
};
use stylus_sdk::{
    abi::Bytes,
    alloy_primitives::{aliases::B32, Address, B256, U256},
    evm, msg,
    prelude::*,
    storage::{StorageBool, StorageMap},
};

sol! {
    /// Emitted when an account's send-allowlist status changes.
    event SendWhitelisted(address indexed account, bool status);
    /// Emitted when an account's receive-allowlist status changes.
    event ReceiveWhitelisted(address indexed account, bool status);
    /// Emitted when the frozen status of `tokenId` for `account` changes.
    event Frozen(address indexed account, uint256 indexed tokenId, bool frozenStatus);
    /// Emitted when `tokenId` is seized from one account and moved to another.
    event ForcedTransfer(address indexed from, address indexed to, uint256 indexed tokenId);

    /// The account is not allowed to send tokens.
    error ERC7943CannotSend(address account);
    /// The account is not allowed to receive tokens.
    error ERC7943CannotReceive(address account);
    /// The transfer is disallowed by token rules.
    error ERC7943CannotTransfer(address from, address to, uint256 tokenId);
    /// `tokenId` is frozen for `account` and cannot be transferred by the account.
    error ERC7943InsufficientUnfrozenBalance(address account, uint256 tokenId);
}

/// Aggregated error type surfaced by the contract's external methods.
#[derive(SolidityError)]
enum Error {
    UnauthorizedAccount(control::AccessControlUnauthorizedAccount),
    BadConfirmation(control::AccessControlBadConfirmation),
    InvalidOwner(erc721::ERC721InvalidOwner),
    NonexistentToken(erc721::ERC721NonexistentToken),
    IncorrectOwner(erc721::ERC721IncorrectOwner),
    InvalidSender(erc721::ERC721InvalidSender),
    InvalidReceiver(erc721::ERC721InvalidReceiver),
    InvalidReceiverWithReason(erc721::InvalidReceiverWithReason),
    InsufficientApproval(erc721::ERC721InsufficientApproval),
    InvalidApprover(erc721::ERC721InvalidApprover),
    InvalidOperator(erc721::ERC721InvalidOperator),
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

impl From<erc721::Error> for Error {
    fn from(value: erc721::Error) -> Self {
        match value {
            erc721::Error::InvalidOwner(e) => Error::InvalidOwner(e),
            erc721::Error::NonexistentToken(e) => Error::NonexistentToken(e),
            erc721::Error::IncorrectOwner(e) => Error::IncorrectOwner(e),
            erc721::Error::InvalidSender(e) => Error::InvalidSender(e),
            erc721::Error::InvalidReceiver(e) => Error::InvalidReceiver(e),
            erc721::Error::InvalidReceiverWithReason(e) => Error::InvalidReceiverWithReason(e),
            erc721::Error::InsufficientApproval(e) => Error::InsufficientApproval(e),
            erc721::Error::InvalidApprover(e) => Error::InvalidApprover(e),
            erc721::Error::InvalidOperator(e) => Error::InvalidOperator(e),
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

/// Empty call data for safe mints.
fn empty_data() -> Bytes {
    Vec::new().into()
}

#[entrypoint]
#[storage]
struct URWA721 {
    erc721: Erc721,
    access: AccessControl,
    send_whitelist: StorageMap<Address, StorageBool>,
    receive_whitelist: StorageMap<Address, StorageBool>,
    frozen: StorageMap<Address, StorageMap<U256, StorageBool>>,
}

#[public]
#[implements(IErc721<Error = Error>, IAccessControl<Error = control::Error>, IErc165)]
impl URWA721 {
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

    /// Whether `token_id` is frozen for `account`.
    fn get_frozen_tokens(&self, account: Address, token_id: U256) -> bool {
        self.frozen.get(account).get(token_id)
    }

    /// Whether an ordinary transfer of `token_id` from `from` to `to` is allowed:
    /// `from` owns it, it is not frozen, and both allowlists pass.
    fn can_transfer(&self, from: Address, to: Address, token_id: U256) -> bool {
        self.erc721.owner_of(token_id).map_or(false, |owner| owner == from)
            && !self.get_frozen_tokens(from, token_id)
            && self.can_send(from)
            && self.can_receive(to)
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

    /// Safely mint `token_id` to `to`. Requires `MINTER_ROLE` and `to` on the receive-allowlist.
    fn safe_mint(&mut self, to: Address, token_id: U256) -> Result<(), Error> {
        self.access.only_role(MINTER_ROLE.into())?;
        self.can_receive(to)
            .then_some(())
            .ok_or(Error::CannotReceive(ERC7943CannotReceive { account: to }))?;
        self.erc721._safe_mint(to, token_id, &empty_data())?;
        Ok(())
    }

    /// Burn `token_id`. Requires `BURNER_ROLE`. Clears any freeze on the token; burning is
    /// destruction by a trusted role and is intentionally not gated on the send-allowlist
    /// (so a blocklisted holder's token remains burnable).
    fn burn(&mut self, token_id: U256) -> Result<(), Error> {
        self.access.only_role(BURNER_ROLE.into())?;
        let owner = self.erc721._owner_of(token_id);
        self.frozen.setter(owner).setter(token_id).set(false);
        self.erc721._burn(token_id)?;
        Ok(())
    }

    /// Set the frozen status of `token_id` for `account`. Requires `FREEZING_ROLE`.
    fn set_frozen_tokens(&mut self, account: Address, token_id: U256, frozen_status: bool) -> Result<(), Error> {
        self.access.only_role(FREEZING_ROLE.into())?;
        self.frozen.setter(account).setter(token_id).set(frozen_status);
        evm::log(Frozen { account, tokenId: token_id, frozenStatus: frozen_status });
        Ok(())
    }

    /// Seize `token_id` from `from` and deliver to `to`, bypassing send rules.
    /// Requires `FORCE_TRANSFER_ROLE`, `to` on the receive-allowlist, and `from` to be the owner.
    fn forced_transfer(&mut self, from: Address, to: Address, token_id: U256) -> Result<(), Error> {
        self.access.only_role(FORCE_TRANSFER_ROLE.into())?;
        (!to.is_zero())
            .then_some(())
            .ok_or(Error::InvalidReceiver(erc721::ERC721InvalidReceiver { receiver: Address::ZERO }))?;
        (!from.is_zero())
            .then_some(())
            .ok_or(Error::InvalidSender(erc721::ERC721InvalidSender { sender: Address::ZERO }))?;
        self.can_receive(to)
            .then_some(())
            .ok_or(Error::CannotReceive(ERC7943CannotReceive { account: to }))?;
        let owner = self.erc721.owner_of(token_id)?;
        (owner == from).then_some(()).ok_or(Error::IncorrectOwner(erc721::ERC721IncorrectOwner {
            sender: from,
            token_id,
            owner,
        }))?;
        // Hardening (F2): a self-directed seizure moves nothing and must not clear the freeze.
        if from != to {
            self.frozen.setter(from).setter(token_id).set(false);
            self.erc721._update(to, token_id, Address::ZERO)?;
        }
        evm::log(ForcedTransfer { from, to, tokenId: token_id });
        Ok(())
    }
}

impl URWA721 {
    /// Enforce ordinary-transfer rules: token not frozen for `from`, then both allowlists.
    /// Ownership (`from` owns `token_id`) is enforced by the delegated base transfer.
    fn enforce_transfer(&self, from: Address, to: Address, token_id: U256) -> Result<(), Error> {
        (!self.get_frozen_tokens(from, token_id)).then_some(()).ok_or(
            Error::InsufficientUnfrozenBalance(ERC7943InsufficientUnfrozenBalance {
                account: from,
                tokenId: token_id,
            }),
        )?;
        self.can_send(from)
            .then_some(())
            .ok_or(Error::CannotSend(ERC7943CannotSend { account: from }))?;
        self.can_receive(to)
            .then_some(())
            .ok_or(Error::CannotReceive(ERC7943CannotReceive { account: to }))?;
        Ok(())
    }
}

#[public]
impl IErc721 for URWA721 {
    type Error = Error;

    fn balance_of(&self, owner: Address) -> Result<U256, Error> {
        Ok(self.erc721.balance_of(owner)?)
    }

    fn owner_of(&self, token_id: U256) -> Result<Address, Error> {
        Ok(self.erc721.owner_of(token_id)?)
    }

    fn safe_transfer_from(&mut self, from: Address, to: Address, token_id: U256) -> Result<(), Error> {
        self.enforce_transfer(from, to, token_id)?;
        Ok(self.erc721.safe_transfer_from(from, to, token_id)?)
    }

    #[selector(name = "safeTransferFrom")]
    fn safe_transfer_from_with_data(
        &mut self,
        from: Address,
        to: Address,
        token_id: U256,
        data: Bytes,
    ) -> Result<(), Error> {
        self.enforce_transfer(from, to, token_id)?;
        Ok(self.erc721.safe_transfer_from_with_data(from, to, token_id, data)?)
    }

    fn transfer_from(&mut self, from: Address, to: Address, token_id: U256) -> Result<(), Error> {
        self.enforce_transfer(from, to, token_id)?;
        Ok(self.erc721.transfer_from(from, to, token_id)?)
    }

    fn approve(&mut self, to: Address, token_id: U256) -> Result<(), Error> {
        Ok(self.erc721.approve(to, token_id)?)
    }

    fn set_approval_for_all(&mut self, operator: Address, approved: bool) -> Result<(), Error> {
        Ok(self.erc721.set_approval_for_all(operator, approved)?)
    }

    fn get_approved(&self, token_id: U256) -> Result<Address, Error> {
        Ok(self.erc721.get_approved(token_id)?)
    }

    fn is_approved_for_all(&self, owner: Address, operator: Address) -> bool {
        self.erc721.is_approved_for_all(owner, operator)
    }
}

#[public]
impl IAccessControl for URWA721 {
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
impl IErc165 for URWA721 {
    fn supports_interface(&self, interface_id: B32) -> bool {
        self.access.supports_interface(interface_id) || self.erc721.supports_interface(interface_id)
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

    const TOKEN: u64 = 1;

    fn setup_allowlisted(
        contract: &Contract<URWA721>,
        admin: Address,
        who: Address,
    ) -> Result<(), TestErr> {
        contract.sender(admin).constructor(admin);
        contract.sender(admin).change_send_whitelist(who, true).ortest("send wl")?;
        contract.sender(admin).change_receive_whitelist(who, true).ortest("recv wl")?;
        Ok(())
    }

    #[motsu::test]
    fn constructor_grants_roles(contract: Contract<URWA721>, admin: Address) -> Result<(), TestErr> {
        contract.sender(admin).constructor(admin);
        let c = contract.sender(admin);
        ensure(c.has_role(MINTER_ROLE.into(), admin), "MINTER")?;
        ensure(c.has_role(FORCE_TRANSFER_ROLE.into(), admin), "FORCE")?;
        Ok(())
    }

    #[motsu::test]
    fn mint_requires_role_and_receive_allowlist(
        contract: Contract<URWA721>,
        admin: Address,
        holder: Address,
        mallory: Address,
    ) -> Result<(), TestErr> {
        contract.sender(admin).constructor(admin);
        // not receive-allowlisted yet
        ensure(contract.sender(admin).safe_mint(holder, n(TOKEN)).is_err(), "mint to non-allowlisted reverts")?;
        contract.sender(admin).change_receive_whitelist(holder, true).ortest("recv wl")?;
        // non-minter cannot mint
        ensure(contract.sender(mallory).safe_mint(holder, n(TOKEN)).is_err(), "non-minter reverts")?;
        contract.sender(admin).safe_mint(holder, n(TOKEN)).ortest("mint ok")?;
        ensure(contract.sender(admin).owner_of(n(TOKEN)).ortest("owner")? == holder, "holder owns")?;
        Ok(())
    }

    #[motsu::test]
    fn transfer_respects_allowlists_and_freeze(
        contract: Contract<URWA721>,
        admin: Address,
        holder: Address,
        dest: Address,
    ) -> Result<(), TestErr> {
        setup_allowlisted(&contract, admin, holder)?;
        setup_allowlisted(&contract, admin, dest)?;
        contract.sender(admin).safe_mint(holder, n(TOKEN)).ortest("mint")?;

        // Freeze blocks the transfer.
        contract.sender(admin).set_frozen_tokens(holder, n(TOKEN), true).ortest("freeze")?;
        ensure(contract.sender(holder).transfer_from(holder, dest, n(TOKEN)).is_err(), "frozen cannot move")?;

        // Unfreeze and transfer succeeds.
        contract.sender(admin).set_frozen_tokens(holder, n(TOKEN), false).ortest("unfreeze")?;
        contract.sender(holder).transfer_from(holder, dest, n(TOKEN)).ortest("transfer ok")?;
        ensure(contract.sender(admin).owner_of(n(TOKEN)).ortest("owner")? == dest, "dest owns")?;
        Ok(())
    }

    #[motsu::test]
    fn transfer_to_non_allowlisted_reverts(
        contract: Contract<URWA721>,
        admin: Address,
        holder: Address,
        dest: Address,
    ) -> Result<(), TestErr> {
        setup_allowlisted(&contract, admin, holder)?;
        contract.sender(admin).safe_mint(holder, n(TOKEN)).ortest("mint")?;
        // dest not receive-allowlisted
        ensure(contract.sender(holder).transfer_from(holder, dest, n(TOKEN)).is_err(), "to not allowlisted")?;
        Ok(())
    }

    #[motsu::test]
    fn forced_transfer_seizes_and_self_is_noop(
        contract: Contract<URWA721>,
        admin: Address,
        holder: Address,
        dest: Address,
    ) -> Result<(), TestErr> {
        setup_allowlisted(&contract, admin, holder)?;
        setup_allowlisted(&contract, admin, dest)?;
        contract.sender(admin).safe_mint(holder, n(TOKEN)).ortest("mint")?;
        contract.sender(admin).set_frozen_tokens(holder, n(TOKEN), true).ortest("freeze")?;

        // F2: self-directed forced transfer must not clear the freeze or move the token.
        contract.sender(admin).forced_transfer(holder, holder, n(TOKEN)).ortest("self forced")?;
        ensure(contract.sender(admin).get_frozen_tokens(holder, n(TOKEN)), "still frozen")?;
        ensure(contract.sender(admin).owner_of(n(TOKEN)).ortest("owner")? == holder, "still holder")?;

        // Real seizure moves the token even though it is frozen (and clears the freeze).
        contract.sender(admin).forced_transfer(holder, dest, n(TOKEN)).ortest("seize")?;
        ensure(contract.sender(admin).owner_of(n(TOKEN)).ortest("owner2")? == dest, "dest owns")?;
        ensure(!contract.sender(admin).get_frozen_tokens(dest, n(TOKEN)), "freeze cleared")?;
        Ok(())
    }

    #[motsu::test]
    fn forced_transfer_requires_owner_match(
        contract: Contract<URWA721>,
        admin: Address,
        holder: Address,
        dest: Address,
        stranger: Address,
    ) -> Result<(), TestErr> {
        setup_allowlisted(&contract, admin, holder)?;
        setup_allowlisted(&contract, admin, dest)?;
        contract.sender(admin).safe_mint(holder, n(TOKEN)).ortest("mint")?;
        // `from` is not the owner -> reverts.
        ensure(contract.sender(admin).forced_transfer(stranger, dest, n(TOKEN)).is_err(), "wrong from reverts")?;
        Ok(())
    }

    #[motsu::test]
    fn privileged_actions_are_role_gated(
        contract: Contract<URWA721>,
        admin: Address,
        holder: Address,
        mallory: Address,
    ) -> Result<(), TestErr> {
        setup_allowlisted(&contract, admin, holder)?;
        contract.sender(admin).safe_mint(holder, n(TOKEN)).ortest("mint")?;
        ensure(contract.sender(mallory).set_frozen_tokens(holder, n(TOKEN), true).is_err(), "freeze gated")?;
        ensure(contract.sender(mallory).forced_transfer(holder, mallory, n(TOKEN)).is_err(), "force gated")?;
        ensure(contract.sender(mallory).burn(n(TOKEN)).is_err(), "burn gated")?;
        ensure(contract.sender(mallory).change_send_whitelist(mallory, true).is_err(), "whitelist gated")?;
        Ok(())
    }

    #[motsu::test]
    fn burn_clears_freeze(
        contract: Contract<URWA721>,
        admin: Address,
        holder: Address,
    ) -> Result<(), TestErr> {
        setup_allowlisted(&contract, admin, holder)?;
        contract.sender(admin).safe_mint(holder, n(TOKEN)).ortest("mint")?;
        contract.sender(admin).set_frozen_tokens(holder, n(TOKEN), true).ortest("freeze")?;
        contract.sender(admin).burn(n(TOKEN)).ortest("burn")?;
        // Token no longer exists.
        ensure(contract.sender(admin).owner_of(n(TOKEN)).is_err(), "token gone")?;
        ensure(!contract.sender(admin).get_frozen_tokens(holder, n(TOKEN)), "freeze cleared")?;
        Ok(())
    }
}
