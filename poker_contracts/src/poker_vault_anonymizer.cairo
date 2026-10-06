/// STRK20 privacy-pool anonymizer for poker chips.
/// Plan B buy-in (STRK → vault chips) and Plan D P2.2 unshield/claim
/// (vault chips → STRK), dispatched by `operation` in one entry point.
///
/// The STRK20 privacy pool calls `privacy_invoke` on this contract from
/// inside a private transaction (InvokeExternal phase, at most once per tx,
/// entrypoint selected by the protocol's INVOKE_SELECTOR). The pool
/// deserializes the dapp's calldata into this function's parameters per the
/// contract ABI, and before the call it has already transferred the user's
/// spent input-note tokens to this helper — `amount` of them — via a plain
/// public transfer.
///
/// `calldata[0]` (operation) selects the flow:
///
/// - `0` BuyIn:  approve the vault to pull `amount` STRK from the helper and
///   credit the player's chips 1:1 (`deposit_for`). Whatever STRK remains in
///   the helper is "change": approve the pool to pull it back and return it
///   as a single `OpenNoteDeposit` credited to `note_id` (empty span when
///   there is no change, so `note_id` may be 0 on an exact buy-in).
/// - `1` Withdraw: burn `amount` of the player's chips 1:1 (`burn_chips`;
///   this helper must be the vault's authorized helper) and return the
///   helper's whole STRK balance as one `OpenNoteDeposit` credited to
///   `note_id` (`note_id` must be non-zero). A zero balance means the pool
///   sent no input — revert rather than credit an empty note.
///
/// Client calldata (STRK20 invoke action, 5 items):
///   `[operation, player, amount_lo, amount_hi, "${openNoteIds[N]}"]`
///
/// ## STRK20 integration rules honored
///
/// - Approve (never transfer) the pool to pull outputs; the pool executes
///   the pull when applying the deposits.
/// - Return exactly `Span<OpenNoteDeposit>`; no zero-amount entries.
/// - u256 → u128 guard on note amounts (pool note amounts are u128).
/// - Per-token temp balance must end exactly zero after the pool pulls.
/// - Only the pool may call `privacy_invoke`.
///
/// Deployment: constructor takes the maintenance owner (may rebind the vault
/// via `set_vault`), the PokerVault, and the STRK20 privacy pool addresses.
use starknet::ContractAddress;

/// `privacy_invoke` operation: convert pool-supplied STRK into chips.
pub const OP_BUY_IN: felt252 = 0;
/// `privacy_invoke` operation: burn chips, return STRK as an open note.
pub const OP_WITHDRAW: felt252 = 1;

/// Open-note deposit entry returned by `privacy_invoke` to the STRK20 pool
/// (shape mandated by the privacy-pool protocol).
#[derive(Copy, Drop, Serde)]
pub struct OpenNoteDeposit {
    pub note_id: felt252,
    pub token: ContractAddress,
    pub amount: u128,
}

/// Minimal vault surface used by the anonymizer (selector-compatible with
/// PokerVault; keeps the helper decoupled from the full vault ABI).
#[starknet::interface]
pub trait IVaultLike<TContractState> {
    fn deposit_for(ref self: TContractState, player: ContractAddress, amount: u256);
    /// P1-2 会话委托（私密路径）：anonymizer 即 vault 的 authorized_helper，
    /// 在同一笔私交易里为 player 登记会话交易公钥。
    fn set_session_tx_pk_for(
        ref self: TContractState,
        player: ContractAddress,
        pk: felt252,
        expires_at: u64,
    );
    fn burn_chips(ref self: TContractState, player: ContractAddress, amount: u256);
    /// #25 全链路私密提现：烧 player 筹码并把背书 STRK 转给 recipient。
    /// vault 侧信任门 = unshield_helper（本合约需被 set_unshield_helper）。
    fn withdraw_to(
        ref self: TContractState,
        player: ContractAddress,
        recipient: ContractAddress,
        amount: u256,
    );
    fn token(self: @TContractState) -> ContractAddress;
}

#[starknet::interface]
pub trait IPokerVaultAnonymizer<TContractState> {
    /// Called by the STRK20 privacy pool inside a private transaction.
    /// `operation` selects BuyIn (0: STRK → chips for `player`, surplus
    /// returns as the open note `note_id`) or Withdraw (1: burn `amount` of
    /// `player`'s chips, the helper's whole STRK balance returns as the open
    /// note `note_id`). Returns exactly the open-note deposits for the pool
    /// to apply.
    fn privacy_invoke(
        ref self: TContractState,
        operation: felt252,
        player: ContractAddress,
        amount: u256,
        note_id: felt252,
    ) -> Span<OpenNoteDeposit>;
    /// P1-2 会话委托（私密买入 + 登记同笔完成）：与
    /// [`IPokerVaultAnonymizer::privacy_invoke`] 同协议，但 BuyIn 操作额外
    /// 在**同一笔私交易**里为 player 登记会话交易公钥
    /// （vault `set_session_tx_pk_for`）——避免玩家钱包公开发起登记而
    /// 建立 `main_wallet ↔ player` 链接（破坏 STRK20 付款人隐藏）。
    /// `tx_pk == 0` 表示本次不登记（等价 privacy_invoke）。
    fn privacy_invoke_with_session(
        ref self: TContractState,
        operation: felt252,
        player: ContractAddress,
        amount: u256,
        note_id: felt252,
        tx_pk: felt252,
        tx_pk_expires_at: u64,
    ) -> Span<OpenNoteDeposit>;
}

/// Vault / pool addresses for observability and SDK configuration.
#[starknet::interface]
pub trait IAnonymizerInfo<TContractState> {
    fn vault(self: @TContractState) -> ContractAddress;
    fn pool(self: @TContractState) -> ContractAddress;
}

/// Owner-gated maintenance: rebind the vault without redeploying the helper
/// (a vault upgrade would otherwise strand the helper on the old vault —
/// the helper's STRK flows are vault-bound via approve/deposit_for/burn_chips).
/// The owner is the deployer account recorded at construction.
#[starknet::interface]
pub trait IAnonymizerAdmin<TContractState> {
    fn set_vault(ref self: TContractState, vault: ContractAddress);
    fn owner(self: @TContractState) -> ContractAddress;
}

#[starknet::contract]
pub mod PokerVaultAnonymizer {
    use core::num::traits::Zero;
    use openzeppelin::token::erc20::interface::{IERC20Dispatcher, IERC20DispatcherTrait};
    use starknet::{
        ContractAddress, get_caller_address, get_contract_address,
        storage::{StoragePointerReadAccess, StoragePointerWriteAccess},
    };

    use super::{
        IAnonymizerAdmin, IAnonymizerInfo, IPokerVaultAnonymizer, IVaultLikeDispatcher,
        IVaultLikeDispatcherTrait, OpenNoteDeposit, OP_BUY_IN, OP_WITHDRAW,
    };

    #[storage]
    struct Storage {
        /// PokerVault that converts STRK to chips via deposit_for and burns
        /// them via burn_chips.
        vault: ContractAddress,
        /// STRK20 privacy pool — the only authorized caller.
        pool: ContractAddress,
        /// Maintenance owner (the deployer account): may rebind the vault.
        owner: ContractAddress,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        BuyInExecuted: BuyInExecuted,
        UnshieldExecuted: UnshieldExecuted,
        VaultRebound: VaultRebound,
    }

    #[derive(Drop, starknet::Event)]
    struct VaultRebound {
        vault: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    struct BuyInExecuted {
        /// Indexed: lets the backend reconcile a buy-in whose deposit
        /// receipt confirmation failed (RPC blip) by scanning events for
        /// the player instead of relying on one tx receipt fetch.
        #[key]
        player: ContractAddress,
        amount: u256,
        change: u128,
    }

    #[derive(Drop, starknet::Event)]
    struct UnshieldExecuted {
        /// Indexed: same reconciliation guarantee as BuyInExecuted.
        #[key]
        player: ContractAddress,
        amount: u256,
        recipient_note_id: felt252,
        out: u128,
    }

    #[constructor]
    fn constructor(
        ref self: ContractState,
        owner: ContractAddress,
        vault: ContractAddress,
        pool: ContractAddress,
    ) {
        assert!(!owner.is_zero(), "owner required");
        assert!(!vault.is_zero(), "vault required");
        assert!(!pool.is_zero(), "pool required");
        self.vault.write(vault);
        self.pool.write(pool);
        // Owner is explicit: UDC-based deploy pipelines execute the
        // constructor from the UDC address, so get_caller_address() would
        // strand set_vault behind an address nobody can act as.
        self.owner.write(owner);
    }

        fn privacy_invoke_impl(
        ref self: ContractState,
        operation: felt252,
        player: ContractAddress,
        amount: u256,
        note_id: felt252,
        tx_pk: felt252,
        tx_pk_expires_at: u64,
    ) -> Span<OpenNoteDeposit> {
        let pool = self.pool.read();
        assert!(get_caller_address() == pool, "caller is not the pool");
        assert!(!player.is_zero(), "player required");
        assert!(amount > 0_u256, "amount must be > 0");

        let vault = self.vault.read();
        let vault_dispatcher = IVaultLikeDispatcher { contract_address: vault };
        let token = vault_dispatcher.token();
        let token_dispatcher = IERC20Dispatcher { contract_address: token };
        let self_address = get_contract_address();

        if operation == OP_WITHDRAW {
            // Unshield（守恒模型，2026-09-07 修复）：withdraw_to 烧掉
            // player 的 amount 筹码并让 vault 把背书 STRK 释放进 helper，
            // helper 全额作为 recipient 的输出 note 记回池。
            // 旧实现用 burn_chips（无代币移动）+ 要求用户先用池内
            // 余额自筹注资——每领 X 销毁 X 价值（chips 烧掉、背书 STRK
            // 滞留 vault 无人可领、用户拿回的只是自己的钱），且把
            // "池内屏蔽余额 ≥ 领取额" 错立为前置。withdraw_to 模型下
            // 输出 note 由 vault 出资，无需任何池内预存。
            assert!(note_id != 0, "recipient note id required");
            vault_dispatcher.withdraw_to(player, self_address, amount);
            let remaining = token_dispatcher.balance_of(self_address);
            assert!(!remaining.is_zero(), "no unshield funds in helper");
            assert!(remaining.high == 0_u128, "unshield overflows u128");
            let out: u128 = remaining.low;
            let ok = token_dispatcher.approve(pool, remaining);
            assert!(ok, "pool approve failed");

            self.emit(UnshieldExecuted { player, amount, recipient_note_id: note_id, out });

            let mut deposits = core::array::ArrayTrait::new();
            deposits.append(OpenNoteDeposit { note_id, token, amount: out });
            deposits.span()
        } else if operation == OP_BUY_IN {
            // P1-2：私密买入同笔登记会话钥（tx_pk != 0 时）。anonymizer
            // 是 vault 的 authorized_helper（set_authorized_helper）。
            if !tx_pk.is_zero() {
                vault_dispatcher.set_session_tx_pk_for(player, tx_pk, tx_pk_expires_at);
            }
            // Buy in: approve the vault, then let it pull `amount` and
            // credit the player's chips 1:1.
            let ok = token_dispatcher.approve(vault, amount);
            assert!(ok, "vault approve failed");
            vault_dispatcher.deposit_for(player, amount);

            // Change = remaining helper balance (pool-funded surplus). The
            // pool pulls it via the approval below and credits the user's
            // `note_id`. Pool note amounts are u128, so the change must
            // fit — reject rather than silently truncate.
            let remaining = token_dispatcher.balance_of(self_address);
            if remaining.is_zero() {
                self.emit(BuyInExecuted { player, amount, change: 0 });
                let empty = core::array::ArrayTrait::new();
                return empty.span();
            }
            assert!(remaining.high == 0_u128, "change overflows u128");
            let change: u128 = remaining.low;
            assert!(note_id != 0, "change note id required");
            let ok = token_dispatcher.approve(pool, remaining);
            assert!(ok, "pool approve failed");

            self.emit(BuyInExecuted { player, amount, change });

            let mut deposits = core::array::ArrayTrait::new();
            deposits.append(OpenNoteDeposit { note_id, token, amount: change });
            deposits.span()
        } else {
            assert!(false, "unknown operation");
            core::array::ArrayTrait::new().span()
        }
    }

#[abi(embed_v0)]
    impl AnonymizerImpl of super::IPokerVaultAnonymizer<ContractState> {
        fn privacy_invoke(
            ref self: ContractState,
            operation: felt252,
            player: ContractAddress,
            amount: u256,
            note_id: felt252,
        ) -> Span<OpenNoteDeposit> {
            privacy_invoke_impl(ref self, operation, player, amount, note_id, 0, 0)
        }

        fn privacy_invoke_with_session(
            ref self: ContractState,
            operation: felt252,
            player: ContractAddress,
            amount: u256,
            note_id: felt252,
            tx_pk: felt252,
            tx_pk_expires_at: u64,
        ) -> Span<OpenNoteDeposit> {
            privacy_invoke_impl(
                ref self,
                operation,
                player,
                amount,
                note_id,
                tx_pk,
                tx_pk_expires_at,
            )
        }


    }

    /// Vault / pool addresses for observability and SDK configuration.
    #[abi(embed_v0)]
    impl AnonymizerInfoImpl of IAnonymizerInfo<ContractState> {
        fn vault(self: @ContractState) -> ContractAddress {
            self.vault.read()
        }

        fn pool(self: @ContractState) -> ContractAddress {
            self.pool.read()
        }
    }

    /// Owner-gated maintenance: rebind the vault without redeploying.
    #[abi(embed_v0)]
    impl AnonymizerAdminImpl of IAnonymizerAdmin<ContractState> {
        fn set_vault(ref self: ContractState, vault: ContractAddress) {
            assert!(get_caller_address() == self.owner.read(), "only owner");
            assert!(!vault.is_zero(), "vault required");
            self.vault.write(vault);
            self.emit(VaultRebound { vault });
        }

        fn owner(self: @ContractState) -> ContractAddress {
            self.owner.read()
        }
    }
}

// ============================================================
// Tests (snforge): the test contract acts as the privacy pool.
// ============================================================

#[cfg(test)]
mod mock_token {
    use starknet::ContractAddress;

    #[starknet::interface]
    pub trait IMockToken<TContractState> {
        fn mint(ref self: TContractState, to: ContractAddress, amount: u256);
        fn approve(ref self: TContractState, spender: ContractAddress, amount: u256) -> bool;
        fn transfer(ref self: TContractState, recipient: ContractAddress, amount: u256) -> bool;
        fn transfer_from(
            ref self: TContractState,
            sender: ContractAddress,
            recipient: ContractAddress,
            amount: u256,
        ) -> bool;
        fn balance_of(self: @TContractState, account: ContractAddress) -> u256;
    }

    /// Minimal ERC-20 stand-in exposing the snake_case selectors the vault
    /// and anonymizer call through IERC20Dispatcher.
    #[starknet::contract]
    pub mod MockToken {
        use starknet::{ContractAddress, get_caller_address};
        use starknet::storage::{Map, StorageMapReadAccess, StorageMapWriteAccess};

        #[storage]
        struct Storage {
            balances: Map<ContractAddress, u256>,
            allowances: Map<(ContractAddress, ContractAddress), u256>,
        }

        #[abi(embed_v0)]
        impl MockTokenImpl of super::IMockToken<ContractState> {
            fn mint(ref self: ContractState, to: ContractAddress, amount: u256) {
                let current = self.balances.read(to);
                self.balances.write(to, current + amount);
            }

            fn approve(ref self: ContractState, spender: ContractAddress, amount: u256) -> bool {
                let caller = get_caller_address();
                self.allowances.write((caller, spender), amount);
                true
            }

            fn transfer(ref self: ContractState, recipient: ContractAddress, amount: u256) -> bool {
                let caller = get_caller_address();
                let from_balance = self.balances.read(caller);
                assert!(from_balance >= amount, "insufficient balance");
                self.balances.write(caller, from_balance - amount);
                let to_balance = self.balances.read(recipient);
                self.balances.write(recipient, to_balance + amount);
                true
            }

            fn transfer_from(
                ref self: ContractState,
                sender: ContractAddress,
                recipient: ContractAddress,
                amount: u256,
            ) -> bool {
                let spender = get_caller_address();
                let key = (sender, spender);
                let allowed = self.allowances.read(key);
                assert!(allowed >= amount, "insufficient allowance");
                self.allowances.write(key, allowed - amount);
                let from_balance = self.balances.read(sender);
                assert!(from_balance >= amount, "insufficient balance");
                self.balances.write(sender, from_balance - amount);
                let to_balance = self.balances.read(recipient);
                self.balances.write(recipient, to_balance + amount);
                true
            }

            fn balance_of(self: @ContractState, account: ContractAddress) -> u256 {
                self.balances.read(account)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use core::byte_array::ByteArray;
    use starknet::{ContractAddress, get_contract_address};
    use snforge_std::{
        ContractClassTrait, DeclareResultTrait, declare,
        cheatcodes::execution_info::caller_address::{
            start_cheat_caller_address, stop_cheat_caller_address,
        },
    };

    use super::mock_token::{IMockTokenDispatcher, IMockTokenDispatcherTrait};
    use super::{
        IAnonymizerAdminDispatcher, IAnonymizerAdminDispatcherTrait, IAnonymizerInfoDispatcher,
        IAnonymizerInfoDispatcherTrait, IPokerVaultAnonymizerDispatcher,
        IPokerVaultAnonymizerDispatcherTrait,
    };
    use crate::poker_vault::{IPokerVaultDispatcher, IPokerVaultDispatcherTrait};

    fn deploy_contract(name: ByteArray, calldata: @Array<felt252>) -> ContractAddress {
        let class = declare(name).unwrap().contract_class();
        let (address, _) = class.deploy(calldata).unwrap();
        address
    }

    #[derive(Drop)]
    struct Setup {
        token: ContractAddress,
        vault: ContractAddress,
        anonymizer: ContractAddress,
        player: ContractAddress,
    }

    /// Deploy token + vault + anonymizer with `pool` as the authorized
    /// caller. No funds minted yet.
    fn setup(pool: ContractAddress) -> Setup {
        let test_addr = get_contract_address();
        let zero: ContractAddress = 0.try_into().unwrap();
        let token = deploy_contract("MockToken", @array![]);
        let vault = deploy_contract(
            "PokerVault",
            @array![test_addr.into(), token.into(), zero.into()],
        );
        let anonymizer = deploy_contract(
            "PokerVaultAnonymizer",
            @array![test_addr.into(), vault.into(), pool.into()],
        );
        let player: ContractAddress = 1234567.try_into().unwrap();
        Setup { token, vault, anonymizer, player }
    }

    #[test]
    fn deposit_for_credits_player_1to1() {
        let test_addr = get_contract_address();
        let s = setup(test_addr);
        let tok = IMockTokenDispatcher { contract_address: s.token };
        let vault = IPokerVaultDispatcher { contract_address: s.vault };

        tok.mint(test_addr, 1000);
        tok.approve(s.vault, 400);
        vault.deposit_for(s.player, 400);

        assert!(vault.chip_balance(s.player) == 400, "chips not credited");
        assert!(vault.chip_balance(test_addr) == 0, "caller must not gain");
        assert!(vault.total_chips() == 400, "total chips");
    }

    // ---- operation 0: buy-in ----

    #[test]
    fn privacy_invoke_buy_in_deposits_and_returns_change() {
        let test_addr = get_contract_address();
        let s = setup(test_addr); // pool == test contract
        let tok = IMockTokenDispatcher { contract_address: s.token };

        // The pool transfers the user's shielded inputs to the helper
        // before privacy_invoke runs.
        tok.mint(test_addr, 1000);
        tok.transfer(s.anonymizer, 1000);

        let anon = IPokerVaultAnonymizerDispatcher { contract_address: s.anonymizer };
        let deposits = anon.privacy_invoke(0, s.player, 400, 7);

        assert!(deposits.len() == 1, "one change note");
        let change = *deposits.at(0);
        assert!(change.note_id == 7, "note id mismatch");
        assert!(change.token == s.token, "token mismatch");
        assert!(change.amount == 600, "change mismatch");

        let vault = IPokerVaultDispatcher { contract_address: s.vault };
        assert!(vault.chip_balance(s.player) == 400, "chips not credited");
        assert!(tok.balance_of(s.anonymizer) == 600, "helper balance");

        // The pool pulls the change via the approval the helper granted.
        assert!(tok.transfer_from(s.anonymizer, test_addr, 600), "pool pull");
        assert!(tok.balance_of(s.anonymizer) == 0, "helper must be empty");
    }

    #[test]
    fn privacy_invoke_buy_in_exact_amount_empty_change() {
        let test_addr = get_contract_address();
        let s = setup(test_addr);
        let tok = IMockTokenDispatcher { contract_address: s.token };

        tok.mint(test_addr, 400);
        tok.transfer(s.anonymizer, 400);

        let anon = IPokerVaultAnonymizerDispatcher { contract_address: s.anonymizer };
        let deposits = anon.privacy_invoke(0, s.player, 400, 0);

        assert!(deposits.len() == 0, "no change expected");
        let vault = IPokerVaultDispatcher { contract_address: s.vault };
        assert!(vault.chip_balance(s.player) == 400, "chips not credited");
        assert!(tok.balance_of(s.anonymizer) == 0, "helper must be empty");
    }

    /// P1-2 私密买入 + 会话委托同笔登记：池在私交易里调
    /// `privacy_invoke_with_session`（BuyIn + tx_pk）→ vault 侧
    /// `set_session_tx_pk_for` 在同一笔内完成登记（anonymizer 须先被
    /// 设为 vault 的 authorized_helper——生产部署顺序同此）。
    #[test]
    fn privacy_buy_in_registers_session_tx_pk_atomically() {
        let test_addr = get_contract_address();
        let s = setup(test_addr);
        let tok = IMockTokenDispatcher { contract_address: s.token };
        let vault = IPokerVaultDispatcher { contract_address: s.vault };

        // 部署顺序：vault owner 把 anonymizer 设为 authorized_helper
        //（与 burn_chips/withdraw_to 同一信任门）。
        vault.set_authorized_helper(s.anonymizer);

        tok.mint(test_addr, 400);
        tok.transfer(s.anonymizer, 400);

        let tx_pk = 0xC0DE_felt252;
        let expiry = starknet::get_block_timestamp() + 86_400 * 30;
        let anon = IPokerVaultAnonymizerDispatcher { contract_address: s.anonymizer };
        let deposits = anon.privacy_invoke_with_session(0, s.player, 400, 0, tx_pk, expiry);

        assert!(deposits.len() == 0, "no change expected");
        assert!(vault.chip_balance(s.player) == 400, "chips credited");
        assert!(
            vault.active_session_tx_pk(s.player) == tx_pk,
            "session tx pk registered in the SAME private tx as the buy-in"
        );
    }

    #[test]
    #[should_panic(expected: "change overflows u128")]
    fn privacy_invoke_buy_in_rejects_change_over_u128() {
        let test_addr = get_contract_address();
        let s = setup(test_addr);
        let tok = IMockTokenDispatcher { contract_address: s.token };

        // 2^128 + 1 wei remaining as change — pool note amounts are u128.
        let huge: u256 = 340282366920938463463374607431768211457; // 2^128 + 1
        tok.mint(test_addr, huge);
        tok.transfer(s.anonymizer, huge);

        let anon = IPokerVaultAnonymizerDispatcher { contract_address: s.anonymizer };
        anon.privacy_invoke(0, s.player, 1, 7);
    }

    #[test]
    #[should_panic(expected: "caller is not the pool")]
    fn privacy_invoke_rejects_non_pool_caller() {
        let stranger: ContractAddress = 987654.try_into().unwrap();
        let s = setup(stranger); // pool != test contract
        let anon = IPokerVaultAnonymizerDispatcher { contract_address: s.anonymizer };
        anon.privacy_invoke(0, s.player, 100, 1);
    }

    // ---- operation 1: withdraw / claim (Plan D P2.2) ----

    #[test]
    fn privacy_invoke_withdraw_burns_chips_and_returns_output_note() {
        let test_addr = get_contract_address();
        let s = setup(test_addr); // pool == test contract
        let tok = IMockTokenDispatcher { contract_address: s.token };
        let vault = IPokerVaultDispatcher { contract_address: s.vault };

        // Authorize the helper, then fund the player's chips (buy-in path).
        // deposit_for 已把 400 STRK 背书金留在 vault。
        vault.set_authorized_helper(s.anonymizer);
        vault.set_unshield_helper(s.anonymizer);
        tok.mint(test_addr, 1000);
        tok.approve(s.vault, 400);
        vault.deposit_for(s.player, 400);
        assert!(vault.chip_balance(s.player) == 400, "chips credited");

        // 守恒模型：无需任何预注资——withdraw_to 烧 300 筹码并把 vault
        // 里的背书 STRK 释放给 helper（对比旧 burn_chips 模型要求池/用户
        // 预先转 300 进 helper）。
        let vault_balance_before = tok.balance_of(s.vault);

        let anon = IPokerVaultAnonymizerDispatcher { contract_address: s.anonymizer };
        let deposits = anon.privacy_invoke(1, s.player, 300, 42);

        assert!(deposits.len() == 1, "one output note");
        let note = *deposits.at(0);
        assert!(note.note_id == 42, "recipient note id");
        assert!(note.token == s.token, "token mismatch");
        assert!(note.amount == 300, "output amount");

        // Chips burned 1:1 AND the backing STRK left the vault into the
        // helper — value conserved (user: chips -300, note +300).
        assert!(vault.chip_balance(s.player) == 100, "chips burned");
        assert!(vault.total_chips() == 100, "total chips reduced");
        assert!(
            tok.balance_of(s.vault) == vault_balance_before - 300,
            "backing STRK released from vault"
        );
        assert!(tok.balance_of(s.anonymizer) == 300, "helper holds output pre-pull");

        // The pool pulls the output note via the helper's approval.
        assert!(tok.transfer_from(s.anonymizer, test_addr, 300), "pool pull");
        assert!(tok.balance_of(s.anonymizer) == 0, "helper must be empty after pull");
    }

    #[test]
    #[should_panic(expected: "Only the unshield helper")]
    fn privacy_invoke_withdraw_fails_without_helper_authorization() {
        let test_addr = get_contract_address();
        let s = setup(test_addr);
        // set_unshield_helper NOT called — withdraw_to must refuse.
        // （守恒模型无需预注资：helper 空、vault 空，任何出资都不存在。）
        let anon = IPokerVaultAnonymizerDispatcher { contract_address: s.anonymizer };
        anon.privacy_invoke(1, s.player, 300, 42);
    }

    #[test]
    #[should_panic(expected: "caller is not the pool")]
    fn privacy_invoke_withdraw_rejects_non_pool_caller() {
        let stranger: ContractAddress = 987654.try_into().unwrap();
        let s = setup(stranger);
        let anon = IPokerVaultAnonymizerDispatcher { contract_address: s.anonymizer };
        anon.privacy_invoke(1, s.player, 100, 1);
    }

    #[test]
    #[should_panic(expected: "Insufficient chip balance")]
    fn privacy_invoke_withdraw_rejects_overdraw() {
        let test_addr = get_contract_address();
        let s = setup(test_addr);
        let vault = IPokerVaultDispatcher { contract_address: s.vault };
        vault.set_unshield_helper(s.anonymizer);
        // Player has NO chips — withdraw_to must refuse at the balance assert.
        let anon = IPokerVaultAnonymizerDispatcher { contract_address: s.anonymizer };
        anon.privacy_invoke(1, s.player, 300, 42);
    }

    #[test]
    #[should_panic(expected: "recipient note id required")]
    fn privacy_invoke_withdraw_rejects_zero_note_id() {
        let test_addr = get_contract_address();
        let s = setup(test_addr);
        let vault = IPokerVaultDispatcher { contract_address: s.vault };
        vault.set_unshield_helper(s.anonymizer);
        let anon = IPokerVaultAnonymizerDispatcher { contract_address: s.anonymizer };
        anon.privacy_invoke(1, s.player, 300, 0);
    }

    // ---- dispatch ----

    #[test]
    #[should_panic(expected: "unknown operation")]
    fn privacy_invoke_rejects_unknown_operation() {
        let test_addr = get_contract_address();
        let s = setup(test_addr);
        let anon = IPokerVaultAnonymizerDispatcher { contract_address: s.anonymizer };
        anon.privacy_invoke(2, s.player, 100, 1);
    }

    // ---- maintenance: set_vault ----

    #[test]
    fn set_vault_rebinds_vault_for_owner() {
        let test_addr = get_contract_address();
        let s = setup(test_addr); // 构造 caller = 部署者 → owner
        let anon_admin = IAnonymizerAdminDispatcher { contract_address: s.anonymizer };
        assert!(anon_admin.owner() == test_addr, "deployer must be owner");

        let zero: ContractAddress = 0.try_into().unwrap();
        let new_vault = deploy_contract(
            "PokerVault",
            @array![test_addr.into(), s.token.into(), zero.into()],
        );
        anon_admin.set_vault(new_vault);
        let anon_info = IAnonymizerInfoDispatcher { contract_address: s.anonymizer };
        assert!(anon_info.vault() == new_vault, "vault not rebound");
    }

    #[test]
    #[should_panic(expected: "only owner")]
    fn set_vault_rejects_non_owner() {
        let test_addr = get_contract_address();
        let s = setup(test_addr);
        let intruder: ContractAddress = 987654.try_into().unwrap();
        start_cheat_caller_address(s.anonymizer, intruder);
        IAnonymizerAdminDispatcher { contract_address: s.anonymizer }
            .set_vault(98765.try_into().unwrap());
        stop_cheat_caller_address(s.anonymizer);
    }
}
