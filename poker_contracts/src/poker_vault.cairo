/// Chip Vault: deposit STRK20 → chip balance, withdraw chip → STRK20.
///
/// The vault maintains per-player chip balances that the settlement contract
/// updates after each verified hand.
///
/// ## Security
///
/// - Only the settlement contract may call `apply_settlement`; it is the sole
///   path that moves chips between players for hands.
/// - `withdraw()` is permissionless but only up to the caller's chip balance.
/// - Pausing halts new deposits and withdrawals (settlement application is
///   also gated in this deployment for simplicity).
/// - Session tx-pk storage visibility (P1-2, 2026-09-10): `session_tx_pk` /
///   expiry are PUBLIC storage — the privacy buy-in path (anonymizer +
///   `set_session_tx_pk_for`) hides the PAYER, not the chip-holder's state
///   deltas (`chip_balances` / `session_last_activity` are already public).
///   The exposed binding is "chip-holder address ↔ session key ↔ validity
///   window", i.e. a playing window on an already-public address; it never
///   links to the funding wallet. Do not treat it as a privacy defect —
///   changing it would require a shielded registry.
use openzeppelin::access::ownable::OwnableComponent;
use openzeppelin::security::pausable::PausableComponent;
use openzeppelin::token::erc20::interface::{IERC20Dispatcher, IERC20DispatcherTrait};
use starknet::ContractAddress;
use starknet::storage::{
    Map, StorageMapReadAccess, StorageMapWriteAccess, StoragePointerReadAccess,
    StoragePointerWriteAccess,
};

#[starknet::interface]
pub trait IPokerVault<TContractState> {
    /// Deposit STRK20 tokens and credit chip balance 1:1.
    fn deposit(ref self: TContractState, amount: u256);
    /// Deposit STRK20 tokens credited to `player` (caller pays, 1:1).
    ///
    /// Permissionless by design: the STRK20 privacy-pool anonymizer calls this
    /// inside a private transaction, so the on-chain payer is the anonymizer
    /// (funded by the pool) while the chips land on the game player. Anyone
    /// may also gift chips to another player through the same path.
    fn deposit_for(ref self: TContractState, player: ContractAddress, amount: u256);
    /// Withdraw up to `amount` chips as STRK20 tokens.
    fn withdraw(ref self: TContractState, amount: u256);

    /// #25 全链路私密提现：burn `player` 的 `amount` 筹码，STRK 直接转到
    /// `recipient`（如 unshield helper / 隐私池），**不经过玩家公开钱包**。
    /// 仅授权 helper 可调用（与 `burn_chips` 同一信任门）。
    fn withdraw_to(
        ref self: TContractState,
        player: ContractAddress,
        recipient: ContractAddress,
        amount: u256,
    );

    /// Plan D P2.2 (unshield): burn `player`'s chips without any token
    /// movement. Only the authorized helper (PokerVaultAnonymizer) may call
    /// it; the STRK conservation happens inside the privacy pool (the pool
    /// transfers the user's burned input note to the helper, which returns
    /// it to the pool as the recipient's output note).
    fn burn_chips(ref self: TContractState, player: ContractAddress, amount: u256);

    /// Owner-gated: authorize the helper contract allowed to call
    /// `withdraw_to`（#25 全链路私密提现的 unshield helper）。
    fn set_unshield_helper(ref self: TContractState, helper: ContractAddress);
    /// View: the authorized unshield helper.
    fn unshield_helper(self: @TContractState) -> ContractAddress;

    /// Owner-gated: authorize the helper contract allowed to call
    /// `burn_chips` (the PokerVaultAnonymizer deployment).
    fn set_authorized_helper(ref self: TContractState, helper: ContractAddress);

    // ===== #33 在局锁定（牌局未结束取款逃单 / 结算砖死风险，见 TODO.md #33）=====

    /// Owner-gated（operator）：入座/开局时锁定 `player` 的 `amount` 筹码。
    /// 锁定额度只能被结算（apply_settlement 负 delta 优先扣锁定）消耗，
    /// 玩家取款路径只能动未锁定部分。
    fn lock(ref self: TContractState, player: ContractAddress, amount: u256);
    /// Owner-gated（operator）：结算/续局后刷新 session 时钟。
    fn refresh_session(ref self: TContractState, player: ContractAddress);
    /// 无许可自助解锁：`block.timestamp > last_activity + lock_ttl` 后任何人
    /// 可解锁（后端失联时玩家资金不被无限期冻结）。TTL=0 表示禁用自助解锁。
    fn unlock_after_deadline(ref self: TContractState, player: ContractAddress);
    /// Owner-gated: 调整自助解锁 TTL（秒）。
    fn set_lock_ttl(ref self: TContractState, ttl: u64);
    /// Owner-gated: 应急强制解锁（运营应急通道）。
    fn force_unlock(ref self: TContractState, player: ContractAddress);
    /// View: 锁定中的筹码。
    fn locked_balance(self: @TContractState, player: ContractAddress) -> u256;
    /// View: session 时钟（0 = 无活跃 session）。
    fn session_last_activity(self: @TContractState, player: ContractAddress) -> u64;
    /// View: 自助解锁 TTL（秒；0 = 禁用）。
    fn lock_ttl(self: @TContractState) -> u64;
    /// View: 是否存在活跃在局 session。
    fn session_active(self: @TContractState, player: ContractAddress) -> bool;

    /// 会话委托公钥登记（P1-2 修复的链上锚点，2026-09-10）：玩家把当前
    /// **会话交易公钥**（Stark Schnorr 32B 压缩点，felt）登记到 vault。
    /// 游戏服务器在 join 接受点经 [`IPokerVault::session_tx_pk`] 核验
    /// "座位声称的会话钥 == 链上登记钥"，VM 层交易签名按座位登记钥
    /// 验证——替代可公开推导的确定性身份（sk = H(wallet) 的冒名面）。
    ///
    /// 生命周期：买入/rebuy 时与 deposit/lock **同一笔 multicall** 调用
    /// （单钱包交互）；重连只需服务端 view，零钱包交互；latest-wins——
    /// 新登记自动顶掉旧钥（换设备/钥泄露后自救）。不设 owner 门与
    /// pause 门：密钥轮换是安全通道，应急暂停时也应可用。
    ///
    /// 校验：`pk != 0`；`expires_at > block.timestamp`（撤销用
    /// [`IPokerVault::clear_session_tx_pk`]，而不是登记一个已过期值）。
    fn set_session_tx_pk(ref self: TContractState, pk: felt252, expires_at: u64);
    /// 私密买入路径的代理登记（STRK20 隐私兼容）：仅 `authorized_helper`
    /// （PokerVaultAnonymizer，与 `burn_chips`/`withdraw_to` 同一信任门）
    /// 可代 `player` 登记——anonymizer 在**同一笔 private tx** 里
    /// `[deposit_for + set_session_tx_pk_for]`，避免玩家钱包公开发起
    /// 登记而建立 `main_wallet ↔ player` 链接（破坏 STRK20 付款人隐藏）。
    fn set_session_tx_pk_for(
        ref self: TContractState,
        player: ContractAddress,
        pk: felt252,
        expires_at: u64,
    );
    /// 撤销会话委托（仅登记人本人；踢出/登出的链上侧自主撤销通道）。
    fn clear_session_tx_pk(ref self: TContractState);
    /// View: 登记的 `(pk, expires_at)`（pk = 0 表示未登记）。
    fn session_tx_pk(self: @TContractState, player: ContractAddress) -> (felt252, u64);
    /// View: 当前**有效**的会话公钥——未登记或已过期返回 0
    /// （`block.timestamp >= expires_at` 视为过期）。
    fn active_session_tx_pk(self: @TContractState, player: ContractAddress) -> felt252;

    /// Read chip balance of a player.
    fn chip_balance(self: @TContractState, player: ContractAddress) -> u256;
    /// Token (STRK20) address.
    fn token(self: @TContractState) -> ContractAddress;
    /// Total chips in circulation.
    fn total_chips(self: @TContractState) -> u256;
    /// Apply a net chip delta to a player (settlement contract only).
    /// `delta > 0` credits chips, `delta < 0` debits, `delta == 0` is a no-op.
    fn apply_settlement(ref self: TContractState, player: ContractAddress, delta: i128);
    /// Set the settlement contract address (owner only).
    fn set_settlement_contract(ref self: TContractState, settlement_contract: ContractAddress);
    /// Emergency pause (owner only).
    fn pause(ref self: TContractState);
    /// Emergency unpause (owner only).
    fn unpause(ref self: TContractState);
    /// Whether the vault is paused.
    fn paused(self: @TContractState) -> bool;
    /// Register a payout claim commitment for the caller
    /// (docs/design/SETTLEMENT_PRIVACY_PLAN.md Part A Phase 1): `commitment =
    /// poseidon(secret)` where `secret` is a client-side capability. Winners'
    /// settlements become claimable from the settlement escrow only by
    /// revealing `secret` with `hand_binding` and `amount` — the secret
    /// never leaves the client until the claim itself.
    fn register_payout_commitment(ref self: TContractState, commitment: felt252);
    /// Read the registered payout commitment of `player` (0 = unregistered).
    fn payout_commitment(self: @TContractState, player: ContractAddress) -> felt252;
    /// Settlement-contract gated: transfer `amount` tokens from the vault to
    /// `escrow` (the claim helper), funding a hand's private-payout pot.
    /// Phase 1 pays winners from escrow claims instead of crediting public
    /// chip balances.
    fn settlement_fund_escrow(
        ref self: TContractState,
        escrow: ContractAddress,
        hand_binding: felt252,
        amount: u256,
    );
}

#[starknet::contract]
pub mod PokerVault {
    use core::num::traits::Zero;
    use openzeppelin::access::ownable::OwnableComponent;
    use openzeppelin::security::pausable::PausableComponent;
    use openzeppelin::token::erc20::interface::{IERC20Dispatcher, IERC20DispatcherTrait};
    use starknet::ContractAddress;
    use starknet::storage::{
        Map, StorageMapReadAccess, StorageMapWriteAccess, StoragePointerReadAccess,
        StoragePointerWriteAccess,
    };

    component!(path: OwnableComponent, storage: ownable, event: OwnableEvent);
    component!(path: PausableComponent, storage: pausable, event: PausableEvent);

    #[abi(embed_v0)]
    impl OwnableImpl = OwnableComponent::OwnableImpl<ContractState>;
    impl OwnableInternalImpl = OwnableComponent::InternalImpl<ContractState>;

    #[abi(embed_v0)]
    impl PausableImpl = PausableComponent::PausableImpl<ContractState>;
    impl PausableInternalImpl = PausableComponent::InternalImpl<ContractState>;

    #[storage]
    struct Storage {
        /// STRK20 token contract address.
        token_address: ContractAddress,
        /// Per-player chip balance (1 chip = 1 smallest STRK20 unit).
        chip_balances: Map<ContractAddress, u256>,
        /// Total chips in circulation.
        total_chips: u256,
        /// Settlement contract authorized to call apply_settlement.
        settlement_contract: ContractAddress,
        /// Helper contract authorized to call burn_chips (PokerVaultAnonymizer).
        authorized_helper: ContractAddress,
        /// #25：unshield 方向 helper（chip_to_note 提现通道）。
        unshield_helper: ContractAddress,
        /// #33 在局锁定：player → 锁定筹码（入局额度；结算优先从这里扣）。
        locked: Map<ContractAddress, u256>,
        /// #33 在局 session：player → last_activity（秒）。解锁时钟基准。
        session_last_activity: Map<ContractAddress, u64>,
        /// #33 在局 session 活跃标志（与 last=0 哨兵解耦——测试/新链的
        /// block timestamp 可能为 0）。
        session_active: Map<ContractAddress, bool>,
        /// P1-2 会话委托公钥：player → Stark Schnorr 32B 压缩点（0 = 未登记）。
        session_tx_pk: Map<ContractAddress, felt252>,
        /// P1-2 会话委托过期时刻（秒；`block.timestamp >= expires_at` 失效）。
        session_tx_pk_expires_at: Map<ContractAddress, u64>,
        /// #33 自助解锁 TTL（秒；0 = 禁用自助解锁）。constructor 默认 12h。
        lock_ttl: u64,
        /// Per-player payout claim commitments (0 = unregistered).
        payout_commitments: Map<ContractAddress, felt252>,
        #[substorage(v0)]
        ownable: OwnableComponent::Storage,
        #[substorage(v0)]
        pausable: PausableComponent::Storage,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        #[flat]
        OwnableEvent: OwnableComponent::Event,
        #[flat]
        PausableEvent: PausableComponent::Event,
        Deposit: Deposit,
        Withdraw: Withdraw,
        ChipCredited: ChipCredited,
        ChipDebited: ChipDebited,
        SettlementContractSet: SettlementContractSet,
        AuthorizedHelperSet: AuthorizedHelperSet,
        UnshieldHelperSet: UnshieldHelperSet,
        Locked: Locked,
        SessionRefreshed: SessionRefreshed,
        Unlocked: Unlocked,
        SessionTxPkRegistered: SessionTxPkRegistered,
        SessionTxCleared: SessionTxCleared,
        PayoutCommitmentRegistered: PayoutCommitmentRegistered,
        EscrowFunded: EscrowFunded,
    }

    #[derive(Drop, starknet::Event)]
    struct SessionTxPkRegistered {
        player: ContractAddress,
        pk: felt252,
        expires_at: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct SessionTxCleared {
        player: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    struct PayoutCommitmentRegistered {
        player: ContractAddress,
        commitment: felt252,
    }

    #[derive(Drop, starknet::Event)]
    struct EscrowFunded {
        hand_binding: felt252,
        escrow: ContractAddress,
        amount: u256,
    }

    #[derive(Drop, starknet::Event)]
    struct UnshieldHelperSet {
        helper: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    struct Locked {
        player: ContractAddress,
        amount: u256,
    }

    #[derive(Drop, starknet::Event)]
    struct SessionRefreshed {
        player: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    struct Unlocked {
        player: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    struct AuthorizedHelperSet {
        helper: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    struct Deposit {
        player: ContractAddress,
        amount: u256,
    }

    #[derive(Drop, starknet::Event)]
    struct Withdraw {
        player: ContractAddress,
        amount: u256,
    }

    #[derive(Drop, starknet::Event)]
    struct ChipCredited {
        player: ContractAddress,
        amount: u256,
    }

    #[derive(Drop, starknet::Event)]
    struct ChipDebited {
        player: ContractAddress,
        amount: u256,
    }

    #[derive(Drop, starknet::Event)]
    struct SettlementContractSet {
        settlement_contract: ContractAddress,
    }

    #[constructor]
    fn constructor(
        ref self: ContractState,
        owner: ContractAddress,
        token_address: ContractAddress,
        settlement_contract: ContractAddress,
    ) {
        self.ownable.initializer(owner);
        self.token_address.write(token_address);
        self.settlement_contract.write(settlement_contract);
        self.authorized_helper.write(starknet::get_contract_address());
        // #33：自助解锁 TTL 默认 12h（owner 可经 set_lock_ttl 调整）
        self.lock_ttl.write(43200);
    }

    /// P1-2 会话委托登记写入的共享内部（参数校验 + 存储 + 事件）。
    fn write_session_tx_pk(
        ref self: ContractState,
        player: ContractAddress,
        pk: felt252,
        expires_at: u64,
    ) {
        assert!(!player.is_zero(), "Session tx pk player must be non-zero");
        assert!(!pk.is_zero(), "Session tx pk must be non-zero");
        let now = starknet::get_block_timestamp();
        assert!(expires_at > now, "Session tx pk expiry must be in the future");
        self.session_tx_pk.write(player, pk);
        self.session_tx_pk_expires_at.write(player, expires_at);
        self.emit(SessionTxPkRegistered { player, pk, expires_at });
    }

    /// #33：可花费余额 = 余额 − 锁定。所有玩家侧取款路径共用。
    fn assert_spendable(self: @ContractState, player: ContractAddress, amount: u256) {
        let current = self.chip_balances.read(player);
        assert!(current >= amount, "Insufficient chip balance");
        let locked = self.locked.read(player);
        assert!(
            current - amount >= locked,
            "Insufficient unlocked balance (in-hand lock)"
        );
    }

    #[abi(embed_v0)]
    impl IPokerVaultImpl of super::IPokerVault<ContractState> {
        fn deposit(ref self: ContractState, amount: u256) {
            self.pausable.assert_not_paused();
            assert!(amount > 0_u256, "Amount must be > 0");
            let caller = starknet::get_caller_address();
            self.pull_and_credit(caller, amount);
        }

        fn deposit_for(ref self: ContractState, player: ContractAddress, amount: u256) {
            self.pausable.assert_not_paused();
            assert!(amount > 0_u256, "Amount must be > 0");
            assert!(!player.is_zero(), "Player must be set");
            self.pull_and_credit(player, amount);
        }

        fn withdraw(ref self: ContractState, amount: u256) {
            self.pausable.assert_not_paused();
            assert!(amount > 0_u256, "Amount must be > 0");
            let caller = starknet::get_caller_address();

            let current = self.chip_balances.read(caller);
            assert!(current >= amount, "Insufficient chip balance");
            assert_spendable(@self, caller, amount);

            self.chip_balances.write(caller, current - amount);
            self.total_chips.write(self.total_chips.read() - amount);

            let token = self.token_address.read();
            let dispatcher = IERC20Dispatcher { contract_address: token };
            let ok = dispatcher.transfer(caller, amount);
            assert!(ok, "Token transfer failed");

            self.emit(Withdraw { player: caller, amount });
        }

        /// #25 全链路私密提现：burn `player` 的 `amount` 筹码，STRK 直接转到
        /// `recipient`（如 unshield helper / 隐私池），**不经过玩家公开钱包**。
        /// 仅授权 helper 可调用（与 `burn_chips` 同一信任门）。
        fn withdraw_to(
            ref self: ContractState,
            player: ContractAddress,
            recipient: ContractAddress,
            amount: u256,
        ) {
            self.pausable.assert_not_paused();
            assert!(
                starknet::get_caller_address() == self.unshield_helper.read(),
                "Only the unshield helper"
            );
            assert!(amount > 0_u256, "Amount must be > 0");
            assert!(!player.is_zero(), "Player must be set");
            assert!(!recipient.is_zero(), "Recipient must be set");

            let current = self.chip_balances.read(player);
            assert!(current >= amount, "Insufficient chip balance");
            assert_spendable(@self, player, amount);
            self.chip_balances.write(player, current - amount);
            self.total_chips.write(self.total_chips.read() - amount);

            let token = self.token_address.read();
            let dispatcher = IERC20Dispatcher { contract_address: token };
            let ok = dispatcher.transfer(recipient, amount);
            assert!(ok, "Token transfer failed");

            self.emit(ChipDebited { player, amount });
        }

        fn burn_chips(ref self: ContractState, player: ContractAddress, amount: u256) {
            self.pausable.assert_not_paused();
            assert!(
                starknet::get_caller_address() == self.authorized_helper.read(),
                "Only the authorized helper"
            );
            assert!(amount > 0_u256, "Amount must be > 0");
            assert!(!player.is_zero(), "Player must be set");
            assert_spendable(@self, player, amount);

            let current = self.chip_balances.read(player);
            assert!(current >= amount, "Insufficient chip balance");
            self.chip_balances.write(player, current - amount);
            self.total_chips.write(self.total_chips.read() - amount);
            self.emit(ChipDebited { player, amount });
        }

        fn set_authorized_helper(ref self: ContractState, helper: ContractAddress) {
            self.ownable.assert_only_owner();
            self.authorized_helper.write(helper);
            self.emit(AuthorizedHelperSet { helper });
        }

        // ===== #33 在局锁定 =====

        fn lock(ref self: ContractState, player: ContractAddress, amount: u256) {
            self.ownable.assert_only_owner();
            assert!(amount > 0_u256, "Amount must be > 0");
            assert!(!player.is_zero(), "Player must be set");
            let current = self.chip_balances.read(player);
            assert!(current >= amount, "Insufficient chip balance");
            let now = starknet::get_block_timestamp();
            self.locked.write(player, self.locked.read(player) + amount);
            self.session_last_activity.write(player, now);
            self.session_active.write(player, true);
            self.emit(Locked { player, amount });
        }

        fn refresh_session(ref self: ContractState, player: ContractAddress) {
            self.ownable.assert_only_owner();
            assert!(
                self.session_last_activity.read(player) != 0_u64,
                "No active session"
            );
            self.session_last_activity.write(player, starknet::get_block_timestamp());
            self.session_active.write(player, true);
            self.emit(SessionRefreshed { player });
        }

        fn unlock_after_deadline(ref self: ContractState, player: ContractAddress) {
            // 无许可自助解锁：后端失联时玩家资金不被无限期冻结（#33 必要组成）
            assert!(
                self.session_active.read(player),
                "No active session"
            );
            let ttl = self.lock_ttl.read();
            assert!(ttl != 0_u64, "Self unlock disabled");
            assert!(
                starknet::get_block_timestamp()
                    >= self.session_last_activity.read(player) + ttl,
                "Lock not expired"
            );
            self.locked.write(player, 0_u256);
            self.session_last_activity.write(player, 0_u64);
            self.session_active.write(player, false);
            self.emit(Unlocked { player });
        }

        fn set_lock_ttl(ref self: ContractState, ttl: u64) {
            self.ownable.assert_only_owner();
            self.lock_ttl.write(ttl);
        }

        fn force_unlock(ref self: ContractState, player: ContractAddress) {
            self.ownable.assert_only_owner();
            self.locked.write(player, 0_u256);
            self.session_last_activity.write(player, 0_u64);
            self.session_active.write(player, false);
            self.emit(Unlocked { player });
        }

        fn locked_balance(self: @ContractState, player: ContractAddress) -> u256 {
            self.locked.read(player)
        }

        fn session_last_activity(self: @ContractState, player: ContractAddress) -> u64 {
            self.session_last_activity.read(player)
        }

        /// View: 是否存在活跃在局 session。
        fn session_active(self: @ContractState, player: ContractAddress) -> bool {
            self.session_active.read(player)
        }

        fn set_session_tx_pk(ref self: ContractState, pk: felt252, expires_at: u64) {
            write_session_tx_pk(ref self, starknet::get_caller_address(), pk, expires_at);
        }

        fn set_session_tx_pk_for(
            ref self: ContractState,
            player: ContractAddress,
            pk: felt252,
            expires_at: u64,
        ) {
            assert!(
                starknet::get_caller_address() == self.authorized_helper.read(),
                "Only the authorized helper"
            );
            write_session_tx_pk(ref self, player, pk, expires_at);
        }

        fn clear_session_tx_pk(ref self: ContractState) {
            let player = starknet::get_caller_address();
            assert!(
                !self.session_tx_pk.read(player).is_zero(),
                "No session tx pk registered"
            );
            self.session_tx_pk.write(player, Zero::zero());
            self.session_tx_pk_expires_at.write(player, 0_u64);
            self.emit(SessionTxCleared { player });
        }

        fn session_tx_pk(self: @ContractState, player: ContractAddress) -> (felt252, u64) {
            (self.session_tx_pk.read(player), self.session_tx_pk_expires_at.read(player))
        }

        fn active_session_tx_pk(self: @ContractState, player: ContractAddress) -> felt252 {
            let pk = self.session_tx_pk.read(player);
            if pk.is_zero() {
                return Zero::zero();
            }
            let expires_at = self.session_tx_pk_expires_at.read(player);
            if starknet::get_block_timestamp() >= expires_at {
                return Zero::zero();
            }
            pk
        }

        fn lock_ttl(self: @ContractState) -> u64 {
            self.lock_ttl.read()
        }

        fn set_unshield_helper(ref self: ContractState, helper: ContractAddress) {
            self.ownable.assert_only_owner();
            self.unshield_helper.write(helper);
            self.emit(UnshieldHelperSet { helper });
        }

        fn unshield_helper(self: @ContractState) -> ContractAddress {
            self.unshield_helper.read()
        }

        fn register_payout_commitment(ref self: ContractState, commitment: felt252) {
            let caller = starknet::get_caller_address();
            assert!(commitment != 0, "Payout commitment required");
            self.payout_commitments.write(caller, commitment);
            self.emit(PayoutCommitmentRegistered { player: caller, commitment });
        }

        fn payout_commitment(self: @ContractState, player: ContractAddress) -> felt252 {
            self.payout_commitments.read(player)
        }

        fn settlement_fund_escrow(
            ref self: ContractState,
            escrow: ContractAddress,
            hand_binding: felt252,
            amount: u256,
        ) {
            let caller = starknet::get_caller_address();
            assert!(
                caller == self.settlement_contract.read(), "Only settlement contract",
            );
            assert!(amount > 0_u256, "Amount must be > 0");
            assert!(!escrow.is_zero(), "Escrow required");
            let token = self.token_address.read();
            let dispatcher = IERC20Dispatcher { contract_address: token };
            let ok = dispatcher.transfer(escrow, amount);
            assert!(ok, "Token transfer failed");
            self.emit(EscrowFunded { hand_binding, escrow, amount });
        }

        fn chip_balance(self: @ContractState, player: ContractAddress) -> u256 {
            self.chip_balances.read(player)
        }

        fn token(self: @ContractState) -> ContractAddress {
            self.token_address.read()
        }

        fn total_chips(self: @ContractState) -> u256 {
            self.total_chips.read()
        }

        fn apply_settlement(ref self: ContractState, player: ContractAddress, delta: i128) {
            let caller = starknet::get_caller_address();
            assert!(
                caller == self.settlement_contract.read(), "Only settlement contract",
            );

            if delta > 0_i128 {
                let delta_u64: u64 = delta.try_into().expect('delta positive fits u64');
                let amount: u256 = delta_u64.into();
                let current = self.chip_balances.read(player);
                self.chip_balances.write(player, current + amount);
                self.total_chips.write(self.total_chips.read() + amount);
                self.emit(ChipCredited { player, amount });
            } else if delta < 0_i128 {
                let abs_delta = -delta;
                let abs_delta_u64: u64 = abs_delta.try_into().expect('abs delta fits u64');
                let amount: u256 = abs_delta_u64.into();
                // #33：结算扣款**优先消耗锁定额度**——输家即使提走全部未锁定
                // 余额，锁定部分仍足以覆盖输额，结算不再被砖死。
                let locked = self.locked.read(player);
                let from_locked = if locked < amount { locked } else { amount };
                if from_locked != 0_u256 {
                    self.locked.write(player, locked - from_locked);
                }
                // 锁定部分本就是余额的一部分：全额扣减余额（winner 从托管拿钱）
                let current = self.chip_balances.read(player);
                assert!(current >= amount, "Insufficient chip balance");
                self.chip_balances.write(player, current - amount);
                self.total_chips.write(self.total_chips.read() - amount);
                self.emit(ChipDebited { player, amount });
            }
            // delta == 0: no-op.
        }

        fn set_settlement_contract(
            ref self: ContractState, settlement_contract: ContractAddress,
        ) {
            self.ownable.assert_only_owner();
            self.settlement_contract.write(settlement_contract);
            self.emit(SettlementContractSet { settlement_contract });
        }

        fn pause(ref self: ContractState) {
            self.ownable.assert_only_owner();
            self.pausable.pause();
        }

        fn unpause(ref self: ContractState) {
            self.ownable.assert_only_owner();
            self.pausable.unpause();
        }

        fn paused(self: @ContractState) -> bool {
            self.pausable.is_paused()
        }
    }

    /// Shared deposit path: pull STRK20 from the caller (caller must have
    /// approved the vault) and credit `player` 1:1. Used by both `deposit`
    /// (self-credit) and `deposit_for` (anonymizer / gifting credit).
    #[generate_trait]
    impl VaultInternalImpl of VaultInternalTrait {
        fn pull_and_credit(
            ref self: ContractState, player: ContractAddress, amount: u256,
        ) {
            let caller = starknet::get_caller_address();
            let token = self.token_address.read();

            let dispatcher = IERC20Dispatcher { contract_address: token };
            let ok = dispatcher
                .transfer_from(caller, starknet::get_contract_address(), amount);
            assert!(ok, "Token transfer failed");

            let current = self.chip_balances.read(player);
            self.chip_balances.write(player, current + amount);
            self.total_chips.write(self.total_chips.read() + amount);
            self.emit(Deposit { player, amount });
        }
    }
}
// ============================================================
// Tests (snforge): Part A Phase 1 payout-commitment registry +
// settlement-gated escrow funding.
// ============================================================

// ============================================================
// Tests (snforge)：#33 在局锁定 — 取款门 / 结算扣款顺序 / 超时自助解锁 /
// 非 helper 直调拒绝。withdraw_to 与 burn_chips 分别只放行 unshield/authorized helper。
// ============================================================

#[cfg(test)]
mod in_hand_lock_mocks {
    use starknet::{ContractAddress, get_caller_address};

    #[starknet::interface]
    pub trait ILockMockToken<ContractState> {
        fn mint(ref self: ContractState, to: ContractAddress, amount: u256);
        fn approve(ref self: ContractState, spender: ContractAddress, amount: u256) -> bool;
        fn balance_of(self: @ContractState, account: ContractAddress) -> u256;
        fn allowance(
            self: @ContractState,
            owner: ContractAddress,
            spender: ContractAddress,
        ) -> u256;
        fn transfer(ref self: ContractState, to: ContractAddress, amount: u256) -> bool;
        fn transfer_from(
            ref self: ContractState,
            from: ContractAddress,
            to: ContractAddress,
            amount: u256,
        ) -> bool;
    }

    #[starknet::contract]
    pub mod LockMockToken {
        use starknet::{ContractAddress, get_caller_address};
        use starknet::storage::{Map, StorageMapReadAccess, StorageMapWriteAccess};

        #[storage]
        struct Storage {
            balances: Map<ContractAddress, u256>,
            allowances: Map<(ContractAddress, ContractAddress), u256>,
        }

        #[constructor]
        fn constructor(ref self: ContractState) {}

        #[abi(embed_v0)]
        pub impl LockMockTokenImpl of super::ILockMockToken<ContractState> {
            fn mint(ref self: ContractState, to: ContractAddress, amount: u256) {
                let current = self.balances.read(to);
                self.balances.write(to, current + amount);
            }

            fn approve(
                ref self: ContractState,
                spender: ContractAddress,
                amount: u256,
            ) -> bool {
                let caller = get_caller_address();
                let current = self.allowances.read((caller, spender));
                self.allowances.write((caller, spender), current + amount);
                true
            }

            fn balance_of(self: @ContractState, account: ContractAddress) -> u256 {
                self.balances.read(account)
            }

            fn allowance(
                self: @ContractState,
                owner: ContractAddress,
                spender: ContractAddress,
            ) -> u256 {
                self.allowances.read((owner, spender))
            }

            fn transfer(ref self: ContractState, to: ContractAddress, amount: u256) -> bool {
                let caller = get_caller_address();
                let current = self.balances.read(caller);
                assert!(current >= amount, "insufficient token balance");
                self.balances.write(caller, current - amount);
                let to_current = self.balances.read(to);
                self.balances.write(to, to_current + amount);
                true
            }

            fn transfer_from(
                ref self: ContractState,
                from: ContractAddress,
                to: ContractAddress,
                amount: u256,
            ) -> bool {
                let spender = get_caller_address();
                let allowed = self.allowances.read((from, spender));
                assert!(allowed >= amount, "insufficient allowance");
                self.allowances.write((from, spender), allowed - amount);
                let from_balance = self.balances.read(from);
                assert!(from_balance >= amount, "insufficient balance");
                self.balances.write(from, from_balance - amount);
                let to_balance = self.balances.read(to);
                self.balances.write(to, to_balance + amount);
                true
            }
        }
    }
}

#[cfg(test)]
mod in_hand_lock_tests {
    use core::num::traits::Zero;
    use starknet::{ContractAddress, get_contract_address};
    use snforge_std::{ContractClassTrait, DeclareResultTrait, declare};

    use super::in_hand_lock_mocks::{
        ILockMockTokenDispatcher, ILockMockTokenDispatcherTrait,
    };
    use super::{IPokerVaultDispatcher, IPokerVaultDispatcherTrait};

    /// 部署 token + vault（owner/operator/玩家 = 测试合约），充 1000 筹码。
    /// `lock_amount` > 0 时同时锁定。返回 (token, vault, player, vault_d)。
    fn setup(lock_amount: u256) -> (
        ContractAddress,
        ContractAddress,
        ContractAddress,
        IPokerVaultDispatcher,
    ) {
        let test = get_contract_address();
        let zero: ContractAddress = 0.try_into().unwrap();
        let token = declare("LockMockToken").unwrap().contract_class();
        let (token_addr, _) = token.deploy(@array![]).unwrap();
        let token_d = ILockMockTokenDispatcher { contract_address: token_addr };
        token_d.mint(test, 1000);

        let vault_class = declare("PokerVault").unwrap().contract_class();
        let (vault, _) = vault_class
            .deploy(@array![test.into(), token_addr.into(), zero.into()])
            .unwrap();
        let vault_d = IPokerVaultDispatcher { contract_address: vault };
        token_d.approve(vault, 1000);
        println!("DEBUG allowance test-vault={}", token_d.allowance(test, vault));
        println!("DEBUG bal test={} vault={}", token_d.balance_of(test), token_d.balance_of(vault));
        vault_d.deposit_for(test, 1000);
        if lock_amount != 0_u256 {
            vault_d.lock(test, lock_amount);
        }
        (token_addr, vault, test, vault_d)
    }

    #[test]
    #[should_panic(expected: "Insufficient unlocked balance (in-hand lock)")]
    fn withdraw_above_unlocked_reverted() {
        let (_, _, _, vault_d) = setup(800);
        // 未锁定仅 200；取 300 必须被拒（否则逃单）
        vault_d.withdraw(300);
    }

    #[test]
    fn withdraw_unlocked_part_allowed() {
        let (_, _, player, vault_d) = setup(800);
        vault_d.withdraw(200);
        assert!(vault_d.chip_balance(player) == 800_u256, "remaining");
        assert!(vault_d.locked_balance(player) == 800_u256, "locked");
    }

    #[test]
    fn settlement_consumes_locked_first() {
        let (_, _, player, mut vault_d) = setup(800);
        // apply_settlement 仅 settlement 合约可调：测试合约自任 settlement
        vault_d.set_settlement_contract(get_contract_address());
        // 结算 -900：先扣锁定 800，再扣未锁定 100 → 不砖死
        vault_d.apply_settlement(player, -900);
        assert!(vault_d.locked_balance(player) == 0_u256, "locked drained");
        assert!(vault_d.chip_balance(player) == 100_u256, "balance net");
    }

    #[test]
    fn settlement_within_locked_keeps_unlocked_intact() {
        let (_, _, player, vault_d) = setup(800);
        vault_d.set_settlement_contract(get_contract_address());
        vault_d.apply_settlement(player, -500);
        assert!(vault_d.locked_balance(player) == 300_u256, "locked rest");
        assert!(vault_d.chip_balance(player) == 500_u256, "unlocked intact");
    }

    #[test]
    #[should_panic(expected: "Lock not expired")]
    fn self_unlock_before_ttl_reverted() {
        let (_, _, _, vault_d) = setup(800);
        // 同一 block 内 timestamp 未推进 → 未过期，自助解锁被拒
        vault_d.unlock_after_deadline(get_contract_address());
    }

    #[test]
    #[should_panic(expected: "Self unlock disabled")]
    fn self_unlock_disabled_when_ttl_zero() {
        let (_, _, _, vault_d) = setup(800);
        vault_d.set_lock_ttl(0);
        vault_d.unlock_after_deadline(get_contract_address());
    }

    #[test]
    fn force_unlock_allows_withdrawal() {
        let (_, _, _, vault_d) = setup(800);
        vault_d.force_unlock(get_contract_address());
        assert!(vault_d.locked_balance(get_contract_address()) == 0_u256, "unlocked");
        vault_d.withdraw(900);
    }

    #[test]
    fn set_lock_ttl_takes_effect() {
        let (_, _, _, vault_d) = setup(800);
        vault_d.set_lock_ttl(600);
        assert!(vault_d.lock_ttl() == 600_u64, "ttl");
    }

    // ===== P1-2 会话委托登记（set_session_tx_pk / _for / views / clear）=====

    /// 测试块内 block timestamp 固定：登记窗口用"当前 + 大值"保证未过期。
    fn far_future_expiry() -> u64 {
        starknet::get_block_timestamp() + 86_400 * 30
    }

    #[test]
    fn session_tx_pk_register_view_clear_roundtrip() {
        let (_, _, player, vault_d) = setup(0);
        let expiry = far_future_expiry();
        vault_d.set_session_tx_pk(0xC0DE, expiry);
        let (pk, exp) = vault_d.session_tx_pk(player);
        assert!(pk == 0xC0DE_felt252, "raw view pk");
        assert!(exp == expiry, "raw view expiry");
        assert!(vault_d.active_session_tx_pk(player) == 0xC0DE_felt252, "active view");
        vault_d.clear_session_tx_pk();
        assert!(vault_d.active_session_tx_pk(player) == 0_felt252, "cleared");
    }

    #[test]
    fn session_tx_pk_latest_wins_on_reregistration() {
        let (_, _, player, vault_d) = setup(0);
        vault_d.set_session_tx_pk(0x1111, far_future_expiry());
        vault_d.set_session_tx_pk(0x2222, far_future_expiry());
        assert!(vault_d.active_session_tx_pk(player) == 0x2222_felt252, "latest wins");
    }

    #[test]
    #[should_panic(expected: "Session tx pk must be non-zero")]
    fn session_tx_pk_rejects_zero_pk() {
        let (_, _, _, vault_d) = setup(0);
        vault_d.set_session_tx_pk(0, far_future_expiry());
    }

    #[test]
    #[should_panic(expected: "Session tx pk expiry must be in the future")]
    fn session_tx_pk_rejects_past_expiry() {
        let (_, _, _, vault_d) = setup(0);
        // expires_at == now 不满足 "> now"，被拒。
        vault_d.set_session_tx_pk(0xC0DE, starknet::get_block_timestamp());
    }

    #[test]
    #[should_panic(expected: "No session tx pk registered")]
    fn session_tx_pk_clear_empty_reverted() {
        let (_, _, _, vault_d) = setup(0);
        vault_d.clear_session_tx_pk();
    }

    #[test]
    fn session_tx_pk_for_via_authorized_helper_privacy_path() {
        let (_, _, _, mut vault_d) = setup(0);
        let player: ContractAddress = 0x1234.try_into().unwrap();
        // 测试合约自任 authorized helper（owner 门）——模拟 anonymizer 在
        // 私密买入 private tx 里 [deposit_for + set_session_tx_pk_for]。
        vault_d.set_authorized_helper(get_contract_address());
        let expiry = far_future_expiry();
        vault_d.set_session_tx_pk_for(player, 0xBEEF, expiry);
        assert!(vault_d.active_session_tx_pk(player) == 0xBEEF_felt252, "helper path");
    }

    #[test]
    #[should_panic(expected: "Only the authorized helper")]
    fn session_tx_pk_for_rejects_unauthorized_caller() {
        let (_, _, player, vault_d) = setup(0);
        // 未设置 authorized helper（零地址）→ 任何调用者被拒。
        vault_d.set_session_tx_pk_for(player, 0xBEEF, far_future_expiry());
    }
}
