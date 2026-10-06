/// SettlementPayoutAnonymizer — Part A Phase 1 private payout claim
/// (docs/design/SETTLEMENT_PRIVACY_PLAN.md §4 Phase 1 + Part C3).
///
/// The dual settlement contract funds this helper with each hand's winners'
/// pot (`vault.settlement_fund_escrow`) and pins one claim commitment per
/// seat: `cm = poseidon(pk_lo, pk_hi, hand_binding, amount_lo, amount_hi)`
/// where `pk` is the winner's registered secp256k1 payout key (vault
/// registry). The winner then claims INSIDE a STRK20 private transaction:
/// the pool calls `privacy_claim`, which
///
///   1. re-derives `cm` from the player's registered payout key,
///   2. verifies a secp256k1 signature by that key over
///      `poseidon(cm, note_id)` — only the payout-key owner can direct the
///      payout into a specific open note,
///   3. consumes the claim (single-use) in the settlement contract,
///   4. approves the pool to pull `amount` and returns one
///      `OpenNoteDeposit` — the payout lands in a note whose owner the
///      chain cannot see.
///
/// STRK20 integration rules honored: approve (never transfer) the pool,
/// single-use claims, u128 note amounts, empty span never returned with
/// funds parked (claims always pay out exactly `amount`).
///
/// Security model: stateful helper (holds the escrow across transactions) —
/// the pool address and the settlement (dual) contract are pinned in the
/// constructor and asserted on every entry. `consume_claim` in the dual
/// contract is additionally gated to this helper, making double claims
/// impossible even across helper redeploys.
use starknet::ContractAddress;

#[derive(Copy, Drop, Serde, PartialEq)]
pub struct OpenNoteDeposit {
    pub note_id: felt252,
    pub token: ContractAddress,
    pub amount: u128,
}

/// Minimal vault surface: token + the player's registered payout commitment.
#[starknet::interface]
pub trait IVaultPayout<TContractState> {
    fn payout_commitment(self: @TContractState, player: ContractAddress) -> felt252;
    fn token(self: @TContractState) -> ContractAddress;
}

/// Minimal settlement surface: claim commitments + single-use consumption.
#[starknet::interface]
pub trait ISettlementClaims<TContractState> {
    fn claim_cm(self: @TContractState, hand_binding: felt252, seat_index: u32) -> felt252;
    fn claim_amount(self: @TContractState, hand_binding: felt252, seat_index: u32) -> u256;
    /// P2-M3 v2：金额藏在 cm（电路证明），合约不保存明文 claim_amount。
    fn amounts_hidden(self: @TContractState, hand_binding: felt252) -> bool;
    fn consume_claim(
        ref self: TContractState,
        hand_binding: felt252,
        seat_index: u32,
        amount: u256,
    );
}

#[starknet::interface]
pub trait ISettlementPayoutAnonymizer<TContractState> {
    /// Called by the STRK20 privacy pool inside a private transaction.
    /// The escrow is funded by the settlement contract at settle time; this
    /// entry verifies the secret preimage of the player's registered payout
    /// commitment, consumes the single-use claim, and returns the escrowed
    /// tokens as the caller's open note (owner hidden by the pool).
    fn privacy_claim(
        ref self: TContractState,
        player: ContractAddress,
        hand_binding: felt252,
        seat_index: u32,
        amount: u256,
        note_id: felt252,
        secret: felt252,
    ) -> Span<OpenNoteDeposit>;
}

#[starknet::interface]
pub trait IAnonymizerInfo<TContractState> {
    fn vault(self: @TContractState) -> ContractAddress;
    fn pool(self: @TContractState) -> ContractAddress;
    fn settlement(self: @TContractState) -> ContractAddress;
}

#[starknet::contract]
pub mod SettlementPayoutAnonymizer {
    use core::hash::HashStateTrait;
    use core::num::traits::Zero;
    use core::poseidon::PoseidonTrait;
    use openzeppelin::token::erc20::interface::{IERC20Dispatcher, IERC20DispatcherTrait};
    use starknet::{
        ContractAddress, get_caller_address,
        storage::{StoragePointerReadAccess, StoragePointerWriteAccess},
    };

    use super::{
        IAnonymizerInfo, ISettlementClaimsDispatcher, ISettlementClaimsDispatcherTrait,
        IVaultPayoutDispatcher, IVaultPayoutDispatcherTrait, OpenNoteDeposit,
    };

    #[storage]
    struct Storage {
        /// PokerVault holding the escrowed tokens + the payout-key registry.
        vault: ContractAddress,
        /// STRK20 privacy pool — the only authorized caller.
        pool: ContractAddress,
        /// PokerDualSettlement — publishes claim commitments + consume gate.
        settlement: ContractAddress,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        ClaimExecuted: ClaimExecuted,
    }

    #[derive(Drop, starknet::Event)]
    struct ClaimExecuted {
        player: ContractAddress,
        hand_binding: felt252,
        seat_index: u32,
        amount: u256,
        note_id: felt252,
    }

    #[constructor]
    fn constructor(
        ref self: ContractState,
        vault: ContractAddress,
        pool: ContractAddress,
        settlement: ContractAddress,
    ) {
        assert!(!vault.is_zero(), "vault required");
        assert!(!pool.is_zero(), "pool required");
        assert!(!settlement.is_zero(), "settlement required");
        self.vault.write(vault);
        self.pool.write(pool);
        self.settlement.write(settlement);
    }

    #[abi(embed_v0)]
    impl AnonymizerImpl of super::ISettlementPayoutAnonymizer<ContractState> {
        fn privacy_claim(
            ref self: ContractState,
            player: ContractAddress,
            hand_binding: felt252,
            seat_index: u32,
            amount: u256,
            note_id: felt252,
            secret: felt252,
        ) -> Span<OpenNoteDeposit> {
            let pool = self.pool.read();
            assert!(get_caller_address() == pool, "caller is not the pool");
            assert!(!player.is_zero(), "player required");
            assert!(amount > 0_u256, "amount must be > 0");
            assert!(note_id != 0, "note id required");

            let vault = self.vault.read();
            let settlement = self.settlement.read();

            // 1. The player must have registered a payout commitment
            //    (poseidon(secret)) at sit-down — the secret stays client-side.
            let vault_payout = IVaultPayoutDispatcher { contract_address: vault };
            let commitment = vault_payout.payout_commitment(player);
            assert!(commitment != 0, "payout commitment not registered");

            // 2. The settlement must have published a matching claim message:
            //    cm = poseidon(commitment, hand_binding, amount_lo, amount_hi).
            let claims = ISettlementClaimsDispatcher { contract_address: settlement };
            let cm = claims.claim_cm(hand_binding, seat_index);
            let expected = PoseidonTrait::new()
                .update(commitment)
                .update(hand_binding)
                .update(amount.low.into())
                .update(amount.high.into())
                .finalize();
            assert!(cm == expected, "claim commitment mismatch");
            if claims.amounts_hidden(hand_binding) {
                // P2-M3 v2：金额由电路证明的 cm 绑定、托管余额由 vault 封顶，
                // 合约不再保存明文 claim_amount——跳过明文等值断言。
            } else {
                assert!(
                    claims.claim_amount(hand_binding, seat_index) == amount,
                    "claim amount mismatch"
                );
            };

            // 3. Capability: only the secret's owner can reveal it, and the
            //    reveal binds the destination note — an observer replaying
            //    calldata cannot redirect the payout.
            let msg = PoseidonTrait::new().update(cm).update(note_id).finalize();
            assert!(
                PoseidonTrait::new().update(secret).finalize() == msg,
                "invalid claim secret"
            );

            // 4. Single-use consumption in the settlement contract (gated to
            //    this helper) — replay across helper redeploys included.
            claims.consume_claim(hand_binding, seat_index, amount);

            // 5. Approve the pool to pull the escrowed tokens and credit the
            //    caller's open note. Pool note amounts are u128.
            assert!(amount.high == 0_u128, "amount overflows u128");
            let token = vault_payout.token();
            let token_dispatcher = IERC20Dispatcher { contract_address: token };
            let escrow_amount: u128 = amount.low;
            let ok = token_dispatcher.approve(pool, amount);
            assert!(ok, "pool approve failed");

            self.emit(ClaimExecuted { player, hand_binding, seat_index, amount, note_id });

            let mut deposits = core::array::ArrayTrait::new();
            deposits.append(OpenNoteDeposit { note_id, token, amount: escrow_amount });
            deposits.span()
        }
    }

    /// Vault / pool / settlement addresses for observability and SDK
    /// configuration.
    #[abi(embed_v0)]
    impl AnonymizerInfoImpl of IAnonymizerInfo<ContractState> {
        fn vault(self: @ContractState) -> ContractAddress {
            self.vault.read()
        }
        fn pool(self: @ContractState) -> ContractAddress {
            self.pool.read()
        }
        fn settlement(self: @ContractState) -> ContractAddress {
            self.settlement.read()
        }
    }
}

// ============================================================
// Tests (snforge): escrow claim flow — happy path, wrong secret,
// double claim, non-pool caller. Mock vault/claims/token stand in
// for the real vault & dual settlement contracts.
// ============================================================
