/// Settlement registrar: submit verified outer-aggregate digests off-chain
/// and record per-hand settlement outcomes on-chain.
///
/// ## Design (lightweight verification)
///
/// Heavy ZK verification (Stwo STARK proofs over the Texas AIR) happens
/// off-chain. The Rust proving pipeline verifies every child method proof and
/// dual-proof package, then emits an outer aggregate with a canonical
/// `aggregate_digest` (BLAKE2b over the exact child proofs, dispatch digests,
/// receipts, and chain continuity). This contract:
///
/// 1. **Registers** the aggregate digest once (operator-only, one-time per
///    digest), binding it to the canonical pre/post state roots and the
///    ordered per-hand settlement commitments.
/// 2. **Settles** a hand by having the caller re-assert the per-player chip
///    deltas, recomputing the Poseidon settlement commitment, and requiring
///    it to equal the commitment stored at registration. The chip deltas must
///    be zero-sum.
///
/// This is not a ZK verifier in Cairo. It enforces: operator authorization,
/// digest uniqueness, monotonic hand ordering, exact settlement-state
/// commitment recomputation, zero-sum accounting, replay protection, and
/// vault accounting.
use openzeppelin::access::ownable::OwnableComponent;
use starknet::ContractAddress;

#[starknet::interface]
pub trait IPokerSettlement<TContractState> {
    /// Register a verified outer aggregate digest (authorized prover only).
    fn register_aggregate(
        ref self: TContractState,
        aggregate_digest: (felt252, felt252),
        first_hand_id: u64,
        last_hand_id: u64,
        pre_state_root: (felt252, felt252),
        post_state_root: (felt252, felt252),
        settlement_roots: Span<felt252>,
    );

    /// Settle chips for one hand, using a registered aggregate.
    /// `action_log_digest` (#18 Phase B) is the hand's action-log hash —
    /// recomputed into the settlement commitment so it must match the
    /// registered root exactly.
    fn settle_hand(
        ref self: TContractState,
        aggregate_digest: (felt252, felt252),
        hand_id: u64,
        action_log_digest: felt252,
        players: Span<ContractAddress>,
        deltas: Span<i128>,
    );

    /// Authorize an operator (prover) to register aggregates (owner only).
    fn set_prover(ref self: TContractState, prover: ContractAddress);
    /// Deauthorize an operator (owner only).
    fn remove_prover(ref self: TContractState, prover: ContractAddress);
    /// Whether `prover` is authorized.
    fn is_prover(self: @TContractState, prover: ContractAddress) -> bool;
    /// Aggregate registration range for `aggregate_digest`.
    /// Returns (first_hand_id, last_hand_id, pre_root_hi, pre_root_lo, post_root_hi, post_root_lo).
    /// All zero if not registered.
    fn aggregate(
        self: @TContractState, aggregate_digest: (felt252, felt252),
    ) -> (u64, u64, felt252, felt252, felt252, felt252);
    /// Per-hand settlement commitment recorded at registration.
    fn settlement_digest(self: @TContractState, hand_id: u64) -> felt252;
    /// Whether a hand has been settled (replay protection).
    fn hand_settled(self: @TContractState, hand_id: u64) -> bool;
    /// The vault address.
    fn vault(self: @TContractState) -> ContractAddress;
}

#[starknet::contract]
pub mod PokerSettlement {
    use openzeppelin::access::ownable::OwnableComponent;
    use starknet::ContractAddress;
    use core::num::traits::Zero;
    use core::poseidon::poseidon_hash_span;
    use starknet::storage::{
        Map, StorageMapReadAccess, StorageMapWriteAccess, StoragePointerReadAccess,
        StoragePointerWriteAccess,
    };
    use super::IVaultDispatcherDispatcherTrait;

    component!(path: OwnableComponent, storage: ownable, event: OwnableEvent);

    #[abi(embed_v0)]
    impl OwnableMixinImpl = OwnableComponent::OwnableMixinImpl<ContractState>;
    impl OwnableInternalImpl = OwnableComponent::InternalImpl<ContractState>;

    #[storage]
    struct Storage {
        /// Authorized operator (prover) that may register aggregates and
        /// settle hands.
        provers: Map<ContractAddress, bool>,
        /// Vault contract that holds and moves chip balances.
        vault_address: ContractAddress,
        /// Registered aggregates keyed by digest.
        /// (first_hand_id, last_hand_id, pre_root_hi, pre_root_lo,
        ///  post_root_hi, post_root_lo).
        aggregates: Map<(felt252, felt252), (u64, u64, felt252, felt252, felt252, felt252)>,
        /// Per-hand settlement commitment recorded at registration.
        settlement_digests: Map<u64, felt252>,
        /// Hands that have been settled (replay protection).
        settled_hands: Map<u64, bool>,
        /// Highest registered last_hand_id (monotonic ordering).
        last_hand_id: u64,
        #[substorage(v0)]
        ownable: OwnableComponent::Storage,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        #[flat]
        OwnableEvent: OwnableComponent::Event,
        AggregateRegistered: AggregateRegistered,
        HandSettled: HandSettled,
        ProverSet: ProverSet,
    }

    #[derive(Drop, starknet::Event)]
    struct AggregateRegistered {
        aggregate_digest: (felt252, felt252),
        first_hand_id: u64,
        last_hand_id: u64,
        pre_root_hi: felt252,
        pre_root_lo: felt252,
        post_root_hi: felt252,
        post_root_lo: felt252,
    }

    #[derive(Drop, starknet::Event)]
    struct HandSettled {
        aggregate_digest: (felt252, felt252),
        hand_id: u64,
        settlement_digest: felt252,
        participant_count: u32,
    }

    #[derive(Drop, starknet::Event)]
    struct ProverSet {
        prover: ContractAddress,
        authorized: bool,
    }

    #[constructor]
    fn constructor(
        ref self: ContractState,
        owner: ContractAddress,
        vault_address: ContractAddress,
        initial_prover: ContractAddress,
    ) {
        self.ownable.initializer(owner);
        self.vault_address.write(vault_address);
        if !initial_prover.is_zero() {
            self.provers.write(initial_prover, true);
        }
    }

    #[abi(embed_v0)]
    impl IPokerSettlementImpl of super::IPokerSettlement<ContractState> {
        fn register_aggregate(
            ref self: ContractState,
            aggregate_digest: (felt252, felt252),
            first_hand_id: u64,
            last_hand_id: u64,
            pre_state_root: (felt252, felt252),
            post_state_root: (felt252, felt252),
            settlement_roots: Span<felt252>,
        ) {
            let caller = starknet::get_caller_address();
            assert!(self.provers.read(caller), "Caller not authorized prover");
            let (aggregate_hi, aggregate_lo) = aggregate_digest;
            assert!(aggregate_hi != 0 || aggregate_lo != 0, "Zero digest");
            // Unregistered digests map to the all-zero tuple (first_hand_id == 0).
            let (existing_first, existing_last, _, _, _, _) = self
                .aggregates
                .read((aggregate_hi, aggregate_lo));
            assert!(existing_first == 0 && existing_last == 0, "Digest already registered");
            assert!(first_hand_id <= last_hand_id, "Invalid hand range");
            let count_64 = last_hand_id - first_hand_id + 1;
            let count_32: u32 = count_64.try_into().expect('hand count fits u32');
            assert!(settlement_roots.len() == count_32, "Settlement roots count mismatch");
            // Monotonic hand ranges prevent re-registering older outcomes.
            assert!(first_hand_id > self.last_hand_id.read(), "Hand range overlaps past");

            let (pre_hi, pre_lo) = pre_state_root;
            let (post_hi, post_lo) = post_state_root;
            self
                .aggregates
                .write(
                    (aggregate_hi, aggregate_lo),
                    (first_hand_id, last_hand_id, pre_hi, pre_lo, post_hi, post_lo),
                );

            let mut index = 0_u32;
            let mut hand_id = first_hand_id;
            loop {
                let root = *settlement_roots.at(index);
                self.settlement_digests.write(hand_id, root);
                if hand_id == last_hand_id {
                    break;
                }
                index += 1;
                hand_id += 1;
            }

            self.last_hand_id.write(last_hand_id);
            self
                .emit(
                    AggregateRegistered {
                        aggregate_digest,
                        first_hand_id,
                        last_hand_id,
                        pre_root_hi: pre_hi,
                        pre_root_lo: pre_lo,
                        post_root_hi: post_hi,
                        post_root_lo: post_lo,
                    },
                );
        }

        fn settle_hand(
            ref self: ContractState,
            aggregate_digest: (felt252, felt252),
            hand_id: u64,
            action_log_digest: felt252,
            players: Span<ContractAddress>,
            deltas: Span<i128>,
        ) {
            let caller = starknet::get_caller_address();
            let (aggregate_hi, aggregate_lo) = aggregate_digest;
            assert!(self.provers.read(caller), "Caller not authorized prover");
            assert!(players.len() == deltas.len(), "Players/deltas length mismatch");
            assert!(players.len() > 0_u32, "No participants");
            assert!(players.len() < 10_u32, "Too many participants");
            assert!(!self.settled_hands.read(hand_id), "Hand already settled");

            let (first_hand_id, last_hand_id, _, _, _, _) = self
                .aggregates
                .read((aggregate_hi, aggregate_lo));
            assert!(first_hand_id != 0, "Aggregate not registered");
            assert!(hand_id >= first_hand_id && hand_id <= last_hand_id, "Hand outside range");

            // Recompute the settlement commitment.
            let mut felements: Array<felt252> = array![hand_id.into()];
            let mut i = 0_u32;
            while i < players.len() {
                felements.append((*players.at(i)).into());
                let delta = *deltas.at(i);
                if delta >= 0_i128 {
                    let as_u: u64 = delta.try_into().expect('delta fits u64');
                    felements.append(1); // sign = positive
                    felements.append(as_u.into());
                } else {
                    let abs_delta = -delta;
                    let as_u: u64 = abs_delta.try_into().expect('abs delta fits u64');
                    felements.append(0); // sign = negative
                    felements.append(as_u.into());
                };
                i += 1;
            }
            // #18 Phase B：动作日志哈希为承诺尾词（与 register root 同公式）。
            felements.append(action_log_digest);
            let computed = poseidon_hash_span(felements.span());

            // Require exact match with the root committed at registration.
            let stored = self.settlement_digests.read(hand_id);
            assert!(computed == stored, "Settlement digest mismatch");

            // Zero-sum check.
            let zero: i128 = 0_i128;
            let mut sum: i128 = 0_i128;
            let mut j = 0_u32;
            while j < players.len() {
                sum += *deltas.at(j);
                j += 1;
            }
            assert!(sum == zero, "Settlement not zero-sum");

            // Apply per-player net deltas through the vault.
            let vault_addr = self.vault_address.read();
            let mut k = 0_u32;
            while k < players.len() {
                let player = *players.at(k);
                let delta = *deltas.at(k);
                let vault = super::IVaultDispatcherDispatcher { contract_address: vault_addr };
                vault.apply_settlement(player, delta);
                k += 1;
            }

            self.settled_hands.write(hand_id, true);
            self
                .emit(
                    HandSettled {
                        aggregate_digest: (aggregate_hi, aggregate_lo),
                        hand_id,
                        settlement_digest: computed,
                        participant_count: players.len(),
                    },
                );
        }

        fn set_prover(ref self: ContractState, prover: ContractAddress) {
            self.ownable.assert_only_owner();
            if !prover.is_zero() {
                self.provers.write(prover, true);
                self.emit(ProverSet { prover, authorized: true });
            }
        }

        fn remove_prover(ref self: ContractState, prover: ContractAddress) {
            self.ownable.assert_only_owner();
            self.provers.write(prover, false);
            self.emit(ProverSet { prover, authorized: false });
        }

        fn is_prover(self: @ContractState, prover: ContractAddress) -> bool {
            self.provers.read(prover)
        }

        fn aggregate(
            self: @ContractState, aggregate_digest: (felt252, felt252),
        ) -> (u64, u64, felt252, felt252, felt252, felt252) {
            self.aggregates.read(aggregate_digest)
        }

        fn settlement_digest(self: @ContractState, hand_id: u64) -> felt252 {
            self.settlement_digests.read(hand_id)
        }

        fn hand_settled(self: @ContractState, hand_id: u64) -> bool {
            self.settled_hands.read(hand_id)
        }

        fn vault(self: @ContractState) -> ContractAddress {
            self.vault_address.read()
        }
    }
}

/// Minimal vault interface consumed by the settlement contract.
#[starknet::interface]
pub trait IVaultDispatcher<TContractState> {
    fn apply_settlement(ref self: TContractState, player: ContractAddress, delta: i128);
}