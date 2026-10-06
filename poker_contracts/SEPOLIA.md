# Poker STRK20 contracts — Starknet Sepolia

This directory contains the contract-side first phase of the STRK20 integration.
The chain only checks the final `aggregate_digest` and the settlement state; it
does **not** execute the Stwo verifier. The operator must verify the complete
Rust `OuterAggregateBundle` before calling `register_aggregate`.

## Contracts

- `PokerToken`: OpenZeppelin ERC20 test token with owner-only `mint`/`burn`.
  Replace it with the canonical Sepolia STRK token for an integration test that
  uses real STRK.
- `PokerVault`: 1:1 STRK20 deposits/withdrawals and per-player chip balances.
  `apply_settlement` is restricted to the configured settlement contract.
- `PokerSettlement`: authorized-prover registration of aggregate digests,
  monotonic hand ranges, Poseidon settlement commitments, zero-sum checks, and
  replay-protected vault deltas.
- `PokerDualSettlement` (dual-proof route, docs/design/DUAL_PROOF_PROTOCOL.md v2.3):
  verifies the **secp256k1 sigma ownership proofs on-chain** through the
  Starknet EC_OP builtin (`dual/secp256k1_verifier.cairo`; the challenge
  `keccak256(G‖pk‖R) mod n` is derived inside the contract, never submitted),
  binds both proof tracks through the Poseidon `hand_binding`, and settles
  through the same vault. The G-STARK stays host-verified in this phase; its
  commitments are registered via `register_hand`. `scarb test`/`snforge test`
  cross-validate the on-chain verifier against Rust (`k256`) vectors —
  honest/forge/wrong-key/off-curve all covered. Requires `snforge_std`
  (compatible Foundry release) for the Cairo test runner.

## Build

```bash
cd poker_contracts
scarb build
scarb test
```

`scarb test` is a compile/test-runner smoke gate. The current workspace does
not pin `snforge_std`, because the old plugin version fails to compile on the
current macOS toolchain due to its transitive `size-of` Windows ABI list. Use a
matching Starknet Foundry release in CI to execute the Cairo test runner.

## Sepolia deployment

The deployment script requires explicit configuration and never defaults to a
mainnet RPC:

```bash
export SNCAST_ACCOUNT=poker-sepolia
export SNCAST_URL='https://starknet-sepolia.public.blastapi.io/rpc/v0_8'
export OWNER='0x...'
export PROVER='0x...'
export INITIAL_SUPPLY='1000000000000000000000000'
./scripts/deploy_sepolia.sh
```

Before sending transactions:

1. Fund the account with Sepolia ETH/STRK gas tokens.
2. Review the exact Sierra artifacts and constructor calldata.
3. Confirm whether the deployment uses the local `PokerToken` or the canonical
   Sepolia STRK token.
4. Deploy `PokerToken`, `PokerVault`, and `PokerSettlement`.
5. Call `set_settlement_contract(settlement_address)` on the vault as owner.
6. Update `/strk20.json` with the returned addresses and class hashes.
7. Verify the constructor and access-control state with `sncast call`.

## Runtime flow

1. Player calls STRK20 `approve(vault, amount)`.
2. Player calls vault `deposit(amount)`.
3. Rust operator verifies the complete Stwo outer aggregate off-chain.
4. Authorized prover calls `register_aggregate(...)` with the aggregate digest,
   state roots, and one settlement commitment per hand.
5. Authorized prover calls `settle_hand(...)` with the ordered participants and
   signed net chip deltas. The contract recomputes the Poseidon commitment,
   checks zero-sum, and forwards deltas to the vault.
6. Player calls `withdraw(amount)`.

## Rust calldata builder

`poker_texas_air::starknet_settlement` produces the exact Cairo ABI calldata
for steps 4–5. It only accepts already-verified inputs; there is no path from
an unverified `OuterAggregateBundle` to trusted calldata.

```text
use poker_texas_air::outer_aggregate::verify_outer_aggregate;
use poker_texas_air::starknet_settlement::{RegisterAggregateCalldata, SettleHandCalldata};

// One verified aggregate per hand; a VerifiedChain is single-hand by
// construction, so a multi-hand registration passes one per hand.
let verified_hands: Vec<VerifiedOuterAggregate> = /* verify_outer_aggregate(...) per hand */;
let settlement_roots: Vec<FieldElement> = /* poseidon commitment per hand */;

let register = RegisterAggregateCalldata::new(
    &verified_hands,
    first_hand_id,
    last_hand_id,
    settlement_roots,
)?;
let felts: Vec<FieldElement> = register.to_felts();   // invoke calldata

let settle = SettleHandCalldata::new(
    verified_aggregate_digest_32,
    hand_id,
    &authenticated_pre_table,   // pre-settlement TexasPokerTable snapshot
    &canonical_settlement_plan, // SettlementPlan for this hand
    Some(rake_recipient),       // required when plan.rake > 0
)?;
let felts: Vec<FieldElement> = settle.to_felts();     // invoke calldata
```

The builder rejects, before any transaction is built: hand-range or
state-root discontinuities across the aggregate list, aggregate-digest or
table drift, a missing rake recipient when `plan.rake > 0`, empty or
duplicate participant addresses, participant sets above
`MAX_SETTLE_PARTICIPANTS` (10), non-zero-sum deltas, and deltas whose
magnitude exceeds the Cairo `i128`/`u64` commitment bound.

## Aggregate-digest ABI (dual felt)

The 256-bit BLAKE2b/BLAKE3 aggregate digest does not fit in one `felt252`
(Stark prime ≈ 2^251), so `register_aggregate` and its storage key encode it
losslessly as a `(felt252, felt252)` pair:

- `hi = felt252(bytes[0..16])` — big-endian high half.
- `lo = felt252(bytes[16..32])` — big-endian low half.

`poker_texas_air::starknet_settlement::AggregateDigestFelts::{split, merge}`
implement the identical encoding with round-trip and range checks (each half
must be a canonical 128-bit value). `settle_hand` takes the single-felt `lo`
projection for ABI stability; the contract binds it back to the registered
pair in storage.

## Settlement commitment encoding

`settle_hand` recomputes `poseidon_hash_span` over:

```text
hand_id,
(player_i, sign_i, magnitude_i)*   # sign: 1 non-negative, 0 negative
```

with participants ordered by ascending address. The Rust builder computes the
identical commitment via `starknet_crypto::poseidon_hash_many` and exposes it
as `SettleHandCalldata::settlement_digest()`; a mismatch between the builder
and the contract is a hard error on-chain.

## Security boundary

This is intentionally a trusted-operator bridge for the testnet phase. The
contract guarantees commitment consistency, operator authorization, replay
protection, monotonic hand ranges, and chip accounting. It does not guarantee
that the off-chain digest was generated from a valid Stwo proof. A future
permissionless phase must add a Cairo-native proof verifier or a separate
on-chain verifier before removing this trust boundary.
