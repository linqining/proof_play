# Texas Tagged Transition AIR

> **Summary (EN).** Capability boundary of the tagged/canonical transition
> AIR: 29 selectors (`CanonicalTransitionKind` 0..=28) over a fixed-width ABI
> — which relations compose in the AIR today and which stay fail-closed. The
> authoritative live coverage/gap status is maintained in
> [docs/STATUS.md](../STATUS.md); this document specifies the AIR mechanics.

The independent `poker_texas_air` workspace has two direct, transaction-free paths:

- `src/texas_tagged.rs` is the mature, deliberately narrow projected AIR. It accepts a fixed-width `TexasTransitionWitness`
(`pre` state image, one `TexasAction`, and `post` state image), validates the
transition relation, and places all witnesses in one Stwo heterogeneous trace.
The witness-bearing compatibility verifier reconstructs the same trace and
checks its commitment. `verify_tagged_texas_proof` verifies the archived proof
from its public scope alone, without a `ProveTask`, transaction payload, or VM
replay.
- `src/texas_canonical_air.rs` consumes the full fixed-width
  `CanonicalTransitionWitness` ABI for all 29 selectors. It has no dependency on
  `ProveTask`, dispatch, or native VM replay. Its current AIR proves trace shape,
  active-prefix padding, one-hot selectors, table scope, hand/sequence progression,
  adjacent state-image commitment linkage, both sides of the actor authority rule
  (permissionless rows use zero actor; actor rows prove a non-zero actor), immutable
  settlement commitment, and non-zero transition/nullifier identifiers. It additionally
  proves canonical 16-bit-limb arithmetic for `Call`
  (including the short-all-in branch) and unopened-round `Bet`. `validate_shape`
  remains an optional structural helper; the direct trace builder does not use
  `validate_batch` as a replay/admission prefilter. It applies only fixed-width
  ABI guards (for example, crypto commitment presence and canonical
  `AdvanceRound` padding) before advice generation. Any selector semantics not
  listed as AIR relations below remain outside this component and must stay
  fail-closed at production admission.

## Covered transition

The direct canonical-witness relation deliberately supports a small, explicit
subset of the VM:

- `Fold` and `Check` monetary immutability, plus full selected-seat chip
  conservation for `Call` and unopened-round `Bet`;
- acting seat equals `pre.current_turn` and was not already acted/folded/all-in;
- call sequence increments by one and table/hand scope remains fixed;
- 16-bit canonical-limb range checks and ripple-carry arithmetic for the
  selected `stack`, `bet`, `total_bet`, pot, and action amount in those Call/Bet
  branches;
- Call's `min(current_bet - seat_bet, stack)` selection, including short all-in;
- Bet's unopened-round `current_bet`/`min_raise` updates;
- full fixed-width opening of every seat's lifecycle and mutable betting
  buckets during a betting action; the selected-seat fields are derived from
  that opening and non-acting seat images are immutable;
- Raise reopens action by resetting the other `Active` seats' acted flags only
  when the raise increment meets the pre-state `min_raise`; a sub-minimum
  all-in keeps every non-acting seat's flags (TDA #41), while inactive-seat
  flags are always preserved;
- canonical circular next-active-seat scan, including a proof that no Active
  seat was skipped between actor and successor, and contiguous batches.
- `Addon` and `Rebuy` range-check the four 16-bit TableVault limbs and prove
  the exact non-zero `chip_pool` increment, plus the matching selected-seat
  `pending_addon`/`stack` increment.  Seat occupancy/capacity and the full
  custody identity remain part of `validate_shape` on the legacy
  `texas_tagged` route; the separate canonical AIR now opens every fixed-width
  seat image, but does not yet prove every VM transition family;
- `AdvanceRound` opens every seat's wager, range-checks each 16-bit limb, and
  proves `post_pot = pre_pot + sum(pre_seat.bet)` with a checked carry chain;
  it clears every `seat.bet` while preserving stack, total bet, pending funds,
  lifecycle, and acted mask.  It can run only after every remaining `Active`
  seat has acted and matched `current_bet`.
- `SetLeaveAfterHand`, with an occupied in-capacity seat and exactly one
  canonical mask-bit transition. The VM's idempotent no-op is rejected because
  it cannot be represented as a `call_seq`-incrementing witness.
- `CreateTable` preserves all opened mutable seat buckets; StartHand keeps
  every seat's funds identical but admits waiting-for-big-blind seats through
  a constrained `Waiting -> Active` promotion channel (funds and all other
  lifecycle statuses immutable, no `Active -> Waiting` demotion), counts
  post-state participants for the `>= 2` gate, and proves its post-state
  deadline is non-zero. Which Waiting seat is promoted is a host admission
  policy (the blind-position rule) and is not recomputed inside the AIR;
- `AdvanceDeadline` proves a canonical 64-bit comparison
  `action.height >= pre.deadline` with limb range checks and checked carries,
  and preserves all opened mutable seat buckets;
  `JoinTable` installs a `Waiting` seat (waiting-for-big-blind: the seat joins
  the deal only after StartHand promotes it from the blind position) with the
  exact buy-in custody relation; `LeaveTable`/`ForceFold`/`KickPlayer`
  preserve every non-target opened seat, and ForceFold/KickPlayer enforce
  their selected-seat lifecycle domain (`Active|Waiting` to
  `Folded|Out|Empty`). Rules and governance
  commitments are also constrained to remain immutable on every active row.

The narrow tagged AIR uses eight one-hot action tags.  The canonical AIR uses
29 tags (`CanonicalTransitionKind` 0..=28 — AutoFold / EndWithoutShowdown /
timeout-cascade kinds added through 2026-09) and carries the mid-round betting
selectors directly. Funding rows
additionally carry range-checked pending/stack/vault limbs and ripple carries;
leave rows carry a complete canonical nine-bit mask decomposition, a one-hot seat selector,
and the selected-bit flip relation. The legacy `texas_tagged` trace still relies
on host validation for the canonical state image; the newer canonical AIR
authenticates every fixed-width endpoint field but does not recompute the root
fields or prove every VM relation. The proof API is:

```rust
prove_tagged_texas_batch(&[TexasTransitionWitness])
verify_tagged_texas_batch(&[TexasTransitionWitness], &ArchivedTaggedTexasProof)
verify_tagged_texas_proof(&ArchivedTaggedTexasProof)
```

The migration target is the fixed-width `texas_canonical` ABI. It has explicit fields for the
phase union, lifecycle/status, acted mask, board/deck/reveal/reconstruction commitments,
deadlines, run-it-twice, governance/rules, custody, settlement, and roots, plus all 29 dispatch
transition kinds. Its `validate_shape` and commitment are useful structural checks before the AIR
families are complete; they do not claim that an opaque commitment was recomputed inside Stwo.

For chain admission, call `texas_receipt::authenticate_receipt` and then
`AuthenticatedTexasReceipt::admit_tagged_proof`. The authenticated wrapper is
created only after a historical receipt-mapping inclusion path reaches the
finalized state root at the receipt's block height, the confirmation threshold
is met, and the receipt value commits the complete circuit/manifest/effect/
authority/nullifier statement. This path does not inspect transaction bytes or
call VM dispatch.

Both direct APIs are independent of `ProveTask`, `MethodBatchV2`, VM dispatch, and
transaction replay. The legacy `tagged_method` and composite paths remain
available for downstream compatibility and retain their existing semantics.

## Explicit non-goals

`texas_tagged` does not model round advancement, pot collection, timeout
normalization, showdown/deck/reveal, side-pot settlement, or hand-rank
evaluation. Such inputs return `UnsupportedBettingTransition`; they must not be
encoded as a projected mid-round row.

`texas_canonical_air` carries those selector families through a common ABI, but
does not yet constrain their complete semantics in Stwo. It must not be described
as a proof of a complete Texas VM transition. Its batch digest and archive metadata
are transcript-bound and tamper-evident after proving; they are not a substitute for
an in-AIR hash of every witness row or a finalized receipt binding.

The direct canonical route does tighten the crypto-tagged state-machine shape:
shuffle/reveal/reconstruct rows must use their matching pre phase, address an
occupied seat, and carry a 16-bit range-bound non-zero proof commitment.
`FoldWithProof` is a Betting/current-turn action whose nonterminal row changes
the selected seat only from Active to Folded+acted, keeps funds and identity
commitments fixed, and may replace only the deck commitment. This does not
prove the Ristretto DLEQ, Bayer--Groth shuffle, reveal-token, or reconstruction
equations, nor final round/terminal normalization; those remain fail-closed
until their dedicated AIRs are composed.

The Blake2 state-image projections in the trace bind the witness to the proof,
but they are not an in-AIR state-root computation. The witness-free verifier
therefore establishes only the encoded projected relation. A production
no-replay trust model still requires an authenticated state image (or state-root
opening) and an inclusion proof at the finalized consensus height. A
prover-supplied state image without that authenticated anchor remains a
host-attested input, not a trustless chain fact.

The current trace opens every seat's mutable betting image for mid-round
actions, constrains Raise reset plus next-turn selection, and proves the
separate completed-round wager collection micro-step. `AdvanceRound` also has
a fixed-width board-reveal opening: one of the six VM schedules
`(preflop|flop|turn) × (single|run-it-twice)` is selected in AIR, and it fixes
the card cursor, runout, board position, pending participant mask, zero
submitted mask, and all padding. Full seat-image commitments, inclusion of
those assignments in the encrypted deck/reveal commitments, side pots, and
authenticated state-root computation are still outside this AIR. Consequently,
the witness-free entry point must not be used as evidence of complete Texas VM
execution until those relations and receipt inclusion are implemented.

The mid-round component permits a `NO_SEAT` successor only when all remaining
`Active` seats have acted and matched the final bet. The following
`AdvanceRound` row performs the exact `collect_bets_to_pot` relation and the
VM's preflop/flop/turn board-assignment schedule (including run-it-twice).
River-to-showdown remains fail-closed until a fixed-width owner-hole-card
ledger opening is added. The board assignment is not yet proven to be a member
of the encrypted deck or a committed reveal queue, so production admission
must remain fail-closed at that cryptographic reveal boundary.

The board schedule's pre/post `cards_dealt` cursors are separately decomposed
inside the AIR and proven to lie in `0..=52`; the proof does not rely on the
Rust witness validator for this deck-bound check. This prevents a field-valued
trace from moving the assignment cursor beyond the physical deck while still
satisfying the cursor-delta relation.

The direct builder also rejects malformed fixed-width envelopes before constructing
the trace: crypto rows require a non-zero proof commitment; `AdvanceRound` requires
an opening street in `1..=3`, contiguous present assignments, a pending mask equal
to the pre-state active/folded/all-in seats, zero submitted masks, and zero padding;
other transition kinds cannot carry a board opening. These checks protect the fixed
ABI and avoid host-side indexing ambiguity; they are not a substitute for the
unimplemented shuffle, reveal, settlement, or timeout equations.

The verifier reconstructs nine fixed preprocessed columns for every trace size:
an active-row prefix plus the four 16-bit table limbs, two hand-id limbs, and
two pre-call-sequence limbs. The AIR constrains every witness row to those
columns, and inactive rows to the all-zero suffix. Each active row also carries
the post-call sequence and a binary carry; the AIR enforces
`post_call_seq = pre_call_seq + 1`, including the 16-bit rollover case. This
prevents an all-padding trace and prevents moving a valid row to a different
table, hand, or sequence slot. The scope is still a public projected relation:
a future full transition circuit must bind these values to authenticated state
openings and enforce every row's full state transition.

The required no-replay trust-model migration is documented in
`../archive/TRUST_MODEL_NO_TRANSACTION_REPLAY.md`: immutable transition receipts, complete
pre/post public statements, authority and manifest binding, historical
state-root/receipt inclusion proofs, and coordinator admission from an
`AuthenticatedTransitionReceipt`. Removing replay code before those pieces are
available would replace replay trust with prover/RPC trust rather than remove a
trust assumption.
