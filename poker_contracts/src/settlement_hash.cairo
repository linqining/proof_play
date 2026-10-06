/// Shared settlement commitment helper for off-chain Rust adapters and the
/// on-chain settlement contract's hash construction.
use core::poseidon::poseidon_hash_span;
use starknet::ContractAddress;

/// Compute the canonical settlement commitment.
///
/// Encoding: `hand_id`, then for every ordered player: `player`, `sign`,
/// `magnitude`; sign is `1` for non-negative and `0` for negative deltas.
/// The current contract ABI bounds magnitudes to u64.
pub fn settlement_digest(
    hand_id: u64, players: Span<ContractAddress>, deltas: Span<i128>,
) -> felt252 {
    let mut fields: Array<felt252> = array![hand_id.into()];
    let mut i = 0_u32;
    while i < players.len() {
        fields.append((*players.at(i)).into());
        let delta = *deltas.at(i);
        if delta >= 0_i128 {
            let magnitude: u64 = delta.try_into().expect('delta fits u64');
            fields.append(1);
            fields.append(magnitude.into());
        } else {
            let magnitude: u64 = (-delta).try_into().expect('abs delta fits u64');
            fields.append(0);
            fields.append(magnitude.into());
        };
        i += 1;
    }
    poseidon_hash_span(fields.span())
}
