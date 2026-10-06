mod dual;

use core::array::ArrayTrait;
use core::traits::TryInto;

/// Form-② executable: the REAL `hand_verify` verification (EC residual
/// checks via the Cairo EC_OP builtin — EC in trace) as a standalone
/// Cairo program. The STARK proof of this program is the EC attestation
/// half of the composed (form-②) settlement package; the spike's native
/// statement-table AIR is the other half. Both bind to the same
/// (hand_binding, payload) via program arguments / claim.
#[executable]
fn main(hand_binding: felt252, payload: Span<felt252>) -> bool {
    dual::hand_verify::verify_hand(hand_binding, payload)
}
