//! STARK curve access for the hand-verify spike — a thin adapter over
//! `poker-protocol-core::stark_curve` (the protocol's single source of truth).
//!
//! Curve: `y² = x³ + x + β` over `F_P`, `P = 2²⁵¹ + 17·2¹⁹² + 1`, group order
//! `n = 0x0800000000000010ffffffffffffffffb781126dcae7b2321e66a241adc64d2f`,
//! cofactor 1 — the constants Cairo's EC_OP builtin uses, so host points map
//! 1:1 to on-chain felts. Since the 2026-09 starknet-crypto 0.8 alignment the
//! Jacobian formulas (dbl-2001-b / case-aware add / MSB double-and-add) live
//! only in core's `StarkPoint`; this module keeps the spike's Cairo-shaped
//! surface:
//!
//! - [`Point::from_affine`] validates on-curve (mirrors Cairo `EcPoint::new`,
//!   fail-closed on off-curve words) — core's `from_affine_parts` is
//!   unchecked, so the check stays here with `starknet_curve`'s `BETA`;
//! - [`Point::mul`] takes a RAW felt scalar (any value < P), exactly like a
//!   Cairo `EcState::add_mul` scalar: it reduces mod n via
//!   `StarkScalar::from_bytes_mod_order` and multiplies by the canonical
//!   scalar — EC-equivalent because the group order makes `m` and `m mod n`
//!   the same multiplier (pinned by `mul_raw_equals_core_reduced_mul`).
//!
//! Two fields must not be confused (same discipline as core): coordinates
//! live in `F_P`, scalars in `Z_n`. `n < P`, so Felt arithmetic is *not*
//! scalar arithmetic; only the minting side reduces mod n (via core's
//! `StarkScalar`).

use std::ops::{Add, Neg, Sub};

use num_bigint::BigUint;
use starknet_curve::curve_params::BETA;
use starknet_crypto::Felt;

use poker_protocol_core::curve::{Curve, CurvePoint, CurveScalar};
use poker_protocol_core::stark_curve::{StarkCurve, StarkPoint, StarkScalar};

/// A point on the STARK curve (Jacobian underneath; identity is `Z = 0`).
///
/// Semantic equality (cross-multiplied projective comparison) comes from
/// core's `StarkPoint`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Point(StarkPoint);

impl Point {
    pub fn identity() -> Self {
        Self(<StarkPoint as CurvePoint>::identity())
    }

    pub fn is_identity(&self) -> bool {
        self.0.is_identity()
    }

    /// Affine construction with on-curve validation (mirrors Cairo
    /// `EcPoint::new`): rejects points off the curve.
    pub fn from_affine(x: Felt, y: Felt) -> Option<Self> {
        if y * y != x * x * x + x + BETA {
            return None;
        }
        Some(Self(StarkPoint::from_affine_parts(x, y)))
    }

    /// Base point `G` — core's `<StarkCurve as Curve>::base_g()` (same
    /// `starknet_curve` constants the vendored Cairo programs hard-code).
    pub fn generator() -> Self {
        Self(<StarkCurve as Curve>::base_g())
    }

    pub fn to_affine(&self) -> Option<(Felt, Felt)> {
        self.0.to_affine_parts()
    }

    pub fn neg(&self) -> Self {
        Self(-self.0)
    }

    /// Scalar multiplication by a RAW felt (< P, no mod-n pre-condition) —
    /// the Cairo `add_mul` discipline. The raw value is reduced mod n via
    /// core's `StarkScalar::from_bytes_mod_order` and applied with core's
    /// scalar multiplication; `m` and `m mod n` are the same multiplier in a
    /// prime-order group.
    pub fn mul(&self, scalar: Felt) -> Self {
        let s = <StarkScalar as CurveScalar>::from_bytes_mod_order(&scalar.to_bytes_be());
        Self(self.0 * s)
    }

    /// Raw access for the parity tests (core-side conversions).
    pub fn as_core(&self) -> StarkPoint {
        self.0
    }

    /// Wrap a core point that is known to be on-curve (mint side).
    pub fn from_core(p: StarkPoint) -> Self {
        Self(p)
    }
}

impl Add for Point {
    type Output = Point;

    fn add(self, rhs: Point) -> Point {
        Point(self.0 + rhs.0)
    }
}

impl Sub for Point {
    type Output = Point;

    fn sub(self, rhs: Point) -> Point {
        Point(self.0 - rhs.0)
    }
}

impl Neg for Point {
    type Output = Point;

    fn neg(self) -> Point {
        Point::neg(&self)
    }
}

/// Group order as `BigUint` (challenge-parity arithmetic in tests; mint-side
/// mod-n reduction now goes through core's `StarkScalar` instead).
pub fn ec_order() -> BigUint {
    BigUint::from_bytes_be(&poker_protocol_core::stark_curve::ec_order_bytes_be())
}

/// Felt ↔ BigUint helpers (feltmul's integer AIR works on `BigUint` limbs).
pub fn felt_to_biguint(f: Felt) -> BigUint {
    BigUint::from_bytes_be(&f.to_bytes_be())
}

pub fn biguint_to_felt(v: &BigUint) -> Option<Felt> {
    let bytes = v.to_bytes_be();
    if bytes.len() > 32 {
        return None;
    }
    let mut buf = [0u8; 32];
    buf[32 - bytes.len()..].copy_from_slice(&bytes);
    // Infallible on types-core, but values ≥ P cannot be represented as a
    // felt — the caller-checked big-endian bytes are always < 2^252 here in
    // practice (limb recombinations and mod-P/mod-n residues).
    Some(Felt::from_bytes_be(&buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generator_is_on_curve() {
        let g = Point::generator();
        let (x, y) = g.to_affine().unwrap();
        assert_eq!(Point::from_affine(x, y), Some(g));
    }

    #[test]
    fn group_order_times_generator_is_identity() {
        let g = Point::generator();
        let n_felt = Felt::from_bytes_be(&poker_protocol_core::stark_curve::ec_order_bytes_be());
        assert!(g.mul(n_felt).is_identity());
    }

    #[test]
    fn scalar_mul_consistency_small() {
        let g = Point::generator();
        let two_g = g + g;
        let three_g = two_g + g;
        assert_eq!(g.mul(Felt::from(3u32)), three_g);
        assert_eq!(g.mul(Felt::from(2u32)), two_g);
        assert_eq!(g.mul(Felt::from(0u32)), Point::identity());
    }

    /// Delegation pin: a RAW felt scalar (≥ n, as Cairo would feed add_mul)
    /// must multiply like core's canonical reduced scalar.
    #[test]
    fn mul_raw_equals_core_reduced_mul() {
        let g = Point::generator();
        let raw = Felt::from(0xB16D_C0DE_C0DE_1234u128); // arbitrary raw felt
        let reduced =
            <StarkScalar as CurveScalar>::from_bytes_mod_order(&raw.to_bytes_be());
        assert_eq!(g.mul(raw).as_core(), g.as_core() * reduced);
        // And a raw value ≥ n differs from itself minus n by exactly the
        // group order, i.e. they are the same multiplier:
        let n = Felt::from_bytes_be(&poker_protocol_core::stark_curve::ec_order_bytes_be());
        assert_eq!(g.mul(raw + n), g.mul(raw));
    }

    #[test]
    fn add_and_sub_roundtrip() {
        let g = Point::generator();
        let two_g = g + g;
        // Jacobian equality is projective: compare in affine coordinates.
        assert_eq!((two_g - g).to_affine(), g.to_affine());
        assert_eq!((g + g.neg()).to_affine(), None);
    }

    #[test]
    fn off_curve_point_rejected() {
        let g = Point::generator();
        let (x, y) = g.to_affine().unwrap();
        assert_eq!(Point::from_affine(x, y + Felt::ONE), None);
    }

    #[test]
    fn group_order_is_the_expected_hex_constant() {
        // n = 0x0800000000000010ffffffffffffffffb781126dcae7b2321e66a241adc64d2f
        let n = ec_order();
        let expected = Felt::from_hex(
            "0800000000000010ffffffffffffffffb781126dcae7b2321e66a241adc64d2f",
        )
        .expect("hex constant");
        assert_eq!(biguint_to_felt(&n).unwrap(), expected);
    }
}
