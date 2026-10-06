//! Honest payload minting (ownership + reveal + leave + reconstruct) for
//! tests and benchmarks.
//!
//! All randomness is a deterministic Poseidon chain seeded per call, so
//! corpus generation is reproducible without a rand dependency.
//!
//! Statement structures (derived from the verification equations):
//! - ownership: `pk = sk·G`, `R = w·G`, `s = w + c·sk mod n`;
//! - reveal: DLEQ linking `pk = sk·G` to `token = sk·c1` — `c1 = nonce·G`,
//!   `(t1, t2) = (w·G, w·c1)`, `s = w + c·sk mod n`;
//! - leave: batch DLEQ peeling layer `sk` — `cpk = w·G`, per card
//!   `d2 = sk·in_c1`, `out_c2 = in_c2 − d2`, `a = w·in_c1`,
//!   `s = w + c·sk mod n`;
//! - reconstruct: CP-DLEQ — `P_i = sk·G_i`, `(A, B) = (w·G1, w·G2)`,
//!   `s = w + c·sk mod n`.
//!
//! Felt discipline (2026-09-10 全仓统一)：铸造就地运行在
//! `starknet_crypto::Felt`（types-core，与 texas / 根 crate 同一实例），
//! mod-n 归约走 core 的 `StarkScalar`，无本地 num-bigint 镜像、无跨 Felt 桥。

use starknet_crypto::{poseidon_hash_many, Felt};

use poker_protocol_core::curve::CurveScalar;
use poker_protocol_core::stark_curve::StarkScalar;

use crate::curve::Point;
use crate::handbatch::{
    endorsement_challenge, leave_challenge, reconstruct_challenge,
    reveal_challenge, LeaveCard, WORDS_PER_LEAVE_HEADER,
};

/// Deterministic pseudo-random felt chain.
pub struct RandChain {
    state: Felt,
}

impl RandChain {
    pub fn new(seed: u64) -> Self {
        Self { state: poseidon_hash_many(&[Felt::from(seed)]) }
    }

    pub fn next(&mut self) -> Felt {
        self.state = poseidon_hash_many(&[self.state, Felt::from(0x5eedu64)]);
        self.state
    }
}

/// `a + b·c mod n` on raw felts — core's `StarkScalar` Montgomery arithmetic
/// (the old num-bigint mirror is gone with the 0.8 alignment).
fn scalar_add_mod_n(a: Felt, b: Felt, c: Felt) -> Felt {
    let s = to_scalar(a) + to_scalar(b) * to_scalar(c);
    Felt::from_bytes_be(&s.to_bytes_be())
}

/// Raw felt → canonical scalar (`< n` after reduction).
fn to_scalar(f: Felt) -> StarkScalar {
    <StarkScalar as CurveScalar>::from_bytes_mod_order(&f.to_bytes_be())
}

fn scalar_from_felt(f: Felt) -> Felt {
    let reduced = to_scalar(f);
    Felt::from_bytes_be(&reduced.to_bytes_be())
}

/// Mint an honest full-hand payload bound to `hand_binding`. Statement order
/// matches the wire layout: ownership, reveal, leave, recon blocks.
pub fn mint_hand(
    hand_binding: Felt,
    n_own: u32,
    n_action: u32,
    n_reveal: u32,
    n_leave: u32,
    n_recon: u32,
    seed: u64,
) -> Vec<Felt> {
    let mut rand = RandChain::new(seed);
    let g = Point::generator();

    // Leave blocks are variable-length; mint them first to keep the section
    // emission order simple (they are appended after the reveal block).
    let mut leave_blocks = Vec::with_capacity(n_leave as usize);
    for _ in 0..n_leave {
        leave_blocks.push(mint_leave(hand_binding, g, &mut rand, 2));
    }
    let mut recon_blocks = Vec::with_capacity(n_recon as usize);
    for _ in 0..n_recon {
        recon_blocks.push(mint_reconstruct(hand_binding, g, &mut rand));
    }

    let mut action_blocks = Vec::with_capacity(n_action as usize);
    for _ in 0..n_action {
        action_blocks.push(mint_action(g, &mut rand, "call"));
    }

    let mut payload: Vec<Felt> = Vec::new();
    payload.push(Felt::from(n_own as u64)); // n_own
    payload.push(Felt::from(0u64)); // n_shuffle (unsupported → must stay 0)
    payload.push(Felt::from(n_reveal as u64)); // n_reveal
    payload.push(Felt::from(n_leave as u64)); // n_leave
    payload.push(Felt::from(n_recon as u64)); // n_recon
    payload.push(Felt::from(n_action as u64)); // n_action (v3 header tail)

    // Ownership: pk = sk·G, R = w·G, s = (w + c·sk) mod n.
    for _ in 0..n_own {
        let sk = scalar_from_felt(rand.next());
        let w = rand.next();
        let pk = g.mul(sk);
        let r = g.mul(w);
        let c = endorsement_challenge(hand_binding, g, pk, r);
        let s = scalar_add_mod_n(w, c, sk);
        let (pkx, pky) = pk.to_affine().unwrap();
        let (rx, ry) = r.to_affine().unwrap();
        payload.extend([pkx, pky, rx, ry, s]);
    }

    // Reveal: c1 = nonce·G, token = sk·c1, (t1, t2) = (w·G, w·c1),
    // s = (w + c·sk) mod n. c2 rides the transcript only (nonce·pk).
    for _ in 0..n_reveal {
        let sk = scalar_from_felt(rand.next());
        let nonce = scalar_from_felt(rand.next());
        let w = rand.next();
        let pk = g.mul(sk);
        let c1 = g.mul(nonce);
        let token = c1.mul(sk);
        let c2 = pk.mul(nonce);
        let t1 = g.mul(w);
        let t2 = c1.mul(w);
        let c = reveal_challenge(hand_binding, pk, c1, c2, token, t1, t2, nonce);
        let s = scalar_add_mod_n(w, c, sk);
        let (pkx, pky) = pk.to_affine().unwrap();
        let (c1x, c1y) = c1.to_affine().unwrap();
        let (c2x, c2y) = c2.to_affine().unwrap();
        let (tokx, toky) = token.to_affine().unwrap();
        let (t1x, t1y) = t1.to_affine().unwrap();
        let (t2x, t2y) = t2.to_affine().unwrap();
        payload.extend(
            [pkx, pky, c1x, c1y, c2x, c2y, tokx, toky, t1x, t1y, t2x, t2y, nonce, s],
        );
    }

    payload.extend(leave_blocks.into_iter().flatten());
    payload.extend(recon_blocks.into_iter().flatten());
    payload.extend(action_blocks.into_iter().flatten());
    payload
}

/// Mint one action-signature entry (v3 felt-domain challenge): the player
/// signs `(table_id, hand_id, seq, action, amount)`; the entry rides the
/// challenge words alongside (pk, R, s).
fn mint_action(g: Point, rand: &mut RandChain, action: &str) -> Vec<Felt> {
    let sk = scalar_from_felt(rand.next());
    let w = rand.next();
    let pk = g.mul(sk);
    let r = g.mul(w);
    let action_felt = super::handbatch::ascii_felt_pub(action);
    let table_id = 7u64;
    let hand_id = 9u64;
    let seq = rand_u64(rand);
    let amount = 0u64;
    let c = super::handbatch::action_sig_challenge_raw(
        table_id, hand_id, seq, action_felt, amount, r,
    );
    let s = scalar_add_mod_n(w, c, sk);
    let (pkx, pky) = pk.to_affine().unwrap();
    let (rx, ry) = r.to_affine().unwrap();
    vec![
        pkx, pky, rx, ry, s,
        Felt::from(table_id),
        Felt::from(hand_id),
        Felt::from(seq),
        action_felt,
        Felt::from(amount),
    ]
}

fn rand_u64(rand: &mut RandChain) -> u64 {
    let f = rand.next();
    let bytes = f.to_bytes_be();
    u64::from_be_bytes(bytes[24..].try_into().expect("tail 8 bytes"))
}

/// Mint one leave block peeling a random layer, with `n_cards` cards.
fn mint_leave(
    hand_binding: Felt,
    g: Point,
    rand: &mut RandChain,
    n_cards: usize,
) -> Vec<Felt> {
    let sk = scalar_from_felt(rand.next());
    let w = rand.next();
    let nonce = scalar_from_felt(rand.next());
    let pk = g.mul(sk);
    let cpk = g.mul(w);

    let mut words: [Vec<Felt>; 5] = Default::default(); // in_c1, in_c2, out_c1, out_c2, a
    let mut cards = Vec::with_capacity(n_cards);
    for _ in 0..n_cards {
        let r = scalar_from_felt(rand.next());
        let m = scalar_from_felt(rand.next());
        let r_out = rand.next();
        let in_c1 = g.mul(r);
        let in_c2 = g.mul(m);
        let out_c1 = g.mul(r_out);
        let d2 = in_c1.mul(sk);
        let out_c2 = in_c2 - d2;
        let a = in_c1.mul(w);
        cards.push(LeaveCard { in_c1, in_c2, out_c1, out_c2, a });
        for (section, p) in [in_c1, in_c2, out_c1, out_c2, a].into_iter().enumerate() {
            let (x, y) = p.to_affine().unwrap();
            words[section].extend([x, y]);
        }
    }

    let c = leave_challenge(hand_binding, pk, cpk, nonce, &cards);
    let s = scalar_add_mod_n(w, c, sk);

    let mut block = Vec::with_capacity(WORDS_PER_LEAVE_HEADER + 10 * n_cards);
    let (pkx, pky) = pk.to_affine().unwrap();
    let (cpkx, cpky) = cpk.to_affine().unwrap();
    block.push(Felt::from(n_cards as u64));
    block.push(pkx);
    block.push(pky);
    block.push(cpkx);
    block.push(cpky);
    block.push(nonce);
    block.push(s);
    for section in words {
        block.extend(section);
    }
    block
}

/// Mint one reconstruct (CP-DLEQ) block: `P_i = sk·G_i`, `(A, B) = (w·G1, w·G2)`.
fn mint_reconstruct(hand_binding: Felt, g: Point, rand: &mut RandChain) -> Vec<Felt> {
    let sk = scalar_from_felt(rand.next());
    let w = scalar_from_felt(rand.next());
    let g2_rand = rand.next();
    let g1 = g;
    let g2 = g.mul(g2_rand);
    let p1 = g1.mul(sk);
    let p2 = g2.mul(sk);
    let a = g1.mul(w);
    let b = g2.mul(w);
    let c = reconstruct_challenge(hand_binding, g1, g2, p1, p2, a, b);
    let s = scalar_add_mod_n(w, c, sk);
    let (g1x, g1y) = g1.to_affine().unwrap();
    let (g2x, g2y) = g2.to_affine().unwrap();
    let (p1x, p1y) = p1.to_affine().unwrap();
    let (p2x, p2y) = p2.to_affine().unwrap();
    let (ax, ay) = a.to_affine().unwrap();
    let (bx, by) = b.to_affine().unwrap();
    vec![g1x, g1y, g2x, g2y, p1x, p1y, p2x, p2y, ax, ay, bx, by, s]
}
