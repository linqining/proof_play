//! # bg_stark — Bayer–Groth V2 shuffle verification on the STARK curve
//!
//! On-chain / in-program verification of a BG12 shuffle proof over the
//! Cairo-native STARK curve, decomposed into linear point equations
//! (mirroring texas/src/starknet/dual_settle.rs
//! `bg_shuffle_fold_equations` — signs and terms copied 1:1):
//!
//! - E1a/E1b: Σ x^i·in_i.c1 − ct1.c1 = O (c1/c2 sides, i = 1..n)
//! - E2:  e·c_permuted_powers + c_alpha
//!        − (Σ alpha_resp_i·CK_i + commitment_response·CK_h) = O
//! - E3:  c_beta − beta·G − beta_blinding_response·CK_h = O
//! - E4a: ct0.c1 + e·ct1.c1
//!        − (rerand_resp·G + Σ alpha_resp_i·out_i.c1) = O
//! - E4b: ct0.c2 + e·ct1.c2
//!        − (beta·G + rerand_resp·pk + Σ alpha_resp_i·out_i.c2) = O
//! - E5:  c_d + q·(y·c_perm + c_ppow) − q·z·S
//!        − (Σ a_resp_i·CK_i + r_response·CK_h) = O,
//!        where S = Σ_i CK_i is computed in-program from the pinned CK
//!        (52 point additions; it factors E5's uniform −z scalar:
//!        c_minus_z = Σ(−z)·CK_i = −z·S — algebraically identical)
//! - E6:  c_delta + q·c_capital_delta
//!        − (Σ recurrence_i·CK_i + s_response·CK_h) = O,
//!        recurrence_i = q·b_{i+1} − b_i·a_{i+1} (i < n−1), else 0
//! - scalar checks (mod n): b_response[0] == a_response[0];
//!   b_response[n−1] == q·Π_{i=1..n}(y·i + x^i − z)
//!
//! E2/E5/E6 are deliberately **not** λ-batched: a shared λ checks the
//! bare sum E2+E5+E6 (cancellable: response words are prover-chosen and
//! the equations are linear in them — independent exponents would be
//! required), and independent λs lose in the Cairo cost model (a mod-n
//! fr_mul costs ~12× an EC_OP point mul). Recorded here to prevent
//! relapse; final equation count: 8.
//!
//! Challenges x, y, z, e, q are recomputed by replaying the
//! `PoseidonFeltTranscript` sponge (poker-protocol-core stark_curve.rs)
//! over the exact append schedule of `bg_replay_challenges` — including
//! the `challenge_nonzero` retry semantics (a zero poseidon output has
//! probability ≈ 2^-251; the loop is semantic alignment only).
//!
//! ## Pinned commitment key
//!
//! Deriving CK needs `hash_to_curve` (Tonelli–Shanks square root in the
//! STARK base field), which is not implemented in Cairo. The constants
//! below are the deterministic nothing-up-my-sleeve derivation output of
//! `BgCommitmentKey::derive` (h = hash_to_curve("poker/bg12/v2/H"),
//! CK_i = hash_to_curve("poker/bg12/v2/G/52/i")), generated and attested
//! host-side (Rust test `bg_vectors` writes /tmp/bgvectors/ck_n52.txt).
//! Cairo equality-checks nothing here — it only uses the points — so the
//! pinning is a trust assumption on the host attestation, matching the
//! host's own derivation. A future upgrade can add on-chain derivation.
//! Only deck size n = 52 is accepted while the key is pinned.
//!
//! ## Wire format (shuffle bucket, 11n+31 words, n = 52 → 603)
//!
//! [n, input n×4 (c1x c1y c2x c2y per ct), output n×4, pk 2,
//!  22 commitment words: c_permutation, c_permuted_powers, c_alpha,
//!  c_beta, ct0.c1, ct0.c2, ct1.c1, ct1.c2, c_d, c_delta,
//!  c_capital_delta (2 words each), responses 3n+6: alpha_response n,
//!  commitment_response, beta, beta_blinding_response,
//!  rerandomization_response, a_response n, b_response n, r_response,
//!  s_response]. Every response word must be a canonical scalar (< n),
//! mirroring the host's `scalar_from_word` (fail-closed otherwise).

use core::array::{ArrayTrait, SpanTrait};
use core::ec::{EcPoint, EcPointTrait, EcStateTrait, NonZeroEcPoint};
use core::option::Option;
use core::poseidon::poseidon_hash_span;
use core::traits::TryInto;

use super::hand_batch_stark::{
    EquationWords, GENERATOR_X, GENERATOR_Y, STARK_N, felt_to_u256, fr_mul, fr_neg, u256_to_felt,
};

/// Deck size accepted by the pinned commitment key.
pub const BG_DECK_SIZE: u32 = 52;

/// The pinned commitment key as ready-to-use points: index 0 = CK_h,
/// index 1+i = G_i (deterministic host-side `BgCommitmentKey::derive`
/// output — see module doc for the pinning rationale). Built once per
/// verification (106 on-curve checks).
fn build_ck() -> Array<NonZeroEcPoint> {
    let words: Array<felt252> = array![
        0x03ca74d9f228c18c92e3b7f1c1924d59107387b8036c7b4641ab98839175331c,
        0x0413366f733f806545a1b470b64985332d13d620b0ab743e4c44ca16a92b2dcf,
        0x019f6c5007dcdead637e8c2ad4b904848baf4f71edb3a8643a89112514a105ab,
        0x0114b72965fdb13df469280629ceab2133ab7bae8992438c99e2eeddca1098f7,
        0x00ca990e8e7463085d5bfa3a1d2149456872a78a0d1da67086fc0bc87b63afd5,
        0x04515829b162de1e47b7682896518e14fd9235d157bffffe5895db869c24e6ad,
        0x00923da32814606ea6d4ed99551535037f5530c751342bca0c7edaf217fbd4ed,
        0x04514aa6daf1335bf3b2fe37029d83946282c4a82a584ee37a1af9a71a01f3a5,
        0x03d35468ff8a72c7fa71f47a9b59f358808c691e0f57aa2c03526ef777610da1,
        0x04b7eff6837968ba9ede8d1a9cfc424750db9176aacda9b7fb97de7d99ce56e7,
        0x07554ad7a414c60f9a01070ced749c1c9c3db9c176eb4499117716d81e5e5bff,
        0x03902f66202c33c2f14a1032338223d20702d2e8dd7775e6655a9eab0a08d07d,
        0x048c8e0b7daf6c3d7c7e0f8d1c746ea0adf3ea40dd1092a1cdf7cecaa69bc0b3,
        0x0586f2901ecc950242969a1be0ee4e10196617ed3eabd0a05505fef820797aa3,
        0x06c05b93c2c1d98405148d7e076be3ff0d3eb1a9b92e0de4b8b1f55519347663,
        0x04dde38d3cfb15cb4bf1f5dbace7a25cf2979428e3e19f93b279d72c4c70dc1f,
        0x03059b2c753184f83a013fe0924a653e9e42a8c587a1ab10fdd51cb7158d8504,
        0x048811f3ff807143d9f49d78ba09542e92f308d83a5818c3e5da77b517203c5b,
        0x0451c9717a524650521efcfc7ee8de2cba1cdf7501cc8eaeee282a0b9e4a9b9d,
        0x0568d44cc921c70bdac0d5acf326ba5cf2f5aab8484d3180be58e1bf630c33a7,
        0x05a18e3e3b9cc74877979e60b12b91ce2ed02321fc9bec487da3cc43c604f530,
        0x0166e1698d03e5f29f2343fdaceea8ff7e87d3221154adeadb233f1a49223e8f,
        0x0153967c18bef69f4e45c6f631851f15953660a2a6c918d507c2c89651c592ad,
        0x005065857b6eefbc74cac7829a2ab616d26ee319ac69024205a65418b8b8e579,
        0x017419fe65af378ebcd5ed6ac7181a687c748d45f7ed60ecd7be346cedec8367,
        0x002a8934c7778463dfdfc371c0e523f20f30496a9e2f515e2a822a5d2f63b97b,
        0x044359e0eeecf7c58f928d751da0ac70589c07c55d4c6f9c02543787676ecb48,
        0x0246b2cb7a38a1f647f3f5da46574a208e20ea881e998987b6bd88e6f026a623,
        0x03a927ada1f94f29a048a39fd2075f37f7069126a46ab6b888f0199f9a262cf2,
        0x043a1f571ffd1b8ebc642a51f03364c6fc4452e1a09c2e04cbb4447e34375b45,
        0x058faed9ce14ea32ba08fa50f0e1a0e1040d720fb957fb6d3c5aa7f08420b7df,
        0x06d76e54fa134f683ee0fa7395a105913627d817d7eb7afb5c5d82ad37a9a45d,
        0x01379a763f1226a16e9b2692bd30be4b205c45e8c94b24485fa0e13a99a5459a,
        0x057d67f9f3d2756b0b9e0b4af6ef698f8252bfdd9a29fc36070f345ebdfa4807,
        0x067ffac10d7ef4b6234b83b199d68e2cec3b42c84948b95bebcd23d34c524ba7,
        0x05c8cf5ba5586c5b6c33b61da52254775e8866844a5aaabe66a8db025b617b49,
        0x04b0e6ee7b5ff22a107c55cc35caacf90d538d55e84c7cb3799cb1a66ba500ba,
        0x04cc5eab1b4e7a2e8bf76bc29be70e1ac79046933c4a1f4608865aafb2ed3dd3,
        0x0264eb6f1c4fa35112dcd0e832352b8f5dd0b32ae291bd108d35fc569a1c00c0,
        0x05284bbbc65079058804ee28c598315895ae69a07d16574b9bc11bac45f3b3a3,
        0x07ee5b65832b791ed5bc36300ef82226e2f29e8e793672b66ef0783331b5764a,
        0x07177755205fff261f11023defb38acdb85f4b14dccdf05ca11312c1f305805b,
        0x0249336e35b97d23340bee581f3a8a9c2462eb0ab1b0023471aa21db65c87e60,
        0x06b50ef956dadab794ef42a7fb5d986975ebc61da93d0c0d91ca19e7c9aaec0d,
        0x039b91603b5cc6b1d7eea6687801952cf0241f615d74b394551cf96dbf5f0071,
        0x06733984f20294d12c245861e72000e923014eccaa64d85a65915b2524a41171,
        0x0125c300b497b25874734932e47bb0e65a9e843fa8325023dc3e476f8d23129c,
        0x02b96b8abed35eb572100086fe2bf5f51bd51c73e2e5f588f63ef2b4fee735c3,
        0x056261e5c971da0d8c972e3ace25e3c0f63ec1f4de907c2fa93ad83a4fc2d2e5,
        0x07d0921d88d079f17e8d368cec72b0f672e551aaa77f7b69b40f105d064100c9,
        0x009c043e2d83900bb01696224eb859cf4ef0d445387673649053885f56bd5549,
        0x047b0966f26c9001055ba4ed2db79cc6512c2bafa697e25fa1a4fdb1f7982c35,
        0x0451fd0188f8ae7561d2d0dee1816669d10beeeb6fa44f466aa7f4ba84b2e8ae,
        0x0388dfb382936f15f895f7e7c9e2ba40019be25d84953834c15e2c0e5c68fab1,
        0x034c0226e4479cbd2cbc1ada948bb51108f6fffee11483ce292cf5ebce86bac2,
        0x05bf5635d6d3e4ed831e4cf25a9ae3b9a31774c1637adac1e36cc899c8a63bdd,
        0x0578e496b89879dc37c0a097885ab1d34b3fa81dad918061b9b73082becc2bb8,
        0x04c7dccc389c3078b7cca0f7032e3f68be50d83bd4c0da76b275d798ab44cee3,
        0x02d4fbf53ad23c807b20a848c405747c6a76b2940c8e7599164476a8ae27f03d,
        0x06f225e14ad3d5785128de7daf6127d2aa11cf7be5caf82282ee5f8fd34d5487,
        0x0539cc7e8686860153065d2988c8df74bec7cf688e69310ec06929d2c338300d,
        0x066a1d4aa5dd2c5c2d16aef60dd861c00755266c153a3bb4b90f75ac7c6cba57,
        0x057764644ceb13ce27f28968e3fb6f0e9ad0d0e3bc93eeadf539e1cb36905f29,
        0x03b582440dd77decb6559d7024f61248396b3b2cae3829f0ccb2ce70f419c1cd,
        0x05c9cacf4333bfd2e5b36f2cd22127178d6adf540910e0a78292d3e3b78dde18,
        0x01460b3add2980dd32c7308e84cb095025eef11017527dbe2e019958614d38e1,
        0x03c298279fa12b117fc3ffdd4565ef5de52f9578b4b5cf00bd8cc364a1139bb6,
        0x0127ceb213e0831e09dbe41426ee4c1712a279ff14e013ec30572952da385329,
        0x05b53b205aa813d5e619cf1466a6882bb34926eaa0bdee6f80f1250583fa2a08,
        0x005034cbb84cdbabb08909a5391a01f9bf18b2ff1075c418a0c71be6c30ddacb,
        0x079ffee2447439caf7614a98734ca06499b3a71e5eec62b2db5837bea91b36d7,
        0x075e596dcce951921369c5e2ac97d137cd0501e343fd8f3532dd28d9577be875,
        0x053ff55b25cb74b81a4cba583ab0775008dfddf40a5e9ba3bffa023d2ed6b36e,
        0x0093a634f7b083fd12d40f9c43120a4271da09ba674625a21eab9abac81377fb,
        0x00937282df93fa2d4fa45a6f97a31cb9bc8115ba748d5f80fa80490c89530af2,
        0x0767d5bfb5d6af0637fcfe599017d8831c8b504b6d775829341c539ebcfe3fa5,
        0x077b07e52dc3bfccc18410d8db6ab0142d7160dba95e2429de0b2b1444695c66,
        0x06c6a8098d6925dbbe9fe312a9753e000dbfac07c2448e8e87fe3ec2cf527a8b,
        0x01d782c9673380e44fdf7f2e88167836980b51a0de177d83b00423911e88ec47,
        0x01efe468970e899b2a6409bcaa16c0ae1e441e9e20fe35ad50012a40f7852d29,
        0x065602a4219244d70c347a5828420af4940d26533ff30ffb485f9954b5103e30,
        0x00c9aed96642c91477f353581cde8b80b31b02642f6ac4efc7c1c1098d480f61,
        0x07acb5a7705ec4f561d2d319028239a0f43eea4be80d8841c7c3dd4c18b9f158,
        0x0732379ee6ff1050ffb41fa8851d86896f42cd3ac63d73681728049bb4516b3f,
        0x043e35c1ea7f29d62998262aab0c75c494efdc9aa0834ba2a23c89a73fed54e4,
        0x00f2fbc733cd0de4b5c89c8f9ef288cd3b08676bf4c52b37827a37ff1a58196b,
        0x00e9e5840e32e2c352bc01673fd9f8bfc0fc13e4f136deec9a7a335fadc77353,
        0x051d10e89cd6377af01f364bb5ffa130f3a624e8d831a935a319b9550e9ca093,
        0x055f8800331bc50dcff9a246a6db772940a03f22655e396518aed31dc32cce38,
        0x011c26a6980e732924b9cd30a72b3b2bfe67d889d97a76189661904ff6d025ed,
        0x07196cdb564f081e6c7b7937d80d758965ff916918e25c446ec063684a1c433f,
        0x03bb9a51b1d6eebb86ce3bc6c3f8401c56771edb3a25c1f3ea1080d61413eddf,
        0x01843f538c45bea79e96a0498e6fe25565c472c614b966f4919b0b1e106d54d7,
        0x0786f6870942be5a5c599886e248f09ba5e1d6e09c3063246437797a3099d7a7,
        0x067b0d8d72bd0eda7ec9f61cef4ab34c808b199225e414399603c1954ec6d474,
        0x0306144c60608788d1949d2b8879ea44233eb8ca7a99286a7a3e65387742cf35,
        0x04170019af287c39e33d13c814c123261093f008dc5549d0ad2b5f593fffc3ff,
        0x01d29b10f07ada6b90fe776450bc6aef11449b2191988a98cecc57ee313bd607,
        0x059cb73147471f113a468f1a8afb823377e02230f367692d0f5b22cf7893d3ff,
        0x07956354f826325c9b20b45c4ff6f7243fab75741d0297ba4befa1b6fa22123f,
        0x0651b49b3c6f2404710be11cddd852eb4a0e8ce956a2557826b4ab73b5902607,
        0x0761312ba5d8a6053643c2ea3a09682b514333478ccea6d1ea684c315920156d,
        0x045e40b6bce100e54a170fabbeb11da29d254de45490cae2b6c8a843c9006502,
        0x01fb684d6628342cb9555eff664c05f9212146182a7ef9df3587d37ec5bfad1f,
        0x02cccb2346a98bad520461349bf68071b5d037589fa75312b95d61ac5959ad2f,
        0x05e506744e2af5c47ec643a998cedf3eb37696ef3c6ddf70bcf81c9814163c37,
    ];
    let mut ck: Array<NonZeroEcPoint> = array![];
    let mut k: u32 = 0;
    while k < 53 {
        let x = *words.at(2 * k);
        let y = *words.at(2 * k + 1);
        let p: EcPoint = EcPointTrait::new(x, y).unwrap();
        ck.append(p.try_into().unwrap());
        k += 1;
    }
    ck
}

/// `a + b mod n` (canonical inputs; sum < 2^253 fits u256).
pub fn fr_add(a: u256, b: u256) -> u256 {
    (a + b) % STARK_N
}

/// `a − b mod n` (canonical inputs).
pub fn fr_sub(a: u256, b: u256) -> u256 {
    if a >= b {
        a - b
    } else {
        STARK_N - (b - a)
    }
}

/// Canonical mod-n scalar → felt (always < n < 2^252, lossless).
fn scalar_felt(v: u256) -> felt252 {
    match u256_to_felt(v) {
        Option::Some(f) => f,
        Option::None => core::panic_with_felt252(0),
    }
}

/// On-curve, non-identity parse (fail-closed on malformed points).
fn nz_point(x: felt252, y: felt252) -> Option<NonZeroEcPoint> {
    match EcPointTrait::new(x, y) {
        Option::Some(p) => p.try_into(),
        Option::None => Option::None,
    }
}

fn nz_generator() -> NonZeroEcPoint {
    let g: EcPoint = EcPointTrait::new(GENERATOR_X, GENERATOR_Y).unwrap();
    g.try_into().unwrap()
}

// ============================================================
// PoseidonFeltTranscript replay (single-felt sponge; every step is
// one poseidon_hash_span permutation, byte-identical to the Rust
// canonical spec in poker-protocol-core/src/stark_curve.rs).
// ============================================================

/// Poseidon sponge state (BG foldable epoch).
#[derive(Copy, Drop, Debug)]
pub struct BgTranscript {
    pub state: felt252,
}

/// init: `state = poseidon([ascii("poker/bg-fold/v1")])`.
pub fn bg_transcript_new() -> BgTranscript {
    BgTranscript { state: poseidon_hash_span(array!['poker/bg-fold/v1'].span()) }
}

/// append_message(label, msg):
/// `state = poseidon([state, label31, felt(msg.len()), felt(msg)])`
/// (msg ≤ 31 bytes, big-endian integer encoding).
pub fn bg_append_message(
    tr: BgTranscript, label: felt252, msg_len: u64, msg: felt252,
) -> BgTranscript {
    BgTranscript {
        state: poseidon_hash_span(array![tr.state, label, msg_len.into(), msg].span()),
    }
}

/// append_point(label, pt): `state = poseidon([state, label31, x, y])`.
pub fn bg_append_point(tr: BgTranscript, label: felt252, x: felt252, y: felt252) -> BgTranscript {
    BgTranscript { state: poseidon_hash_span(array![tr.state, label, x, y].span()) }
}

/// challenge(label): `out = poseidon([state, label31, ascii("chal")])`,
/// returns `out mod n`, then `state = poseidon([state, out])` (raw out).
pub fn bg_challenge(tr: BgTranscript, label: felt252) -> (u256, BgTranscript) {
    let out = poseidon_hash_span(array![tr.state, label, 'chal'].span());
    let scalar = felt_to_u256(out) % STARK_N;
    (scalar, BgTranscript { state: poseidon_hash_span(array![tr.state, out].span()) })
}

/// ≤ 8-byte integer → BE felt of its little-endian byte encoding
/// (host: `append_message(_, &v.to_le_bytes())`).
fn le_u64_be_felt(v: u64) -> felt252 {
    let mut f: felt252 = 0;
    let mut rem: u64 = v;
    let mut i: u32 = 0;
    while i < 8 {
        let byte: u64 = rem % 256;
        rem = rem / 256;
        f = f * 256 + byte.into();
        i += 1;
    }
    f
}

fn le_u32_be_felt(v: u32) -> felt252 {
    let mut f: felt252 = 0;
    let mut rem: u32 = v;
    let mut i: u32 = 0;
    while i < 4 {
        let byte: u32 = rem % 256;
        rem = rem / 256;
        f = f * 256 + byte.into();
        i += 1;
    }
    f
}

/// challenge_nonzero: resample on a zero challenge (host semantic
/// parity; probability ≈ 2^-251).
fn challenge_nonzero(tr: BgTranscript, label: felt252) -> (u256, BgTranscript) {
    let (mut challenge, mut tr) = bg_challenge(tr, label);
    let mut counter: u32 = 0;
    while challenge == 0_u256 {
        tr = bg_append_message(
            tr, 'bg12_zero_challenge_retry', 4, le_u32_be_felt(counter),
        );
        let (c, t) = bg_challenge(tr, label);
        challenge = c;
        tr = t;
        counter += 1;
    }
    (challenge, tr)
}

/// The five transcript-derived challenges.
#[derive(Copy, Drop, Debug)]
pub struct BgChallenges {
    pub x: u256, // powers
    pub y: u256, // product y
    pub z: u256, // product z
    pub e: u256, // multi-exponentiation
    pub q: u256, // product
}

/// Replay the BG verification transcript over the shuffle bucket words
/// (bucket starts at the deck-size word). Append order and labels are
/// byte-identical to `dual_settle.rs::bg_replay_challenges`.
/// Fails closed on off-curve / identity transcript points and on
/// deck_size != 52.
pub fn bg_replay_challenges(bucket: Span<felt252>) -> Option<BgChallenges> {
    let n: u32 = BG_DECK_SIZE;
    if bucket.len() < 11 * n + 31 {
        return Option::None;
    }
    if felt_to_u256(*bucket.at(0)) != (BG_DECK_SIZE.into()) {
        return Option::None;
    }
    let in_base: u32 = 1;
    let out_base: u32 = 1 + 4 * n;
    let pk_base: u32 = 1 + 8 * n;
    let comm_base: u32 = 1 + 8 * n + 2;

    let mut tr = bg_transcript_new();
    tr = bg_append_message(tr, 'bg12_protocol', 28, 'poker/bayer-groth-shuffle/v2');
    tr = bg_append_message(tr, 'bg12_deck_size', 8, le_u64_be_felt(BG_DECK_SIZE.into()));

    // pk
    let pk_x = *bucket.at(pk_base);
    let pk_y = *bucket.at(pk_base + 1);
    if nz_point(pk_x, pk_y).is_none() {
        return Option::None;
    }
    tr = bg_append_point(tr, 'bg12_public_key', pk_x, pk_y);

    // input / output ciphertexts (append_ciphertext inner order)
    let mut side: u32 = 0;
    while side < 2 {
        let base = if side == 0 { in_base } else { out_base };
        let (msg, msg_len) = if side == 0 { ('input', 5_u64) } else { ('output', 6_u64) };
        let mut i: u32 = 0;
        while i < n {
            let off = base + 4 * i;
            let c1x = *bucket.at(off);
            let c1y = *bucket.at(off + 1);
            let c2x = *bucket.at(off + 2);
            let c2y = *bucket.at(off + 3);
            if nz_point(c1x, c1y).is_none() || nz_point(c2x, c2y).is_none() {
                return Option::None;
            }
            tr = bg_append_message(tr, 'bg12_ciphertext_label', msg_len, msg);
            tr = bg_append_point(tr, 'bg12_ciphertext_c1', c1x, c1y);
            tr = bg_append_point(tr, 'bg12_ciphertext_c2', c2x, c2y);
            i += 1;
        }
        side += 1;
    }

    // commitments (all validated on-curve, non-identity)
    let mut k: u32 = 0;
    while k < 11 {
        let cx = *bucket.at(comm_base + 2 * k);
        let cy = *bucket.at(comm_base + 2 * k + 1);
        if nz_point(cx, cy).is_none() {
            return Option::None;
        }
        k += 1;
    }
    let c_perm_x = *bucket.at(comm_base);
    let c_perm_y = *bucket.at(comm_base + 1);
    let c_ppow_x = *bucket.at(comm_base + 2);
    let c_ppow_y = *bucket.at(comm_base + 3);
    let c_alpha_x = *bucket.at(comm_base + 4);
    let c_alpha_y = *bucket.at(comm_base + 5);
    let c_beta_x = *bucket.at(comm_base + 6);
    let c_beta_y = *bucket.at(comm_base + 7);
    let ct0c1_x = *bucket.at(comm_base + 8);
    let ct0c1_y = *bucket.at(comm_base + 9);
    let ct0c2_x = *bucket.at(comm_base + 10);
    let ct0c2_y = *bucket.at(comm_base + 11);
    let ct1c1_x = *bucket.at(comm_base + 12);
    let ct1c1_y = *bucket.at(comm_base + 13);
    let ct1c2_x = *bucket.at(comm_base + 14);
    let ct1c2_y = *bucket.at(comm_base + 15);
    let c_d_x = *bucket.at(comm_base + 16);
    let c_d_y = *bucket.at(comm_base + 17);
    let c_delta_x = *bucket.at(comm_base + 18);
    let c_delta_y = *bucket.at(comm_base + 19);
    let c_cdelta_x = *bucket.at(comm_base + 20);
    let c_cdelta_y = *bucket.at(comm_base + 21);

    tr = bg_append_point(tr, 'bg12_c_permutation', c_perm_x, c_perm_y);
    let (x, mut tr) = challenge_nonzero(tr, 'bg12_powers_challenge');
    tr = bg_append_point(tr, 'bg12_c_permuted_powers', c_ppow_x, c_ppow_y);
    let (y, mut tr) = challenge_nonzero(tr, 'bg12_product_y');
    let (z, mut tr) = challenge_nonzero(tr, 'bg12_product_z');

    tr = bg_append_point(tr, 'bg12_mexp_c_alpha', c_alpha_x, c_alpha_y);
    tr = bg_append_point(tr, 'bg12_mexp_c_beta', c_beta_x, c_beta_y);
    tr = bg_append_message(tr, 'bg12_ciphertext_label', 6, 'mexp_0');
    tr = bg_append_point(tr, 'bg12_ciphertext_c1', ct0c1_x, ct0c1_y);
    tr = bg_append_point(tr, 'bg12_ciphertext_c2', ct0c2_x, ct0c2_y);
    tr = bg_append_message(tr, 'bg12_ciphertext_label', 6, 'mexp_1');
    tr = bg_append_point(tr, 'bg12_ciphertext_c1', ct1c1_x, ct1c1_y);
    tr = bg_append_point(tr, 'bg12_ciphertext_c2', ct1c2_x, ct1c2_y);
    let (e, mut tr) = challenge_nonzero(tr, 'bg12_mexp_challenge');

    tr = bg_append_point(tr, 'bg12_product_c_d', c_d_x, c_d_y);
    tr = bg_append_point(tr, 'bg12_product_c_delta', c_delta_x, c_delta_y);
    tr = bg_append_point(tr, 'bg12_product_c_capital_delta', c_cdelta_x, c_cdelta_y);
    let (q, _tr) = challenge_nonzero(tr, 'bg12_product_challenge');

    Option::Some(BgChallenges { x, y, z, e, q })
}

/// Fold-words for the 8 BG equations (E1a, E1b, E2, E3, E4a, E4b, E5, E6;
/// kind=5, s=c=0 — the statement is fully bound by the transcript replay,
/// mirroring `host_fold_check_linear`'s words).
pub fn bg_equation_words() -> EquationWords {
    EquationWords { kind: 5, s: 0, c: 0 }
}

/// Decompose a shuffle bucket (starting at the deck-size word) into the
/// 6 equation residuals (E1a, E1b, E3, E4a, E4b, E-batched) + the two
/// scalar checks. `Option::None` on any malformed input (bad deck size,
/// off-curve point, non-canonical response scalar). The bool is
/// `scalar_check_1 && scalar_check_2`.
pub fn bg_equations(bucket: Span<felt252>) -> Option<(Array<EcPoint>, BgChallenges, bool)> {
    let n: u32 = BG_DECK_SIZE;
    let ch = match bg_replay_challenges(bucket) {
        Option::Some(c) => c,
        Option::None => { return Option::None; },
    };
    let in_base: u32 = 1;
    let out_base: u32 = 1 + 4 * n;
    let pk_base: u32 = 1 + 8 * n;
    let comm_base: u32 = 1 + 8 * n + 2;
    let resp_base: u32 = comm_base + 22;

    // response scalars: canonical (< n) mod-n words, host parity with
    // scalar_from_word (from_canonical_bytes).
    let resp = |k: u32| -> Option<u256> {
        let v = felt_to_u256(*bucket.at(resp_base + k));
        if v >= STARK_N {
            Option::None
        } else {
            Option::Some(v)
        }
    };
    let commitment_response = match resp(n) { Option::Some(v) => v, Option::None => { return Option::None; } };
    let beta = match resp(n + 1) { Option::Some(v) => v, Option::None => { return Option::None; } };
    let beta_blind = match resp(n + 2) { Option::Some(v) => v, Option::None => { return Option::None; } };
    let rerand_resp = match resp(n + 3) { Option::Some(v) => v, Option::None => { return Option::None; } };
    let alpha_resp = |i: u32| -> Option<u256> { resp(i) };
    let a_resp = |i: u32| -> Option<u256> { resp(n + 4 + i) };
    let b_resp = |i: u32| -> Option<u256> { resp(2 * n + 4 + i) };
    let r_resp = match resp(3 * n + 4) { Option::Some(v) => v, Option::None => { return Option::None; } };
    let s_resp = match resp(3 * n + 5) { Option::Some(v) => v, Option::None => { return Option::None; } };

    // points (all validated during replay; rebuilt here for arithmetic)
    let nz = |x: felt252, y: felt252| -> NonZeroEcPoint { nz_point(x, y).unwrap() };
    let pk = nz(*bucket.at(pk_base), *bucket.at(pk_base + 1));
    let in_pt = |i: u32, side: u32| -> NonZeroEcPoint {
        let off = in_base + 4 * i + 2 * side;
        nz(*bucket.at(off), *bucket.at(off + 1))
    };
    let out_pt = |i: u32, side: u32| -> NonZeroEcPoint {
        let off = out_base + 4 * i + 2 * side;
        nz(*bucket.at(off), *bucket.at(off + 1))
    };
    let comm_pt = |k: u32| -> NonZeroEcPoint {
        nz(*bucket.at(comm_base + 2 * k), *bucket.at(comm_base + 2 * k + 1))
    };

    let g = nz_generator();
    let ck = build_ck();
    let ck_h = *ck.at(0);
    let ck_g = |i: u32| -> NonZeroEcPoint { *ck.at(1 + i) };

    // powers x^1..x^n (mod n — an EC scalar only needs congruence mod n)
    let mut powers: Array<u256> = array![];
    let mut cur = ch.x;
    let mut i: u32 = 0;
    while i < n {
        powers.append(cur);
        cur = fr_mul(cur, ch.x);
        i += 1;
    }

    let mut equations: Array<EcPoint> = array![];

    // E1a/E1b: Σ x^{i+1}·in_i − ct1
    let mut side: u32 = 0;
    while side < 2 {
        let mut st = EcStateTrait::init();
        i = 0;
        while i < n {
            st.add_mul(scalar_felt(*powers.at(i)), in_pt(i, side));
            i += 1;
        }
        let ct1 = if side == 0 { comm_pt(6) } else { comm_pt(7) };
        st.add_mul(scalar_felt(fr_neg(1)), ct1);
        equations.append(st.finalize());
        side += 1;
    }

    // E3: c_beta − beta·G − beta_blinding_response·CK_h
    {
        let mut st = EcStateTrait::init();
        st.add(comm_pt(3));
        st.add_mul(scalar_felt(fr_neg(beta)), g);
        st.add_mul(scalar_felt(fr_neg(beta_blind)), ck_h);
        equations.append(st.finalize());
    }

    // E4a: ct0.c1 + e·ct1.c1 − (rerand·G + Σ alpha_resp_i·out_i.c1)
    // E4b: ct0.c2 + e·ct1.c2 − (beta·G + rerand·pk + Σ alpha_resp_i·out_i.c2)
    {
        let mut st = EcStateTrait::init();
        st.add(comm_pt(4));
        st.add_mul(scalar_felt(ch.e), comm_pt(6));
        st.add_mul(scalar_felt(fr_neg(rerand_resp)), g);
        i = 0;
        while i < n {
            let a = match alpha_resp(i) { Option::Some(v) => v, Option::None => { return Option::None; } };
            st.add_mul(scalar_felt(fr_neg(a)), out_pt(i, 0));
            i += 1;
        }
        equations.append(st.finalize());

        let mut st = EcStateTrait::init();
        st.add(comm_pt(5));
        st.add_mul(scalar_felt(ch.e), comm_pt(7));
        st.add_mul(scalar_felt(fr_neg(beta)), g);
        st.add_mul(scalar_felt(fr_neg(rerand_resp)), pk);
        i = 0;
        while i < n {
            let a = match alpha_resp(i) { Option::Some(v) => v, Option::None => { return Option::None; } };
            st.add_mul(scalar_felt(fr_neg(a)), out_pt(i, 1));
            i += 1;
        }
        equations.append(st.finalize());
    }

    // E2/E5/E6 as SEPARATE equations (no λ-batching). Two reasons,
    // recorded to prevent relapse:
    // 1. Soundness: a single shared λ reduces to checking the bare sum
    //    E2+E5+E6 = O — alpha/a response words are prover-chosen public
    //    words and E2/E5 are linear in them, so residual(E2) = P with
    //    residual(E5) = −P cancels exactly. Small-exponent batching
    //    needs INDEPENDENT exponents.
    // 2. Cost: in the Cairo VM a mod-n scalar mul (fr_mul, no mul-mod
    //    builtin) costs thousands of steps per element while an EC mul
    //    rides the EC_OP builtin at ~162 steps — independent λs need
    //    3 fr_muls per element and lose ~17% step-gas overall.
    // E2: e·c_ppow + c_alpha − vc(alpha_resp, commitment_response)
    {
        let mut st = EcStateTrait::init();
        st.add_mul(scalar_felt(ch.e), comm_pt(1));
        st.add(comm_pt(2));
        i = 0;
        while i < n {
            let alpha = match alpha_resp(i) { Option::Some(v) => v, Option::None => { return Option::None; } };
            st.add_mul(scalar_felt(fr_neg(alpha)), ck_g(i));
            i += 1;
        }
        st.add_mul(scalar_felt(fr_neg(commitment_response)), ck_h);
        equations.append(st.finalize());
    }

    // E5: c_d + q·(y·c_perm + c_ppow) − q·z·S − vc(a_resp, r_resp).
    // Uniform-scalar factoring: c_minus_z = Σ(−z)·CK_i = −z·S with
    // S = Σ CK_i (52 point adds over the pinned CK — algebraically
    // identical, saves the 52-mul MSM).
    {
        // S = Σ CK_i (52 point adds over the pinned constants)
        let mut s_st = EcStateTrait::init();
        i = 0;
        while i < n {
            s_st.add(ck_g(i));
            i += 1;
        }
        let s_sum: NonZeroEcPoint = match s_st.finalize().try_into() {
            Option::Some(v) => v,
            Option::None => { return Option::None; }, // S = O would be a broken pinning
        };

        let mut st = EcStateTrait::init();
        st.add(comm_pt(8)); // c_d
        st.add_mul(scalar_felt(fr_mul(ch.q, ch.y)), comm_pt(0)); // q·y·c_perm
        st.add_mul(scalar_felt(ch.q), comm_pt(1)); // q·c_ppow
        st.add_mul(scalar_felt(fr_neg(fr_mul(ch.q, ch.z))), s_sum); // −q·z·S
        i = 0;
        while i < n {
            let a = match a_resp(i) { Option::Some(v) => v, Option::None => { return Option::None; } };
            st.add_mul(scalar_felt(fr_neg(a)), ck_g(i));
            i += 1;
        }
        st.add_mul(scalar_felt(fr_neg(r_resp)), ck_h);
        equations.append(st.finalize());
    }

    // E6: c_delta + q·c_capital_delta − vc(recurrence, s_resp),
    // recurrence_i = q·b_{i+1} − b_i·a_{i+1} (i < n−1), else 0.
    {
        let mut st = EcStateTrait::init();
        st.add(comm_pt(9)); // c_delta
        st.add_mul(scalar_felt(ch.q), comm_pt(10)); // q·c_capital_delta
        i = 0;
        while i < n {
            let rec = if i + 1 < n {
                let b_next = match b_resp(i + 1) { Option::Some(v) => v, Option::None => { return Option::None; } };
                let b_i = match b_resp(i) { Option::Some(v) => v, Option::None => { return Option::None; } };
                let a_next = match a_resp(i + 1) { Option::Some(v) => v, Option::None => { return Option::None; } };
                fr_sub(fr_mul(ch.q, b_next), fr_mul(b_i, a_next))
            } else {
                0_u256
            };
            st.add_mul(scalar_felt(fr_neg(rec)), ck_g(i));
            i += 1;
        }
        st.add_mul(scalar_felt(fr_neg(s_resp)), ck_h);
        equations.append(st.finalize());
    }

    // scalar check 1: b_response[0] == a_response[0]
    let b0 = match b_resp(0) { Option::Some(v) => v, Option::None => { return Option::None; } };
    let a0 = match a_resp(0) { Option::Some(v) => v, Option::None => { return Option::None; } };
    let sc1 = b0 == a0;
    // scalar check 2: b_response[n−1] == q·Π_{i=1..n}(y·i + x^i − z)
    let mut prod: u256 = 1;
    i = 1;
    while i <= n {
        let t = fr_sub(fr_add(fr_mul(ch.y, i.into()), *powers.at(i - 1)), ch.z);
        prod = fr_mul(prod, t);
        i += 1;
    }
    let b_last = match b_resp(n - 1) { Option::Some(v) => v, Option::None => { return Option::None; } };
    let sc2 = b_last == fr_mul(ch.q, prod);

    Option::Some((equations, ch, sc1 && sc2))
}

/// Full standalone verification of one shuffle bucket (direct residual
/// checks + both scalar checks). Does not depend on the hand binding
/// (the BG statement is bound by its own transcript).
pub fn verify_bg_shuffle(bucket: Span<felt252>) -> bool {
    let (equations, _ch, scalars_ok) = match bg_equations(bucket) {
        Option::Some(v) => v,
        Option::None => { return false; },
    };
    if !scalars_ok {
        return false;
    }
    let mut i: u32 = 0;
    while i < equations.len() {
        let nz: Option<NonZeroEcPoint> = (*equations.at(i)).try_into();
        if nz.is_some() {
            return false;
        }
        i += 1;
    }
    true
}

#[cfg(target: 'test')]
pub mod tests {
    use super::super::bg_stark::{bg_equations, bg_replay_challenges, verify_bg_shuffle};
    use core::ec::NonZeroEcPoint;
    use core::option::Option;
    use core::traits::TryInto;
    use core::array::{ArrayTrait, SpanTrait};

    /// hand_binding of the /tmp/bgvectors set (same value as
    /// hand_batch_stark::tests::FULL_HAND_BINDING — 0x025b5b..5b BE word).
    pub const BGV_BINDING: felt252 = 0x025b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b;

    /// Honest n=52 shuffle bucket (deck-size word first; generated by the
    /// Rust `bg_vectors` test from an honest BG prove, host-verified).
    pub fn bg_bucket() -> Array<felt252> {
        array![
            0x0000000000000000000000000000000000000000000000000000000000000034,
            0x03eec89ec15f1b2da685ff0ce8f3d9965a4464cc7aa5dc2f752a06e67e46754c,
            0x07d1d0d6e3552e0a919ca6bd4810a317f950ee2068b0cf3e90e3940f5c2284dd,
            0x06639aa1a45e4315da5ae17105a3884b6ebf5ca40b7b9fa9025db6e727a00a52,
            0x0393f303356c6506d441c8796ad76d55036455473739a4a3b4c534b1a5ac471a,
            0x0338ce1cdf8bb71d3ce9cf7417fe154eb66d6747bd7fa03de6142288df81d1f6,
            0x035bdb3446a889b242da0c273a8fa2212809fe1f51759fee0d825d43b1e1f535,
            0x02e80a70779618012404854e825ff8d88ccacb6277c4b274ba53a6697879c43a,
            0x036fa9f6a13a5133507f4584faee158b80f07964a813d8bbba65bf68be802913,
            0x04b73817ec61e681d6e33ec86e12c2b79efd197f2bf7df704bf18e26643951c0,
            0x06f844a0db15d33acc54da42dbbd11b74c0cf5dda27dce3a96acda4707fdee2d,
            0x07251e3227cbda55f55425a96fb25796e13a0dbcf20dbc7fd5da977b26779cb2,
            0x02d51b4b5c42efc49264bb80064b9be3199ba0104e5eaad527158040cab4da36,
            0x05d9c18de1878fb3b7509c96238e70b0d70d4bb1f51e559e6c010eb970c458b0,
            0x07d867fdc1a607eece16f4a68e0888ff2287e99ad54be4e2cd464b2005d37869,
            0x016bf675a12c267edb3826f8d0b6219d265916e9cf7be156d0bc9954d8671654,
            0x050a270c9befb40ade22cae6f89ca0ae56ecbee2f518a8b3efdf2b05b1135ff8,
            0x00c094ee17ad2eeba5bf811c0f91231d056c5badee41204351cbba3e518a4e6c,
            0x05e4b5d93283d710a2d7a19be96a56e714e6a0162d920ec2ec56feb84369db82,
            0x05c24e6efc74da5a2c303211c90caff4825c5e2b42348b58f414310ece43b0de,
            0x02a03ab04995018b410c433cdb8ca82d71953eb761d84d64edf82128c8ee1b96,
            0x056337236d331d73e033febca47e479df42699fd55830ed85bb46fb69160a37c,
            0x05875a09e0e2c5078fdb498b0e2a04e9c7ad010a00593696a5bdec0e9bec192d,
            0x043668ecfbd9ba03f478e5f55f41034b9296c04a906706f18e9233fcc6525b13,
            0x04f8f30adb62c312999eb669fd9763625d0d91ece462771b85e5ebd96bd45656,
            0x023bb613f40595e26aec85a112e3d458fd263ff5ddf0647f5dd9b2b36bbaffc7,
            0x0539a6571fac89626b5caa3eb974678f9d8df26ba74ff6e5ed95e01d46997fe3,
            0x052831d729a572fef37b17ad348c11425d2b4cb684ea77a6900f7dc590d8bd46,
            0x028a914ca38cfde7f90627eee37d21c2f0465898c6214afc3171ca14524ff088,
            0x001c9850bbaf9c6c1b7bd7916dd1bb4250cefef3ef926db5ed7777cdebd5da88,
            0x0590aa1ed14b3e19e9bbc95a445226e79cbc134c1b52e8c505f7e19429296b51,
            0x07d55239b8525cf3ab39da0725a1968262ff883afd384827eda8339b8a05dae9,
            0x0258c7127a6af6a5c3149357bfaba88441755cb9dc236a78727eb4e5b8ce6083,
            0x04e4cfa15a22047f0b232aa12a6fc3dda919261659c4752fdfcb47c40e820444,
            0x023cde0c3e332ee51eceb1abe3bb9dc7ff689148aef66884027aeb0361251d75,
            0x05889f1b5ec3ee93710cc15aa29cf55d5109dfde633093a56ed5a0d1cdd90373,
            0x06f83bccc3bd955fe224a77b54ba64666783526811eacf0e989e431b13be150f,
            0x05f4a1d5b90132d9fbbe97b4a4f61ecaabc9f21fb930dd8a8224cb492e6d86e3,
            0x02739955277129060e8b57b8bb4c978bcb8d18bc82337ee19a1fec07f34bbd17,
            0x012169fb4dd37643920bedce9088faaf0471ffdb3adf41c2fd3960a1b76a100c,
            0x06c4bdcdae864d8f1959ea1e406131f427d4ac4b7e6daf0f5ec4e3ecec21188c,
            0x004139b7460b9ae62a959d8a6eb2b080a5f0f9dcbeac798c305eda1ffb44a282,
            0x07a64c7b483eeca4615eb75375c071930d968ec348d0a5dc7ea985af6d0dd15c,
            0x01542b7488c0939b921c1ea12c64d505aecf54b6bc6a59533c0a80449ebf6246,
            0x03d7e9b1bfa8bd5dbc9d959f7e97343ab8623bc2fe76c7e81e557052f3e7aec7,
            0x00ca39786418b189cf9e4be6838c9a4077ad8318f0cd493d69c9c141f2d78221,
            0x01b66a36b810322e7c6ecb2f5211e3bc10ca46898bb92039e3ab86d4fc6dc386,
            0x07f39741b95a76253f417eff4691ef6abe3e74d66fd8aa1fc87dff1cbfbf6a3a,
            0x07b5f47fe26ebaf4026a3897f8ddbcaa630b572dabf28f7f37b092ad51824c86,
            0x03016311d64eb0834ec65db6877d881d0f8e5b891165979d8827228dde917ff5,
            0x00573d8d740eb19a3eaf5e0d21ea7a52322fdf52d35fa47b36baaab06877c2f6,
            0x06873dff5f50f848658bb28e7f75690eac6af13f1245ed757f4c7af79cca595f,
            0x0715277b5f036972478c1337610a51288b238e10b4fe521b3df893ce8d612368,
            0x010f2c1531ad4f5dbe6eab7dad75d39825fa836a428ef6548fc7ef8b6e2fcd1e,
            0x06a6b26844d81e70efd3210da5c2d48781ba2f4a4123d6121f691d88a1eee6b0,
            0x018f470161511b361627e848c2fdc3c79bfc895d852ca85ad2be27476c36238b,
            0x05511e8b486f92b968b8a45a10c965b194b93cb1fdba73bc11d6e336802a73cb,
            0x0795b54cb7687dc40e76bda1cd026a601d14128a3710ca359505a6b3e0cb3232,
            0x05f3c6ffb9469eea6cd502e14628f46f7d7590213e1bd055b85711f5ecbfa57e,
            0x0699946860682db2800233e855165259cd823664277014a5412641dcf4aa95e7,
            0x02d8c6e16f8ea4831a77d786c7471ffd42aacaec3d57f0ce62bc7c699215b96d,
            0x03a699293e4a061d3b0df5378a7a09925b68b3713df536f22686950e46c978a9,
            0x05d1f0f217cfde68294af036273b5dd3a77327ee40f64dc00a0eed267df2af49,
            0x0394588f0238bb830a99f93c4d2e225d7b9a1d2fd4129717c5a4591c9b571aeb,
            0x016e73e4bf0c058b75fc001eee9c84acdca94f920313a04803eea97bcd9c052c,
            0x0771c68e702fa7bf15b5937970b5d3bcaea0b54809c5676f235723f4588b93e9,
            0x045f02d95c54d2b848b9aa50b11e329af89732d58ac8dc87d17c17a008414b24,
            0x0694f8f3d22e65a7f0d751d9561a06efd7d57515a7d412c754cc546c15822fae,
            0x03a13109afcbb138e0a8209e4a701088b5038e0382dc0c0164378b65c48ab2f6,
            0x01b0bea079352474f1dd20c0b517973b2d613aa5b084f2fba13d659bab9d08a2,
            0x061004b77814bafe17df008294a73a0ccabfb8fbe218d4c0f56b3a0eabe70def,
            0x06fa9e8559958b02908f90968223ea560d5934768fd14859d3dfd88c432c539b,
            0x04374b5ea91b2eac6cc2981b54f0dcd0db5c64161cf20449fbc8a4e51a559b8a,
            0x07ac31b393c8fddc615a7e786bb13f17c5937329f692101d25521cd254518121,
            0x05622b772dcefc6e85df068e28575609ffae7bbbb2237ac34c361810c8fd1f0a,
            0x0549c25dd75fc4039e6af627ba79c9dc98707ba08cc271096ad84bd9a67311c5,
            0x05ab832b99ee0dcd6d51147fdd25ae5c83f24cceb1919d0044c6a895771be5c8,
            0x0234fecd6311ebb9e33519d37d6b3c26d2b781a4b3f1abb0f9910117fc360987,
            0x016e3d2ce0c1a26259680b009501be6c655c7958bec50f33590bd68084466f1c,
            0x039fee6f95fa96e705346a97b28ba394d99e2000c0ec4eecdb9cd37b1dc1c69e,
            0x07e2de9b40d9fad39ac2f37cd0dc039af5fae13bc09cac35a7c8859b2ce016da,
            0x071e8ceab88f0d1486f37caa30a2b61e410d8a16658682845551c0e0d1c5a57d,
            0x03abd30877f264a667c05e6b5f7639a410f8089e423964539713ff8d7caae04c,
            0x00ab1ec86155bc105b35f1593c51cfa707bbc3ce50603f86ded0ac24b445786b,
            0x04dbb81037d3867fb6b36f07d94b6477b591910d07e3cf2d7a0ce457d4ad5b44,
            0x078883103c047537779c0b9e24e83dc9c70bb0c098770a79b366a3feb6713efd,
            0x06378952708d4af83e6f32e1d8c0e8fdc3007eb98e359f679ba677069ce52baf,
            0x0528e1741081c15855d0daaf2fd7d1b57e38dcef7c42ee540fcb088d7795e763,
            0x0253e3f32fa3541c486924214f036880ffae4102e14414e0c6992b4b12c5e862,
            0x058a7b1cabd787b9645fd96fa264954c1708448ea0880b3681471e6e18338356,
            0x0529dae575860f5a1c6611893bbc4941888dccf8b88bea1c72342811f63f01e6,
            0x04cb222a0e5a82a26d462c004ec5435b1eb7193bfb4bdc4b689d52c8850bd744,
            0x048e885ea84762a286d421947b67127d96801de5cb05a94d6a7100e344f9c011,
            0x01b974f83aad60cd1ce25d1bee6414371ec21c584dc94f82234d3fda53f01f6d,
            0x06264d315b122d0d35e313f5e4116d41d98ed8cd57f11fe45c138e802ff22f9d,
            0x03d1c668b64e429e2c5cf908fd3a550a214aa61d51f81c27b5f221e38cefa1e0,
            0x036450dc79aed3c38ffb502b676351d6093c10ff530f08fca777ada0c1e9e023,
            0x066e9667ac47eacfcd612f5ab0912a80f01a43cafd686f2e555e7413ef6ceead,
            0x0713d7f1451dd8e40aa4ee643827f585b1e1c3585482fd3926c410757ab0cb98,
            0x063111f413ca7cd06fb3ea2210bac04bac240bf897461aab2c582ce52504a7fc,
            0x020a865eba2a17a6f30f7b167550bd50d9fc7ef22f7e18f92faca106c80f6db2,
            0x0195680ede9bc0121b7703e1bc97acb12f14b2ebcd00412275ae9c2d4c7d653b,
            0x036ffeb650f6dc420b421e80966e95feba9c1cf695bd611f2ad8bff27c177d78,
            0x017387fc57a7e10c8baea75dd32cdc35b8113d3885c3c15f6bef10aa892d741c,
            0x04ce0b351723423394907ae1a9e8112dc5de3a5c979015eb71ca1137e7b123aa,
            0x032369c1a2f67efb6a502befc0126d3a3960760b1cf5268f66f5e5c6ef50cf8a,
            0x02eb316239cde677dfd5d75153b23e140e26e129ffaff287510b80ceb17e1b0e,
            0x000126227b058461dfcc6a65aa8e8822febab473f739a2db401cda8b7c1da9af,
            0x05d0eab2067bfc193ce2bf254e6ed36f6d3f16476740fc06f260567e4a142a4f,
            0x05448feb681879f9b2e0292bde747f09f967a0a2a03b04f259d8954da9053cfc,
            0x0782eea4c8c25adb8e5afb9f2f2bf4406a723c7c15fccd768911fcdadf792e68,
            0x03d4f17df1313ba793e979fa9f26bb5b897f6326ebe0df36a8b4595896a90ecf,
            0x01e7ab8000be97cee48769f28355783f9dbc8623775c450057d7b86762da4c14,
            0x0604d1570cf20e4c6ca822b982eb89ed0f7bfd778103cfea8414f6d54c38551a,
            0x03656fcaa637016b78f26dbc27ab38f449f0afb111eec19be00861ec5cc35b35,
            0x03a17d7a40ae553b48d2a97a31dc82968ea16f98e1b7fbca65e8893b639bcb39,
            0x074dc8433b5d27009d8699366ee1d6b2f19dca84449adf431d8a6a053c6555f0,
            0x0332a5f58f770dd5c02b30e98c7c76a401290df1ff8e26d28ac4d99f167c43ca,
            0x02741fa935256fc04c35624c423e0408200023837767d0590299056c04f97aa9,
            0x06a2da8de1f78f6af10682bac9c036d7eb7ce47cab571bf31c7b36fa8c055f20,
            0x003e864d106f0cfa6faa5e3c2cfe51987f81fe2efd2b10387aa12dab9aac2c69,
            0x0501b012c27cdd9a16c3ca626f0b48ac187a8ceab7399cc3f1ae1ad0eb99a2dd,
            0x00577f46d3ec2e2f637044923a67b1d6e6282cff96596539d723334d22e933c0,
            0x04bbb9ec7a766c4f130515f8d1808971e4e61891c076580a0842c5503b0bc4de,
            0x007b486a0ad431f13109ae82f87843f2d49c117e42f3f76b8edd8c59a3ec0482,
            0x06b68dc7e820d2e5a0996436b27805fd6bf30c5bb0551f06758c6d6f816c268c,
            0x06b20e35ab39b1ed24ba1ef72effe91bcfbb1015204e79bf5808cd63f0bea2af,
            0x0652d5352e12a151c67f873fce03f9ce0a96f9e68f916543bb35c5ebadddb772,
            0x0665c153a2b23a7fef68d252fb83f4a4364cee5362ac9178aaa67fd931178d37,
            0x00a5650f221b4f9900d9d86947547eaddfef3daa220857bd941cfd1d5e2fcb03,
            0x05d395ad1d08b1c8475a0336fe5a0bd1502fe188ce65452d701d4b16c6ca4d32,
            0x0588c832b3ac355c3ab6db5003f2ec68870eba3e9d0eaf2196e55651ebd4230d,
            0x074baeefe254c30d92be827aefd683c3dca139dfbba1ce845f704e0b0c30345d,
            0x0559f9cc02999278d23c3974d7ef504a1dfb5c2ce3801454e1955895ba97e9fe,
            0x030f9ccff745481c46771f3e18e8c232d85dde796c3eda6177d797b216cada74,
            0x020d1ceeb6991c4cd14046fbb8bf07bbe64ef23f82cdfc693b22ee9eaae24134,
            0x07e14be5c0a8e909688f2db5ec08257bdd4e6ad10630d6d7721b8c1d079cd5b2,
            0x0481eb60189be7b8b0103f011b899663ce080a0e24d020f75df20c2376368e38,
            0x0729ffb66c83feb18ec9c94659c3ba355ad63468965cc0bae394a57a0200e622,
            0x076adce6d7e498a9d25522903dc303e67ff21f82f076bb6e08c26249123ce78a,
            0x01dd46782a09511c81a194651969641bcfbaffcb0a35bd714a33a927a28be8d5,
            0x0345c7d61c2f8f6e8ebf180120f8ac80af8599ef4d425a36ec6c4704b9f34e49,
            0x04d723b2a465f91cd0e2cb873a5be89c07f0609ec456172d01ea07b2104c990c,
            0x0595bdf13f73dd6d7e35c7e96b09658edd922645b049d6f904dc645cdbd9e340,
            0x04daf72956575a3e49aea957476246ca442ce6fd8d76f1355c4a3a377eb484e7,
            0x04d45d6d33412c26bf12d168e02485b16784ea5a3e41653a07fe01e47100d22b,
            0x04608629101436a146165d1e21f1772ca80d91df1c0fe43424e1a1acdd72fc28,
            0x04c71eb51ac186202a515a752ecfe6d6a8f5ee4a3524cc84f4f7667024473671,
            0x027912f773ec54b2af25b11e6ed0c1a81049d0075f9abe1edf15cbc876e67f2a,
            0x03d8d696c4b7bfd7811405637c7d1636193b233f4884f75433822989d6cf95e7,
            0x042e7a2eb0da2441067b7d5a7f639612cc71f40109f8e5a4a6b4b20150fcb869,
            0x04a1191ce31eba86c4dac9e27e6d4e738c2ee54414168391b01124c0d4f0a2eb,
            0x004be5e41c9ce53f9302b4af97a3e430b6c78af43b53bb442da04e86c302e1d6,
            0x020e2ff84bd5df85e9523ba2519cb27eda7a0ccfec090535e0656bfbed17e181,
            0x07bb9469ce554d75dbf2fa4ec800cd7db0fbdb16d9a1a8c270ec49694092b35b,
            0x057af63e657033441691d8b9808b90939df8b1d948e10d926db09e86d13af545,
            0x0346cfac73d56efb14eb9dbd65eaef0460d447eb4efb8a1bbbfa2d2b1ad73765,
            0x06361a929bb18481135f9c00243b440cc2f32aedf566cca539a799d891ba96e0,
            0x0187f94ee9fe5103bbf14e9f6fb9aadbe6ebab00cfa6536843320bea4c2bea3f,
            0x02c853b783c8cbaeb50c4f93fbdf6ba15613403d69fbafb5937de9972c2a9880,
            0x005547e1d17ede57a16cf3ee2ceea759de9e54e6ddfe17d33d8ab2fc6f6eb0cc,
            0x001d0566f74ae78a2dc9e5ce9dcd3265160018682807ee47e94759369e13acb8,
            0x014fcdd4c42ac6723571a049309412e2c130328236844b2dc36d03329c818b62,
            0x0737bcdf871e52b1cff4c4ec6f14dbd17e686f11d2fe6dc94e4f8a7a6c1e1abf,
            0x02c55e19f86d3099e0988913847f1c6dff163000b18dc85338d8951e43188832,
            0x038956484549c52fe8ec99cf585a55c0f472ca4374b9d93f0d312ba331b527e4,
            0x0292d1657b33249c4752d5781347882f6f7edcf443ef1878fed640e3b1172b3a,
            0x01f7f63b1df6054913025c526e34b6cb63654e8aa8544ae740a2f1a8fc621f37,
            0x0414295cb88375834402fd3c6ce8397fa850cf5b402cdcbf1d5f9979bc3d96b5,
            0x00d5f441c29c84960f40eabf26e61514f47690ca474836c8096587b5d3eab63e,
            0x052fad0fc4eee9a33a52f3ea8ce8fdd1099a1d2b3413603351d01cde713987c6,
            0x03511fcb68ad57700e4603888b142982c2edb1120922ac8cde6cb0009ccd8cb6,
            0x02f70fe44b27fb71d365d086b20cff5988e1d7838b91415a18a6c2709317bbca,
            0x01b652e0bfbcf905e714e2b8bb5f03cc582e61dcd8734facf69d33915ad3a6f6,
            0x002f42c0fd2dc5b39e76894b0a21a63eb6d5e388010cd5f60d052f8f31ce38fb,
            0x0706de7e322adc500e4bc591a303c6e2990669dcd88b19dcc054fae0517a76a6,
            0x04dc4059f54ce3694e3b297d0a5abfc4b67e46d7f127887e3ed9f101374f3af8,
            0x046b22b72fa324701dfaa0993b25edb11d4ed9a8418eb24739f02d4e15d0a211,
            0x025cb94120f9a61498c5c9544cf6ec98636a08450a069bf1b96293684e08ea56,
            0x064f9fbd61154770102c7936eb9eb6c2c3fe1b5a1013b318c5448cf4c58616d0,
            0x020a5e4fe2eb3494d4fb674892bbe89e2b12272b3796d1f152435c27b7b24f83,
            0x05d0b13a2863d2aed49d0aa9b79343778426d2352002cfd43be33767bd5668ef,
            0x0779cb56a7404be78ccb64a81606e199451f562e7ba3c5b033dcc44f8e82f027,
            0x032a06963bfbb17a7e64b2862411c27ad2ffb5b670a754a6102c029cb2816000,
            0x02d37bc55fb198ec746759161574bb73e5f8e0791fd73d7d9a63f3e09a4d1b15,
            0x069a7ca943de955635e79e667dac2702877380f434001d55e97ebe0a30c05a94,
            0x02cc2547b896a31836c8879255387796e4717900eaa607586bf5449702abf451,
            0x0574cb048e95daf5f755381c99d89e11b016fae60a4d6ad35532319da7040baa,
            0x030ecefbc79b530053eb4cb78dd4007638f11a6671a430f414f44db18244050c,
            0x009233bbbd1c2e6155380ab9639bfe79ba0ff6cb69058f4c72fb54393efb0e96,
            0x00884657c5adeab414872eeb575f2d13d51c2c0ba23b6ab6a82070e4e631fbe1,
            0x00496693d34185e85210c1b1dd871a6039e254cca618f5d782b4df3f5d89f05b,
            0x05cf552c07e2cc468ee2e8417b88c1c7f9db711b1875cd48f4bd8631889aabeb,
            0x01bd2020a14908198233f942df3f5b082c61144918abb05793c920ddabb5ddb1,
            0x02363258fda01733ca2b28d86cef5a0fcda4a73582b73fd26a6f26d724850141,
            0x001eace640bfb6c849d506596855f4cb1366cda62855ea100bcbb3e0936bcd1a,
            0x0791ea8c480360785f48d522834ed420f5bedc6bfc6e7d690df7ff7880614e8f,
            0x02125e1688991fd18a340b5e473b53877eba42cce981b0ce2a32a6e01e9c2864,
            0x03ffb66ec34431e4db8f2debc8f4867c0ded09d682614b72ecc86bce578850dd,
            0x04871f2c40be4cfd6e6903a7adb777050c8d00ddf7a248b28f66d437b4c9181b,
            0x06bf3041ce721111e06f36a8cccc17caa347793de65265690f417ce880917602,
            0x070059ce3799209b86572142cf43dc45fbb9768d9c6a53ab5980afd8c39c7273,
            0x0260047abf2fa8a7b4319e6e2f20f8560cd62a9a7a48f131039de0d7dd23a554,
            0x04813d908a2df99cc0ac0b0af6b5a77ac0b4f45f3f59e5e1b0570a9bbe1c1e9d,
            0x075a033d37414ce41a4db35a19a1d1558a214cc5e968d97f28ed7515026975c5,
            0x0013eceb3cf634f6341326fe734ab576eccf20b76203044f9c5c9f64257a8f42,
            0x017841025de61a2892a856a1531163aa2591c79e61725f536a368776cc194824,
            0x023e99d82ce045be4517ed8e20b228891f17e894db75ec9a9c20bf001e7064e8,
            0x0328c33ffb22c31d794c1952f6a3e93af6faf03b0a9d7b23727a6d059f146cf4,
            0x0187943a4c72a80f8b749375943da540f252311f0e81a85e9f7b99b750f288a1,
            0x03c81bcd2330d689b4f87c695682bd80865f5c532ea65e733bda509eba011e3f,
            0x047d25aba8acce5c487c251e04a29319ddc51487a3332373e0d95602ad59f2b9,
            0x03afe6447ca65fc8ff42f9cbb579a5197ba1750976e0ae3afb7601363cada2c2,
            0x051255c3129973b41ad1fc4cc765b79bc1faf76bc5a45da819910a5fbda45291,
            0x07cafc31adbf6e972a9a60436f6331f6920d825becb8f08c054a544e3ca8295f,
            0x00e635b09216adf4687d0b71ca29076d67654505d98c0f7d2ed515b8117f3aa3,
            0x0092ebbb1deddce1219ce4d73e4ab49c942db085ac827867cf4f01c6a52b9f0e,
            0x02d5fc0f037bf5878cf876a021f0bdd0f6deeb2ad2c9c636c2dfa0df82f968ed,
            0x000c83b747bb5fc139a7ad830a7193951e3cb1db7ab540989504e7cae859887b,
            0x07814b0b6e009fc65f0b7578c4108abdeb09909c5248cf973ad7b8f049cbaba3,
            0x05263859a311400a811609db0c01eab9a15e167d17a0f5885455ec30bcde65df,
            0x05626a6d08907bb4e8312d4293e7c8642b99438261ad4ef389a53684ad41f1a7,
            0x019169b98891d5026441a58edfd9c69feb8f3c2c4cf57d45a7e80dc880e6d7d6,
            0x07d6bbbd849e2137341eb7f4c9cfd29de3816414284f12d72828b8e6aac845dd,
            0x072eed1629abfe8a8d0489c5e8604f25ad7c728f41ab7f064194ab5f45e763bf,
            0x0059241fec8415fd987651bf505fa03fbc9670bfd17c6f4aee6c36e9327e86c9,
            0x0258d4315a904ce2f4253c944975f978ee195278d5c4ccfa9f6dd34369d4cfa5,
            0x038a1dbd5574bc44fc4896a3a82d6c05e5ed8461bb84f48a534c0d5c5153f9a3,
            0x03054bb868ac3ee7bd7e06bbc2d73f93f5733a64c012303e159eb979c610aca9,
            0x0530bfdc7c8a97ba89e4a8b7b76bad97347d33ac2555c0d06dab3cb6b1db832c,
            0x02a625cee74f248c5536b1c5000136fee42da3935070962515908634ce9a349b,
            0x03f058bdd4ed452ada284e301df8f094e2d99979d053f62adcee5076e0f0a26e,
            0x006e517e804c7480c951f6655e2e83713c82e25de32b1ff5b1ff793d984258e8,
            0x03716b5550bed6bf4c94e42ca1d7b4662b00bbfaad42c0d082feee14053a7432,
            0x07ec82741aac2bcf58d6ee307b307e55d46bdbb02c3a3d6aa1ae2ffaacaaea8b,
            0x071019bb1339308614b1d92f159e23d78a560981ddcc0a3e35a84313cd2a1ae8,
            0x01e414a4d7a1a5bb8c3d107badc5d80c6e076c9c0e1049039419620f639262a6,
            0x01c97a5da25b9e023a9437c2866498a495eb7be03dd487b538a65c51747c9a09,
            0x05d173f0c178b668377e0d2339df625811e6c79449a15696cabbf07a4294ea8a,
            0x079afb8861bf191e0987f57a1e42e6c2d985d0f84330c3be9cb47d0e6f6d1888,
            0x05d7826bffcaed4c3759fd029de63a7def0aaf4b66e69eb85df3c7f8295854b3,
            0x03f2647812df82b3c41e7ce5eae0c53608d6280f696295fac527c51863f2cb82,
            0x03504856def4817f057fb0450120b3c5364f654eac67f57fefefabcfd292c1e1,
            0x01eb8fbed450aa80dc68e70f4a705373d0d262f8c085e61002da73f802952542,
            0x041b7da2bb466a5225d429c76ebe6c3c3b2dc6cf15d02e1e6240dbcf890a780f,
            0x063fc9a24ae74a71b5a74cd07f01f27246bf8998f9aeef28185c86904cefe91f,
            0x03560ef17e1c785a21e374b1d481c7f5fb5cd941fc195e28869141de7e2a185a,
            0x0515f8bb8e9e11e8a7b618c1dbb92f93cbe07dcc87570a010cee4ecfda3cf387,
            0x01b7b0dcaa8c9e00a6a3a2888e15843ea9fbf48e0e599e983f50a8a87dd52b2e,
            0x0462aade1e4675a6b2519e5c27990d0aced038d578b60f26b00aaaaa0fda0f91,
            0x05dd00ff751855662a408374db39f9d8c551eae6007c85e191490214b3b0b8f2,
            0x01b593cd8d8c1f89406e23c384f84a5cc09e44ab8786389229b3ffee26a189ac,
            0x054598bb21f821852beda0a5008bb1daa7de87428269453179ffb8a8dd77bc70,
            0x06ddb0e5d1fcfcd94136e9435f8cb83895c900e6a8d8634b27decc99dc3c330c,
            0x01d5d5debcfd0563067d2c8505291c972abad64b2931ac7bc002b55b05aee4c3,
            0x00767548a787c33626368d3d7c96c2a2d415b20e7e333d7c6fb10f8ecf64d7ab,
            0x01eec6507048a31de8b19719fd214b9cd3738455259694f861e457bfe66e9180,
            0x0427d5bfe6e4a7831839d5eb7324d911884672988c98d0aac713a4109ac2ff22,
            0x06c718cc6f8096e3097359616a60a7d8a58a2d0837d93939a45c256e821f0667,
            0x06a00c9cb74549b7b0198b10294ff66572f3b7dbd2dcfcf264d640372a4b69a8,
            0x05ae8919b4e23d54b3491e258c42fb1fe43735b3b95ff9550b7d43209aa2fbb1,
            0x054c7326c8f976f01bf9553f3e3b593893b108159b6a70525d7daa270e583da7,
            0x0102888200e4b8a0df0e09b70ef73be2675d4188541d2e27fdf5b864d8d7d6f3,
            0x04b63f70eb4d91b51d2bc4ec44e2cc3d0855aecad829d98e5d54d3c8151cad5c,
            0x023a50e42172874d6f94e31e6511a0ecf704f46ec2cf51a0b872738f7bc9667d,
            0x038f6b1c4a5baf871b097b69e18e747b0b0cb45241dd2adcc0979ade7a1bfd8d,
            0x00c94375cf22a7ea2122d678627bbb1a1a14db41fc515e210346de79c7ab866b,
            0x0276857a5ab8e1ef5dc4f38f4fb464aba0580b729b09e5a95db93687e7a9bdd7,
            0x057fd6838cdd96d28531f4c7c390cafa400279e65f5eccf7a4ca706b4bd7bf33,
            0x02aa059c8673a7af3aae1f0dfd4e74335646adafde728d730cd7801ecc4a134e,
            0x029478b2c8796ccbc36d4d5c1fbc68302ee594ef9c4e95cb6077078db21fa0d3,
            0x026810f4bee4d854e648e282eae2e9525de12971b289be22283b2217ea2d6ad2,
            0x00f76b9d4a4d59ad594e07c46e5deb7991e884805ccbc45d9707f381c7ee3945,
            0x02f4fe579257b40e99fb6f8bc66dbfb4b8f692abf26aa0fee50ff08e9f01d876,
            0x06b53520bfccd2dbf3f841a63c00a11248253b69d14affbd56c4096ebc3b4735,
            0x02b800e33d4750f7594812b1086e302c9bd56660d482c0e12ed1ed5f089738c4,
            0x0071905cd726dcbe64c6cb53695d9b2613f92351b383faa1e0a20bef96ee8bd7,
            0x01b922e7f541ee6780218f7e7f9402a439bc62f1cbd0d18d805127c5bd1cdcec,
            0x02d82f4f1eb36281c616a366f8bac795817085d8e30b60f67e03d3cdf70808b5,
            0x05efdbdb2e4698d7725fd185e5a2d380401dcfaea66970e38b0368ec723cbf21,
            0x049757460b63d0f691e8f7abd2ba0ea6ee50b495fcfaf192cf30d04349af40d1,
            0x06b46e9830a4676ee27d9a15ecffe711d510ff60698eee78876691dc9d391dc8,
            0x00984c73d12f0e8d9712cb0c032db33b78b225d0b509c5fee590d370891e5e7d,
            0x0282ad6df8717b6ee7a29661e360785483201a46cddff4516e5e621a563f46ad,
            0x0737845ed3749c9ba1a3b3cc7b81462b65b16c9c572525b79e71c8dd2d80b785,
            0x000768bbc92263c0ce09dc6ac13c4ba2859851a659d9ac5c7cb9bc551fde8c5e,
            0x079c9ae4eb8637d45b457a140f40acee894410ec29989f4bce7676fed00948f8,
            0x00dfa4f788e0f7ecb134dacea7837001959ea7196c7464a3f4592e5bc2537da2,
            0x001dfc8d5fd28b14d660706fdab0c95a26a3122acf4010e722d61cfdcec38032,
            0x026a78836d21fd1d1f70325f2b2c3d0e195529ae057c16e0be235c964528691a,
            0x05426a05bd5e37dbf2abc298ee8d831c7d1a361602842069efcc9c74816e96f0,
            0x03d4f74ddc37d69f839fc8ba3a9167a9b93a3f4ac8141f9bc5ec50aebd909006,
            0x007b5033398c6cabdb7ff480cdc0f289b75cc201b62c985fa0b92f7b01736cc0,
            0x025ba1db745d9b5092d71c429ff7cb81e0604ec7009c9cad2bd104e46f01a049,
            0x0689a7dd43a7032e8b31ad55dd9e67a641acfb9499ede593e8dede33cec25494,
            0x03c5f5a21c4f435060c1473d129cfece17e771e00913a12ac628883641c39f29,
            0x05759cd100eca68974e7c55e570eb2b4bc475395f2fc269d737f9bcf01be3e5d,
            0x00521920bd4a5805e596b4824801f010a785d4ece70b0b8ea3dda1858075a6e5,
            0x0698cad1018a22cddc857e6b0d0addb56ae7d572452e402766d063064452ba47,
            0x02a6c3a7210e51be7f34762f651bc06b9cb2084e5fc3a2fbfcb51b284f194e46,
            0x03d33278322dde5f84db8b7c92a47c1dd10e665501b7fe563d0b93c75a63abe1,
            0x00f8c8757ebbda5eb7d31c8f33181f441cb24760b45168c53a00976a2cf796d2,
            0x022a0771bf19a7e3c33c537d7469ace292ebb7491eab3056c48f9b1da056368c,
            0x07c0fc365d52958699ed2996cf52c6b891f8b2816e9f9180b10320e20ad9f8dd,
            0x03512ac378ead38a9378a19921825a711987a97acc8da4eaf7d374b72161baca,
            0x0181b9786dfe0a24edbbb1621a610cfbfec621ff9ab91a9b587820b6278a3891,
            0x02892959e1a71e577871962693c90cbc5b34e3f7e7011c03f03b4978002e264b,
            0x07a2e5b8c5e6fd28255176601126f25c06f0bf8dbb2b2664c5347967c334dcd6,
            0x0228132613799fff582510f85cb3c49b37e704834585fde62d112bd430e6adbd,
            0x03dda0731ec5c15f59a9f42271e13e20c0551195f956e4c31133930baf834c26,
            0x0022ab30e6dbe8b660f81c18477e0a79bb9620497ff1e033445e7036a6a6bf20,
            0x06526232436351aa1ff942011c1c7f041c8c7d1ac1bd1ce6f268d089575d5a44,
            0x03c3364b61584d564bc3248cbe2964a7282040a4da47028f325eacdf10de67fd,
            0x04864d058196b0f4affc31486a0d85f0b6ef05b10c7ebad854130a6b6723ada0,
            0x010ff9a503af1022d3e62f3e015cc5d7cf61d6c6bb45ce1a1102db1c548b68b9,
            0x06370e7697294363d3bec0b3d7517fd56d4649bb48cb286a013d1ea4860817d9,
            0x07c5197e2f8e374bbc444f8fdfe9e4d9359219461afaff98abc4f53fca2b4dcb,
            0x0385aa5bbc3b1a5b94e3676111ad64c4b3ef278252fbd1be804073fa1f3da2f5,
            0x00f3fc885e9e2faf74a72328d5713e68b866965e15354f5a745100246d2406e4,
            0x027347335c366be93418542826394023e2965f13d9cf9aa56d90a2d08b4b1bbf,
            0x05e5baf9c2ea322288a2b36561d5507609bc373201fda393ed4e19326767a891,
            0x022bd509a7d1c2e0caed69304a069546f851e9a16c3356268d199d929a89be76,
            0x021a96f63e283084802c7ac99346d01f972282524ca20d774a99ae9a81c7c97c,
            0x029aa4ba09f9e2d1a4c5d4c6f82a221945e21832fb141c5740e9965e6abe8c11,
            0x074291952e7eb5964475c5fe96e96b9294618959efe8d7e6ec06b5b0c4b10be1,
            0x078688329b0ae2dc54a329db0d1219af0297dd3880505e01b3cec633b55183ca,
            0x036600d4f9693862bd55283f2bbb271800d54b230b069402030365d55b016482,
            0x034b9ed076e3e3fbe67aa5620c7c5bbb077ac473ecf054c3b2f3e41c3896f63d,
            0x03baafe0805e464c3a6a57a2744d2cef079660a18d1e27b9096e2b557ad5e062,
            0x0225a9d471f6aa884ec9e559d3dd5dc661be6bb3e3d38fcd7ec0d38edb4ccbfb,
            0x0583e385b72f3b6996b663a9041b38918d00f9718671b9240320d5de67783777,
            0x0302ac3fe8f0463ac39810a1f789aae6e95d1dc4c5b41d755d549f991a26da73,
            0x07559b001073012e58e3495fe68c2d124b403c2fcd6135694fb064d3038eaa09,
            0x06de62af669ca25187e80bc77af25462a89cdc0baa9cb30a5c2ebe4690f2aa79,
            0x010451530d38542a3f72dbff73c71b9e8c9e772c795194f637638f52085bcd77,
            0x04553f2a3eae58bacf76bbf5ff43c1a6a89b7108ed11333d2b77721c34a0b5f0,
            0x071e28101a3c237344c284d0bdccaec920613ba1a73cd744a667d971b3fafe39,
            0x051689f83055dacefa74decb43aaff7d5416999773dc07758701db8e894b2617,
            0x000de1d3cee98f17d340f3668f23886a32a3ee1e9ba182ddee3c4abe8965d966,
            0x01882c95d4fe63c213bf97e5038212d0fe86f52e610bffedfbb4d8dadb043646,
            0x01e7d6e154739b546b1e50e24005fa7f85816e8206f8440fdf01287a0678ae94,
            0x01b08bf24684667f3adf91fc0c8ece71e0465be21f01414ff0f35bd14b16048d,
            0x07a58a5510afcc0ff71c6eec60c10e7fb89b9bc10aaab2142480cb590127cb5e,
            0x062d9a275802c07fde597775cc9ebbf9394b097f47899e7613c64055b5c67484,
            0x069c6294edc040e4a1726a18cb7cea63994ae0166673570e98c2a48c63708a89,
            0x051e7f3f47cb6635a15831bd9b009a9fd98f84f4bb30bcc75882a0344b4fa378,
            0x00b942c16c0d3a713f2ec8aaa42afb91116e52fa0903f72ac9deedc4f30a883c,
            0x04bc0b3d4a94d8c94b2c5641483091ab85c1d02962c006c0bad2cd14879e9f7c,
            0x0642e794e0cc6afca486dd44f6b4a7b74c4e4f93db2090a37e46702c0d3ad77d,
            0x028abd4d4df5b850032025185070bc7efc5ed616061fcd88732e36279a3f0ab3,
            0x0467ba2803e9dadaa870433d18d6a0d3fb83bbcbefbc4f600ceb8a86776507f5,
            0x06d2187fe74bbab78539f6eafab33dc7f6906be0c1265a6254d867ce91c0e4ec,
            0x05ff5772659d6e9d29ebd966f50ff7096ff20b99d5c558bd11892861a26fb6f1,
            0x019da06a74748c7336bfc2e3359c6a45767fac4a2b8de7be79dde1b29ac5b6f8,
            0x0734f10ce9822b06307d77e426bdfa64d487997d951bc359a75a23e307f21138,
            0x03a9b788f9405b49e76a7d3d697b71e2fcc04d6c5f379212083cc3fdf905296e,
            0x01f785d5ef8d5db47c692f8d86a116b63dbc0f8d53052fb5bfd9ac87516e65f3,
            0x0391fbfe587e463539653caf0d1c3fe67bfafadd02c2e1cb70b4c65efc230eaf,
            0x06783171df54f4ccc7fbe58b09134952f7d339dc51525d5d84e8f9582bbb5e5a,
            0x00bb9a8cf386601b33ae96bf5be8914d503aea730e7c4e2014c98dd6febb571a,
            0x00c10da6726e2e0133f5a864da297e130e4683e0d8cc8bb32169a156c70fe466,
            0x01fe589062f32a33e8ca0c9ed8986aa7d9df7ff5dd0ffb203b1ef3ea0608bd0e,
            0x01f9d2f74ed8faba7e799ff4af40558ef92c4c1b709eb2e064a9d4a135f956d8,
            0x04b91c0adc3346d83d567b7fbc2b599645fa29d13977c71e04e73c81e4d912c7,
            0x0689301de4198c81d878057e3dcfe118cc9947950759e7c7db691e014cd49a78,
            0x064e091367792273fc7a1ec3402311868bd5d4e6442c2bb3b48cde816397c15b,
            0x014a3f4f4a302f16cbcfb36bd3d1eb7ed7533b300bcc1a70a66e0ebef6819f19,
            0x04cdb092aea7f0f7c6bc93c02bb80c9a59f12be2e56a48266883f426edd3e621,
            0x01bfab4d585ba2e707f5792a4c75e8ee37ec0a8d33f0245c58ffa7522ae51fb8,
            0x059603c8afa14b680b1861ca343224f8242e7a4743aa83d3a1b9bc4e4b8667ed,
            0x037b88644fcfb980337da893293c8385b6bdb79c5de0409253b99550bce29677,
            0x067930d3a60d4e204184ea2e15300ed0ceb06cdf38ea4d9b73ed8fa76e0eb24c,
            0x074a01446ae537e29a3029aa9c8d13f81fc780a843feef827884068b9111935d,
            0x02da015b10870c4a15b286e203c4bfface5f9e6b3633eec319c900487fab0237,
            0x0166dc6ed44c7831e76f83c58e77f6a9c698e0eb64b9f4d3957f19e7973aaccb,
            0x054616485403088d1f9aaac11d01431377efbbe3f2e3ba74cd8cedb314a508b2,
            0x068fcb73d0d68e7cbc1ae9d16e15a4a1de112e56e8171684e09ef6100e932781,
            0x063423e682ef86aa0777f08e39f44b62e262abc7d805501c3c460e90856b3c16,
            0x0039852174c414fc3218dd10913f1e1cc8374ad8e9c18e32ecb162cafb1ef401,
            0x067ab0d7d2f895e152481b1faa9803f5ec16100ddf8fe62e273c87292df12c96,
            0x0470511edb64cdcdea5ef4e37b0dfd9e185f42e8fd2328e17569681006c17089,
            0x058cd0a347484662e12b02cd02149fd45e557ff0d776ef2979829c48a7006dd5,
            0x0635547ed24b7a605d6ef491d5862552baec213361946ec3d30cbfb64f22be00,
            0x0023b071d9272722a268e944f9beb6faa2ed5190cffe5d4ceded5d022849acbf,
            0x02c22c6aedb71c6bdda853d3a5a7386cab550d199b8d15ef0f852280cc9df3af,
            0x02e9098e1e5bd3b1de17009579004bc19ca540305161cb2b1d996cd655af6d02,
            0x06e79468ec117e51bc0c656783cd57ab4287bcd86a9ab5778216bcf88472f9f8,
            0x048067a03e033328054880697dc30f2d8ddcc34dfbfd0ee7baa54948ed2f2f81,
            0x054038e44efeba65639edc1f4a8ad7bf882a3c8d24372d71a8024245ce51e6bd,
            0x013ce1582b051468b879fd44849a223c6a6bc96c5f127b84b9d6963a1f2b3435,
            0x051e00fb1ab076f87fefa6ec5ea3c78eea266093a181972fd3bf624aa1dedd6e,
            0x02d8dc6ea108a03ccc18ea219cae660ed77e94d610a07141f7b8edb34a5acd41,
            0x00fd5cc10acd637761b3606b5a6a50408ee5de5688857cc3ff00d339362d8022,
            0x03b67b46489f2b7a9ba32b9683c26767e431a5a9d2654594fc767da8771c0d02,
            0x000f4dcc32849c5bcb52bcef86a04cecfa75282b6fee943e8a496eaca91d29d1,
            0x052d0df913b11bd91912976677c811c5880aba2f76c755a8909866d4eeed32bb,
            0x00ed5c75aa4e7e6c50c2b7de7d8757c05fa2f2da30fe2d527c7fc39bbf9084a8,
            0x06e3c92b28118a9985badfac4dff4d33d666c6def8317d03bd8a9b6db932b785,
            0x06cbb9cc716631f0014837e9d26125d03bd55fb297c115f3af6e717e343917b1,
            0x04bbd24de3edadbd54066d1afa2365efa1982461194241aecc477a0c438aaebb,
            0x060f081e41fbe197fdbe2a10bbd936e8bfc6e77d1d64b6e6765dfd5d2871b886,
            0x00b69bdbce64c52124521a84e986e7777b64a1d6b5ee28f220ac08da210bf718,
            0x031dab880e29ffc338b42252f319c85bb88b03bb00287c1bf48aef3c535461e4,
            0x0311577642591cef7876634679081a8cae0157f1f41d2c9ec41ad1a05ddf0d38,
            0x05d981de6577d2a07f4a2e0260c149ce5b6ee1468244cc38cf41651c677d3407,
            0x0498b9c6d36756a6903faade0bf6a92182f6792d6dd9502817c5417df7e3f382,
            0x001202e540fdbf02bc60445bb12d266cc4dda1a1092e6fc91a8a553ce0a520a9,
            0x049cdd65f58ad506cafe54d6c3f89381e021fe04c0ef1767e482f5ea6e9d1cc9,
            0x050d7e1ae5952802d3e14c925112fc53749276e38d8dc6edd6174483c5cb8b61,
            0x04db0284f3ba7a50566cc94d57f8ee520f056c84ab97ab4dad1fef6e6525e312,
            0x072023a28af8acd7fa1f091fb6b0dead6c5961cc2190c461e1efac2b99e322b9,
            0x06ed9c00a89e21c0740a8126d9f7c1d888be474dec5bb9478e8cecb767831f5e,
            0x07c05b73ed5aafff20e1d873210478d4feac7a261c79fd0db40ab692b6a10242,
            0x04f808c812276e22c2ea67dea0718a3482c8f95549974bd1304959c763e53644,
            0x032c746da02c0480f62b9fbad5438729983bdcbe1cb9c879de20e77a12477caf,
            0x00f937a0e539f72ea8a19da93c060bc63463fcbbc5fffb39f32a0a09ccc19878,
            0x02085cd73fe857785d0592489e398d28d55b54b648a6d4e6d6a51bb53b66deb7,
            0x026e607567901559737c527624e0665db46d9e6702bce8c472fc06b6eef7b800,
            0x04fca3dd1023185255c8dcc49471c9f20efdeade9feac7edfede7d20bc2c66c6,
            0x00d33c00df0eafc6713c4a32b823cbe2ed799e9cca4c9ec2fab664634c4716fe,
            0x05deb505f702f50515dffeb53e901e7595b0eb1d35cb0eabfffdbdd6293c4e2b,
            0x06920b00b0792e7e512a8215b6a5459a9975e4e6e7fa653619ab3dce6a590949,
            0x0264be91fb2d103130cf307d7b0cd41df633eeb45f0c150ddb31bcf71b8b6e47,
            0x06fdf967862dea3c95f2ed42a1bc882565c326b98986c73b13cb2e177763df5b,
            0x065790ae1b99ea62bbeaa7e5a55112cac3572b74315a11e229f1842a37101e9f,
            0x07074cadcad0f3cb68ba4f7847e5a9cfa4b5a83391719e6fe30389cd8cd28266,
            0x01badeeed5c55812695d353a1248830e446f024db81ea1ecd773a5f19cb4b778,
            0x03ee0498550c7de70a3e35e307933520e768aa2b905c53378c6486d431c4dbdd,
            0x0773ed1723987ba95da885840f0b26ad67c546f52410f302ba5205cbc6afd9b1,
            0x04ab36d36bf6c5d24d957c74f4ae343397c4718fbd1589b92a2a7d573a6b6d15,
            0x055dc01ea87703bd2d75060aa92b8576fe87ff8956dc1f2f48832d11ab852eb6,
            0x00fa07ddf4a81b0b7342148e2a0cd7136c14906ef034dcd9917a2c58a71ca999,
            0x02154ad8f124e24f1187e55a57fb168a98a6db1a4e2cc13cde9d906d97e73d13,
            0x015f6182d4e639e993c9044e7663ae63cc6bf4058cb1794b873df6234567c2ec,
            0x04d5a1df045d83c490274d0508862d85b87efcd157bc39de83effdcc2b6f5992,
            0x07b193b753571715d0616bca5553a3000291e8b97f8f74d59412f57609aab345,
            0x0165e0f0de64fedeb1c64833927f96c32a2e7aac56514075d50f1609136bc507,
            0x00ec410a086d46d4faf08316f4edf3a1386304bb427436183a81dd717f6b4bb0,
            0x045eb712368e1883cf55844626911970a861f737f8691f8db5661a39f2cff1d7,
            0x0289157c6e03598dce9e09f83e6647320c7b4235c7d2672aa5e19e7445d374a8,
            0x03036f6054eeed02576849f19e3f163a0576e21c59f84a78f0633406c87e7d0d,
            0x02a6ecb3acfb76913987e2175bf4dd8acb38f87ed19faf1a250a13804104d906,
            0x0137f375732ecf72da06a123e5c6dec46cb6c7201e4bc6d0fd0e0697c5a00ae0,
            0x04411f2c44da5fd95522c57f0c2c28cd5aa0783b5a58b8ab27fa296976ca33a5,
            0x072a1f1ee8506e8d35651ec1163dd4cfa497f4f949db80b0c2833407a5a69c7c,
            0x032da3cba678f8fb4a287cba25ed336ea77e51860b36d96f7198010d44d131b1,
            0x034e11913057f3a2b23f07ab5841fc73968e1f9893a53ec717dd30c67620ae97,
            0x07d6b8ff05f2cb07833428a68bdfe5a98bd8022b329e6eb241384104f812500c,
            0x01e6bcb7c55dc57a6ce7f7c548c2d4e24e096519281de2d4d1f1bb361a66e5f3,
            0x0539d9f43148114cc4e8ad51dd940ec66d5748b917848d41dc54bb6e5405015b,
            0x02f4b7d1290d4d3a7532741cf4641daaf79d0062363b49d39fe8bf12b935df52,
            0x049dba799bfb2d6fd48f589dcd2b6eda8589b30d742b34ff62f3b15302abcb52,
            0x073283d9d281f4fac9d073485b4c853e9bd061b1fb9926a030249a822ae9d4b8,
            0x03b0b0353f9b0741719f25faf6ba39f7253762569b6eaaebb754346a70328c2a,
            0x01c85f421be4689709e8aba5ed7b15b0e123142826f3f6d2e1f561d3a4d21e62,
            0x06dcfca5fbd2ff39aed4f40f7fe85a059d41ce8ee3cbcd3f883d69541df8a662,
            0x002144c1edb3213e1b5972a60e53e4a145f4263d82a2fbff1fe91048d1740b56,
            0x07977f50df40da434797b069a14020a2cc2b43f5eb37159d6ce9dc0099cd60c7,
            0x0122ffcefa4adef5686f24f96f8341f09727b1bb4e128bccb34c1bffada72ed1,
            0x0687e644eac767aa627a168d4987bb83ea1e6a245473d5d7899390b926109bf9,
            0x07b72923c3af3a88c115b4cc2c48505621ce6a2c17f41486215d9d94a830ddaa,
            0x046acf10bb25e448059c86676b9e6105e1ffa06073d34ee4b2fe0633e544c898,
            0x05df00467d2f9fa1327fd0d91b04be48dcca6e21d2de31f87fb2cd2c4e8aa79f,
            0x007a87689cfff99bc5e936b6993c50034f3d0f043d0d6639c239ebf9cc12dc55,
            0x039d6692fba796d653b51a31e825238730b232ae31745dcf42698cb31c1c53a9,
            0x063d05b332f6de60b451709f60f284b4cb826b8d7396c926a6e92457fc378523,
            0x0034f9a3b10ec18c0a71aab8a2914c82b08db1e7ed88814959375e4bbb496d23,
            0x046eff959a31cf0efc46730efcfedf007155e62feeb4a7d4181cd98cc7a565ac,
            0x04ede7edd26d173564817640b0c898c4e1006a741e0ec39f7755eb7e7b912263,
            0x0680e7ae4e538978213a9421c9465bd5caeee1a1f0278512a073a146364a3ab2,
            0x062ec88150b6980b274443ddeab008d016b2bc98eca7f62a7604ba4203b22211,
            0x06facba9242e46098b3a2baeb674009490e4b68a51cf2a2d718da5f3e53e4bd4,
            0x008f0df17af9c237e61ea375d348181deb3df08908a328bf1b4d152098942ad8,
            0x05642337adb37bd7e16aa1eaed5388ccbd311eb6856d34d9a93d93faa2199cd8,
            0x05818e0382e0aa926516a839f5a888e3edb611d25f3bf1fc4c2ab540ad75ce83,
            0x013a08708351da95a52c442e70b3d52a49a41eaf5fe1cd315dc986a23f81c620,
            0x05f0fd11a8370792a4da755c95696db98776e4e2dc9c7c6e0e5caecbd886f805,
            0x011e3e814a11da066fc33be9dd961ba23a52bc39598b46f9c4350c7f9bdf7a0c,
            0x07d310f5779b4e324f96df9360a51e7b2907f4f98a667eed26b8f65f05ebb5f0,
            0x0612e30faa55d72247a434895a0ed0fa2eb61246c83067a750b4ae02c2dfe5ea,
            0x039dbfa39b30ed36443b96d0c3258d975972fefd32b5be635e0c113261ec54a2,
            0x02edbfc13f4f3ab565016a4a84d96119ae29ee9965b759de552cd8d53a5e8eba,
            0x0348f33925f89d3e61cd0c89870fa0f93c534b32002edb1f28717c9734fe2031,
            0x0610d0a103da3a09beb3767711bb614b4d67e1b7baaf746a1806a5f8dfc82da0,
            0x04060004fd703c7260183f21e5981581f16dea6939af5732f2dc4d09c494833a,
            0x046b4af45fee18431c91f1e7a9b7a3c27e21234b09c1a261f9a1c1068e6f82af,
            0x0540240ecb5c7cae5dc176a72a2b24ce7a294f4388558f9e6be868552059d2c5,
            0x03ee9e87ede64b77338ab071ed31aee87acf2b1dc583e6874aa6b558921a3569,
            0x01845aa74a62d79b489ce1492cfc64991b8ee591972f738260416e178033807c,
            0x01d68fa3405d9a53a0fc2c616f60b8efb7c0f0dfad4c0b34bb92f27d7ee5481b,
            0x00e54a0bb147c66039a090eb1a6c8e4586c7e08822cb1bf32eba0958f1979649,
            0x076684ef503a4d5540721382df52d8a40199b2a89515d43b723d188bc5fc62ec,
            0x05e8ee8a5d5927c9d33d7aeb8343c9e14592830bec55a6d44920ae1f55645c52,
            0x0573b3ec3714267b6fca9c90220447ac557a1935ff40c7b3241173e0185803d6,
            0x068d7612c3376367e14c6a804555d841e0ae77b01b0592d5e8d02540d4a7b179,
            0x07fb0c1ec08bc378b42842141eb4e74add2bf96b7a43502c8a421a8f718438b1,
            0x034913e0c6e922483198df45ea8d943ef950243381656b73cf615602236013b0,
            0x075685e2277d80bd2bc267a855fac02c5861f42d51b5fe30a2d91dd2549ae266,
            0x0695df36b98af27e73e13cde240aeadbcd5851a9c28d1ec0afef6dbb1f18949a,
            0x00ce1e0d522ddca880aa0ab42ebcd0c7626f9908b141d6fd1a39601a077193ec,
            0x0395ea0087747647c6e61a481c208ffc32825ae42239237c1cf73435d9f209c5,
            0x068907e1b43864d1c3ecffb42ad8d33a6b6f9de35a92c4d1da86b47adce56b32,
            0x00a8f1488c50dc345cdf4f1ea174460161739c862b4e95879891a64d28ee6475,
            0x011988d102c9b38e94a8e769ee2f7284c2b5ccf2b8c78459aca01002bde17217,
            0x06afc2add4e609701469b43f09c17aff47673e003e9049033db8736e4bfb9870,
            0x03e5493f343ad53eaa16f0a75c068b88679328314765c4b98106244ebf16ae63,
            0x051184cf1eafa04827278d1eba7d0f3b1d0c850b321cc25b4d5599f9792e6423,
            0x00425879e59fbc8516ab3889c0e08d3688fc003868bc7bdef3bc1ac6a230a227,
            0x077b79134b4c12b11626bb68cc09abda0f342bba8a7d715c463b56486cee1e0a,
            0x00b0853520d618aec2ed9a5d1770287c8fb5706c6fe25b4caed89f9c77dda5c1,
            0x0475c1b9b3dc34047b60a5b9e3b31e3cece3d923dfa599d9270e9a47e30fdfc3,
            0x020b86281eeb06bcf709250b2f2bb0ecb4c231e05c42ddb778465ffdb574b208,
            0x0211bb5b6f747fe660cec4533e43eb7846b98d849662bf46d968e006c791427e,
            0x0311263426cbbdf0555becd8f44f6f98d60102c87fd7259295364c96b0ed780a,
            0x05d2c44def5f566cd6e9c2685958a9e1888ac8bf688d28ebb8c7fdd8f71f109a,
            0x06a8ad4a6e27c5ac81c126639942db183a8ae8fe8d18ed494aa1630b498a437a,
            0x059f6a06b6884600a386f450d78ddebcc60677c03026b776c9cf0d673ddc7de4,
            0x0332bee49ef58d9242914bb852fd6e20199f615122db91ba7a94fad9fab757c6,
            0x02c253606691d11a2d71cb605454e49d4a7661252c57cd12559eef4dd5825dc8,
            0x06ff2a5e4e74cec887607a7e8a5c99cb317200145f001afe5708321e068d084d,
            0x0696e5400044d72d906909f40a87921995e292e028aadc640449e69504b6c7b1,
            0x03e6462825b78c5096ff9c31ea215fa3f3233ad31f17e619c5eabeed80ea63d2,
            0x053a9b4da149f2af0b5f3030688457504c6437e959a175240842d4c1580881e6,
            0x008b49c22858960dcaaefca8e64cf35c05369139947529dcf6d91898c02687dd,
            0x01b863d1134655e1b28013b2537d08629ca13dc3ecb339cecafd5f6b9775cbd0,
            0x00d8025225245bfb0348ceeed9cb1f9959b4a9beb9b62df42da80aa8230e1675,
            0x05db846fb23cb5f2a42fdfc2542938939492062942daf4be6ece32857947e421,
            0x054e982d1e872bf8b57307f122f4f25a3d73e755c137a241792853be742ef8f4,
            0x0580962010f7d96cbffccb7b7f0f7e1e97db6574a6dbe4666d690404c45bbaef,
            0x02dd92173738e1412aed47d1182cfd603036a0ec7e6163212494cfda23b931ff,
            0x0670bdab529679ea9b4c28aa25ac1934eb04e90ec5a046ee6096e3caa3d795a4,
            0x0316b9786e8bcf60c1a15153a6f8c1aa61b0f67098cb0919f1eb826bbe6d9afd,
            0x01dec66571265c0b76372aa4da0de677c249d0bbc242c4c6a31bbab29353c563,
            0x051e7794513a2a69360049cfcd8d0b9b14e0e3a6c8743952e0645fad43f2353f,
            0x052164afac54e6837b67da91f03d4bfee7173e8d7410f0c89fc281a5324cadc5,
            0x046863cb683c98e2234ad4f0eff911cb43668b039138ac5080aae49b15266dd5,
            0x03eb47b29cd8e761e9b825517a00984943d474e06dea00877f04628ff78d97f6,
            0x04685d3a93fad2b554938792f2dfd2f40ac2c685b97480c89a6f692f79a62aeb,
            0x07b37eafdc848369817f3d01868af6add785d7bcf8aaaf3daa12334dd85c8b46,
            0x0542bd5e1001bebc49927154e3c6e8497c2b9a4960532bcb350b44ec1f92602f,
            0x01505c75a8fd8a9ebf6e31b208b9cd1037af99ce385b64ed775d2b8856b88481,
            0x03cd32000c8ac932c9f1beb7c34a82ae8fb335f1b411e8bc138cfad7d3e4b0c0,
            0x0494b63c8f4e9626b32c3097aa983ac50a24badf8268987c528537f33b05ab8c,
            0x07b4d7cdf9f802f4758657c182d36b004334823833f19b57cf0ac5b48a477819,
            0x00317a777a7c92b16d3ce1a01ce2a1ecd4cc672c2e96b097e74633940cd8d40c,
            0x03faa9dcef032e9300c033efa6dd343d27b45ef0861dff22d24b5ba50f02e142,
            0x064271e31fc27fa5b3ba7b0758a9fdbb8a1d6df979d1d4e3a52bc3b768c4e2f0,
            0x021ef268f0277652dd3200e7272bbdf7d87b20e2b7047d233c95f855c80dc6b7,
            0x02d2e3b125a73c754d2b47242e49d771dbdf693eb6d78cb137fec4edfc08a3d1,
            0x075685e2277d80bd2bc267a855fac02c5861f42d51b5fe30a2d91dd2549ae266,
            0x07005457965c666d8e47e9905846a3d81b72c77710541e9ac5e4a8aac1b8b46b,
            0x0003a5bdba5dd11c0d36b955a4c42f5149458a126d8c4cb75af66161f4d36cba,
            0x07d1d24f104f168676d585ddd98338ca2e326c6cbc66bb3c00a650abc6595b39,
            0x009d6a0eb970a71ac106ba457ceea8438f1428376cf80c3408b101d73e3de461,
            0x048c55c44f34f0f209badcf8401980addcdb0762bb08aad4e82bdbde0434e09e,
            0x00b23a6271befab759561559787f23bbaeafa875f3ee7e8bab10aadb1b58b92f,
            0x01ea64591d9b9ee54ccca33d0353a94254bfd4344f0c8a2e177c9aee9d891dd6,
            0x05cb01935d0d364998c04e0b40659051d72707ff2b98fccffb6238e97ca03c48,
            0x02d34817fa3cb1482b920637f5544aaf3109313fe26fbcb5b6569f29eb66e1d3,
            0x003fd41ac96d11db5de72a722bcd2a17354376e4a50e040e5ca323700340f020,
            0x06cc99d0357b273af6711ec5abc3985b730cc1e3d26a653561844ea46cc2e7d3,
            0x00e1a3bbae6a589a3a7772914650fd65b30f2250344b4c085a6352ce3f502cd9,
            0x065b0b7b5e8ab788bac19485837086b39e46192fe66e2aad448adbc140a1b6e4,
            0x022dc5445399a15fdec35c4e817d646669e8b83829dd86d986a2cf00244a5b8d,
            0x00bcc4a1e787d8beb0ecdefae59eb12e9b60582de787632e4f286bc7f5c8c5e3,
            0x005bbc2ce5c32ebe49bb422a120113ace876868d8a6eb1a2e6358e9203934acc,
            0x016c42eb18d01070d3787e4da0de0fca8fbf030af9fe20f8a6730189be8ab496,
            0x006a1772f6c2f557da5aab45e20c9bffef22293bc7ac2d812e7d09a3c1a7b0c0,
            0x048cce9c30ef747ba69b843515691862c4a521ebd4e0c1c98e1de6013f8e1325,
            0x05b30d9a2a7da3fa06a27ef162b81be72c00a9cdf0be76aef44e0eac194abfb7,
            0x00eb60ea7d30d1f7e029098c6ff719ab0fc3da38eb33ea5115c7070f101529b5,
            0x06f0001a708d6c72848c44347e44ac9fd69f1618f86ce187a1a00c0539702d9f,
            0x0106521ac7679a499a67c18f323aeadb2379ca5978e4ed4bab6b1d9f53d64985,
            0x049e75423ac7a7e6ae3c98444315602547dfeac6a0ea62edb4fd4f77eb6c260c,
            0x02919f85aeaaddf779237838717e6dab7f79024253e7ed816b161f5026f2ffe9,
            0x01001820797d465ba46c42becfd8287f9e851d347500d05286b9b531d8e3da89,
            0x0000586d3ac488e56f68a2414df028ddb2c95ddc4394080d65c939319cfa0705,
            0x04c2ead15469ffc866672708146fd4ed8c1332bc978a4a06d9701df263ce1b18,
            0x03047bbf6dcaa69edb1cd0f4f8532e9ceab0b8b0dff60b5be4fba2758fcd8958,
            0x0361e4cdbb310b404000a45397c7d881201d4e942423b1ff17aa80a40fab4400,
            0x058a2c295b0bb987626b9a3b7c0107349e330354fb7cd43bfc6cd4261f754c75,
            0x016af7a9c7b1bcb8817376763c8a09c8b60259586c0afa016d11aa8e1863ca35,
            0x07e52f39d76b2972aa767566d88c35f756cc5898acafa3dd256912a0ec0d4c08,
            0x051e838fcc76f4f5b29e678a9b86171143a20b5d68e5e9636b323a2f24c8b0ab,
            0x02b07022f7d29a57d8ef7fa6a0c7a6574d72444a01273248807ba30e779477f7,
            0x075de9fc12355cabbdcf1c3f8565327fbe4b380184aa69b77b42b88a8232272c,
            0x05f50fe4fdb0a8d984fa348dedb571396bacd9ff1ee9077f03d587a3068de21b,
            0x0791d43d2b5a470575c8e2888ad39e5998ac75cac9aa8b48259a7eac09040bca,
            0x079b212a1abea86410da709ea8c542cb9243c83774cfa038472f8f7398f2e4e8,
            0x01cb50b16b181a978297bfa07351d392b80e627ced1d50136a8c1441a8d64e65,
            0x03665d095903bfa61b3b8ea61bdce9331ae3211c4a4add9a98395379bd0ad120,
            0x05ea0b96ac13c6a301294d1df33b5e56f1c30b0073dfff9acb9594971a28c415,
            0x07b5ac54434a4ed9ac00e45d7c9f3752d444189ada630b75347ce136461c653a,
            0x06a6b95063e0cfb265b21be9d84dd366e9877580f04bb26a41764f42f17f1867,
            0x0411d217f3ef0a0f64d5efb25d0efba87a2cd8500b7fe88e2a545610578c32d3,
            0x048ff5c00c0d451c36737c1a37cf626042138a92810a5a9d6e7c10c5404903e9,
            0x03657044c8e7ca627b3146d27e3740a30816c6ed41992e115b83a0a244339c48,
            0x00f6d37000e4264e6b4e6339b8ab3566dcb3d7297966d246180599a3901f7fb8,
            0x068f4b6006f6152e70d815087244eb418c08773c23ad8f6e6d74260e878ff3fa,
            0x07bf63bcec2a1794734587a39ecbafea33676667342d52499841d300818ee549,
            0x045613a135f93a38a1b2022924284a19f292e655eeb395b59866d83586be3855,
            0x023f50cb9943883457ecd6621ecb21f79878d1e215073588c070e90e8f06e334,
            0x054ce3b303a2bcdb3fdf8b267bcec634c2ffad03ca7095fb6cd5e83eb59cf38e,
        ]
    }

    fn bump(payload: Array<felt252>, index: u32) -> Array<felt252> {
        let mut out: Array<felt252> = array![];
        let mut i: u32 = 0;
        while i < payload.len() {
            if i == index {
                out.append(*payload.at(i) + 1);
            } else {
                out.append(*payload.at(i));
            }
            i += 1;
        }
        out
    }

    #[test]
    fn transcript_replay_matches_host_challenges() {
        // host-derived x y z e q (tail of bg_shuffle.txt; λ was removed
        // with the batching revert — first five challenges unchanged)
        let expected: Span<felt252> = array![0x02d3d2cb09339304dfdc621064481e9a9c17d1e4708f8b1f8954a698cd9ab4c7, 0x06ecd7ae99d3ce7219fc7682625b07b465d302add9c9a3562c91979fd1e945f2, 0x05936465ce68b79893dc49751573b2fff72b110b39f90dd98201eb49f2ee8680, 0x0371366c44461181992f5d3a6bcf705158fc9d2553aa1e79c918844e93f1250b, 0x07488bbb097f416448d8e2bdc578972d99b36bddbabb170546b7f0840596166c].span();
        let ch = bg_replay_challenges(bg_bucket().span()).unwrap();
        let vals: Array<u256> = array![ch.x, ch.y, ch.z, ch.e, ch.q];
        let mut i: u32 = 0;
        while i < 5 {
            let w_u: u256 = (*expected.at(i)).into();
            assert!(*vals.at(i) == w_u, "challenge {} mismatch", i);
            i += 1;
        }
    }

    #[test]
    fn honest_bg_shuffle_accepts() {
        assert!(verify_bg_shuffle(bg_bucket().span()), "honest BG bucket");
    }

    #[test]
    fn tampered_beta_rejected() {
        // beta is response word (8n+25) + n + 1 = 494
        let p = bump(bg_bucket(), 494);
        assert!(!verify_bg_shuffle(p.span()), "bumped beta must fail");
    }

    #[test]
    fn tampered_response_word_rejected() {
        // bump alpha_response[0] (response word 0, bucket word 8n+25 = 441)
        let p = bump(bg_bucket(), 441);
        assert!(!verify_bg_shuffle(p.span()));
    }

    #[test]
    fn swapped_outputs_rejected() {
        // swap output ct0 <-> ct1 (bucket words 209..213 <-> 213..217)
        let src = bg_bucket();
        let mut r: Array<felt252> = array![];
        let mut i: u32 = 0;
        while i < src.len() {
            let idx = if i >= 209 && i < 213 {
                i + 4 // ct0 word <- ct1 word
            } else if i >= 213 && i < 217 {
                i - 4 // ct1 word <- ct0 word
            } else {
                i
            };
            r.append(*src.at(idx));
            i += 1;
        }
        assert!(!verify_bg_shuffle(r.span()), "swapped output cts must fail");
    }

    #[test]
    fn wrong_deck_size_rejected() {
        let p = bump(bg_bucket(), 0); // deck word 52 -> 53
        assert!(!verify_bg_shuffle(p.span()));
    }
}
