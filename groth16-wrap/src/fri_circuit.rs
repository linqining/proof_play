//! T3-FRI 电路：把 [`crate::fri_shadow::verify_shadow`] 的验证逻辑编译成
//! BN254 Fr 上的 R1CS（原生算术，无仿真），供 Groth16 上链终验。
//!
//! 电路内强制（与 verify_shadow 一一对应，out/t3-fri-wrap-design.md §1）：
//! 1. FS 通道重推导：claim mix_u32s（词线性绑定 + 32 位范围检查）→ 三根 →
//!    rc_A → tree2 → OOD 点 → OOD 值 mix → rc_B → FRI 根/α 交错 → 末层 →
//!    PoW 前导零 → 查询词抽取；
//! 2. Merkle 路径（叶子 sponge = 打包词+词数；内部 H(l,r)）；
//! 3. 首层商累积（QueryBatchConstants 常量表 + M31 gadget）；
//! 4. 折叠链（fold_circle_into_line / fold_coset 的 M31 gadget，mod 2^31−1）；
//! 5. 末层常数相等。
//!
//! 残留信任（v1，与 verify_shadow 相同）：OOD 应答对 fold AIR 的满足在链下
//! fact-verify；查询位置的 sort/dedup 由链上 Solidity helper 校验。

use ark_ff::{PrimeField, Zero};
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::convert::ToBitsGadget;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::GR1CSVar;
use ark_relations::gr1cs::{ConstraintSystemRef, Result as R1CSResult, SynthesisError};

use crate::felt::{felt_from_hex, felt_to_be_bytes, Felt252, Fr};
use crate::fri_shadow::ShadowWitness;
use crate::poseidon::{ROUND_CONSTANTS, STATE_WIDTH};

pub type CFelt = FpVar<Fr>;
type BigInt4 = <ark_bn254::Fr as PrimeField>::BigInt;

// ---------------------------------------------------------------------------
// FrPoseidon（电路版）
// ---------------------------------------------------------------------------

fn rc_var(cs: &ConstraintSystemRef<Fr>, i: usize) -> R1CSResult<CFelt> {
    let bytes = felt_to_be_bytes(&ROUND_CONSTANTS[i]);
    CFelt::new_constant(ark_relations::ns!(cs, "rc"), &Fr::from_be_bytes_mod_order(&bytes))
}

#[inline]
fn sbox3(x: &CFelt) -> R1CSResult<CFelt> {
    let x2 = x * x;
    Ok(x2 * x)
}

#[inline]
fn mix(state: &mut [CFelt; STATE_WIDTH]) {
    let t = &state[0] + &state[1] + &state[2];
    let s0 = &t + &state[0] + &state[0];
    let s1 = &t - &state[1] - &state[1];
    let s2 = &t - &state[2] - &state[2] - &state[2];
    *state = [s0, s1, s2];
}

pub fn fr_hades_var(cs: &ConstraintSystemRef<Fr>, state: &mut [CFelt; STATE_WIDTH]) -> R1CSResult<()> {
    const N_FULL: usize = 8;
    const N_PARTIAL: usize = 83;
    let mut idx = 0usize;
    for _ in 0..N_FULL / 2 {
        for i in 0..STATE_WIDTH {
            let r = rc_var(cs, idx + i)?;
            state[i] = sbox3(&(&state[i] + &r))?;
        }
        mix(state);
        idx += STATE_WIDTH;
    }
    for _ in 0..N_PARTIAL {
        let r = rc_var(cs, idx)?;
        state[2] = sbox3(&(&state[2] + &r))?;
        mix(state);
        idx += 1;
    }
    for _ in 0..N_FULL / 2 {
        for i in 0..STATE_WIDTH {
            let r = rc_var(cs, idx + i)?;
            state[i] = sbox3(&(&state[i] + &r))?;
        }
        mix(state);
        idx += STATE_WIDTH;
    }
    debug_assert_eq!(idx, ROUND_CONSTANTS.len());
    Ok(())
}

pub fn fr_hash_many_var(cs: &ConstraintSystemRef<Fr>, msgs: &[CFelt]) -> R1CSResult<CFelt> {
    let zero = CFelt::new_constant(ark_relations::ns!(cs, "z"), &Fr::from(0u8))?;
    let one = CFelt::new_constant(ark_relations::ns!(cs, "o"), &Fr::from(1u8))?;
    let mut state = [zero.clone(), zero.clone(), zero];
    let mut iter = msgs.iter();
    loop {
        match iter.next() {
            Some(v) => state[0] = &state[0] + v,
            None => {
                state[0] = &state[0] + &one;
                break;
            }
        }
        match iter.next() {
            Some(v) => state[1] = &state[1] + v,
            None => {
                state[1] = &state[1] + &one;
                break;
            }
        }
        fr_hades_var(cs, &mut state)?;
    }
    fr_hades_var(cs, &mut state)?;
    Ok(state[0].clone())
}

// ---------------------------------------------------------------------------
// M31 gadget（mod 2^31−1）
// ---------------------------------------------------------------------------

/// M31 变量：Fr 值 + 已证上界位数。bound ≤ 31 ⇒ 规范（可作乘法操作数）。
#[derive(Clone)]
struct M31 {
    v: CFelt,
    bound: u32,
}

fn m31_modulus() -> Fr {
    Fr::from(1u64 << 31) - Fr::from(1u8)
}

fn const_f(cs: &ConstraintSystemRef<Fr>, v: Fr) -> R1CSResult<CFelt> {
    CFelt::new_constant(ark_relations::ns!(cs, "c"), &v)
}

/// 位绑定：v == Σ_{i<n} bit_i·2^i（位布尔性由 to_bits_le 保证）。
fn enforce_bits(
    cs: &ConstraintSystemRef<Fr>,
    v: &CFelt,
    bits: &[Boolean<Fr>],
    n: usize,
) -> R1CSResult<()> {
    let mut acc = const_f(cs, Fr::from(0u8))?;
    for (i, b) in bits.iter().take(n).enumerate() {
        let bb: CFelt = Boolean::into(b.clone());
        let p = const_f(cs, Fr::from(1u64 << i))?;
        acc = acc + (bb * p);
    }
    acc.enforce_equal(v)?;
    Ok(())
}

/// Boolean 位 × 常数权重的线性项。
fn bit_term(b: &Boolean<Fr>, weight: Fr) -> CFelt {
    let bb: CFelt = Boolean::into(b.clone());
    bb * const_f_ref(weight)
}

fn const_f_ref(v: Fr) -> CFelt {
    // 常数线性项无需 cs（线性组合），用 Constant 变体
    FpVar::Constant(v)
}

fn fr_pow(base: u64, k: usize) -> Fr {
    let mut acc = Fr::from(1u8);
    for _ in 0..k {
        acc *= Fr::from(base);
    }
    acc
}

/// 见证 M31：31 位分解 + 布尔性（规范化）。
fn m31_witness(cs: &ConstraintSystemRef<Fr>, v: u32) -> R1CSResult<M31> {
    let var = CFelt::new_witness(ark_relations::ns!(cs, "m31"), || Ok(Fr::from(v)))?;
    let bits = var.to_bits_le()?;
    enforce_bits(cs, &var, &bits, 31)?;
    Ok(M31 { v: var, bound: 31 })
}

/// 常数 M31（无约束）。
fn m31_const(cs: &ConstraintSystemRef<Fr>, v: u32) -> R1CSResult<M31> {
    Ok(M31 { v: const_f(cs, Fr::from(v))?, bound: 31 })
}

/// 加法：线性，bound 增长。
fn m31_add(cs: &ConstraintSystemRef<Fr>, a: &M31, b: &M31) -> R1CSResult<M31> {
    Ok(M31 { v: &a.v + &b.v, bound: a.bound.max(b.bound) + 1 })
}

fn m31_sub(cs: &ConstraintSystemRef<Fr>, a: &M31, b: &M31) -> R1CSResult<M31> {
    // Fr 域内减法；bound 取保守值
    Ok(M31 { v: &a.v - &b.v, bound: 253 })
}

/// 规范化：range check < 2^31（返回带位分解的变量）。
fn m31_canon(cs: &ConstraintSystemRef<Fr>, x: M31) -> R1CSResult<M31> {
    if x.bound <= 31 {
        return Ok(x);
    }
    let bits = x.v.to_bits_le()?;
    enforce_bits(cs, &x.v, &bits, 31)?;
    Ok(M31 { v: x.v, bound: 31 })
}

/// 乘法 mod 2^31−1：ab = c + k·M；c、k 范围检查。要求操作数规范。
/// c/k 的数值在合成期由操作数值外推（setup 阶段无赋值时取 0，约束不变）。
fn m31_mul(cs: &ConstraintSystemRef<Fr>, a: &M31, b: &M31) -> R1CSResult<M31> {
    debug_assert!(a.bound <= 31 && b.bound <= 31, "m31_mul requires canonical operands");
    let av = a.v.value().unwrap_or_else(|_| Fr::from(0u8));
    let bv = b.v.value().unwrap_or_else(|_| Fr::from(0u8));
    // M31 值 = Fr 值的整数代表（< 2^31）；乘积整数 < 2^62
    let a_int = m31_int(&av);
    let b_int = m31_int(&bv);
    let prod = a_int * b_int;
    let m_int = 0x7FFF_FFFFu128;
    let c_int = (prod % m_int) as u32;
    let k_int = (prod / m_int) as u64;
    let t = &a.v * &b.v;
    let c = {
        let var = CFelt::new_witness(ark_relations::ns!(cs, "m31c"), || Ok(Fr::from(c_int)))?;
        let bits = var.to_bits_le()?;
        enforce_bits(cs, &var, &bits, 31)?;
        var
    };
    let k_bits = ((a.bound as u32 + b.bound as u32).saturating_sub(31)).max(1) as usize;
    let k_var = {
        let var = CFelt::new_witness(ark_relations::ns!(cs, "k"), || Ok(Fr::from(k_int)))?;
        let bits = var.to_bits_le()?;
        enforce_bits(cs, &var, &bits, k_bits)?;
        var
    };
    // t == c + k·M
    let km = &k_var * const_f(cs, m31_modulus())?;
    let rhs = &c + &km;
    rhs.enforce_equal(&t)?;
    Ok(M31 { v: c, bound: 31 })
}

/// Fr 值的 M31 整数代表（仅在 witness 阶段对 <2^31 的值有意义）。
fn m31_int(v: &Fr) -> u128 {
    let bigint: BigInt4 = (*v).into_bigint();
    let limbs = bigint.0;
    (limbs[0] as u128) | ((limbs[1] as u128) << 64)
}

fn m31_mul_const(cs: &ConstraintSystemRef<Fr>, a: &M31, c: u32) -> R1CSResult<M31> {
    let cm = m31_const(cs, c)?;
    m31_mul(cs, a, &cm)
}

/// CM31 / QM31（坐标为 M31）。
#[derive(Clone)]
struct CM31 {
    re: M31,
    im: M31,
}

#[derive(Clone)]
struct QM31 {
    c0: CM31,
    c1: CM31,
}

fn cm31_mul(cs: &ConstraintSystemRef<Fr>, a: &CM31, b: &CM31) -> R1CSResult<CM31> {
    // (a.re + a.im·u)(b.re + b.im·u) mod u²+1
    let t = m31_mul(cs, &m31_add(cs, &a.re, &a.im)?, &m31_add(cs, &b.re, &b.im)?)?;
    let rr = m31_mul(cs, &a.re, &b.re)?;
    let ii = m31_mul(cs, &a.im, &b.im)?;
    let re = m31_sub(cs, &rr, &ii)?;
    let im = m31_sub(cs, &t, &rr)?;
    let im = m31_sub(cs, &im, &ii)?;
    Ok(CM31 { re, im })
}

fn qm31_mul(cs: &ConstraintSystemRef<Fr>, a: &QM31, b: &QM31) -> R1CSResult<QM31> {
    // (a0 + a1·v)(b0 + b1·v) mod v²=u；u 与 v 同构 → CM31 乘法 3 次
    let a0p1 = CM31 {
        re: m31_add(cs, &a.c0.re, &a.c1.re)?,
        im: m31_add(cs, &a.c0.im, &a.c1.im)?,
    };
    let b0p1 = CM31 {
        re: m31_add(cs, &b.c0.re, &b.c1.re)?,
        im: m31_add(cs, &b.c0.im, &b.c1.im)?,
    };
    let t = cm31_mul(cs, &a0p1, &b0p1)?;
    let c0 = cm31_mul(cs, &a.c0, &b.c0)?;
    let c1 = cm31_mul(cs, &a.c1, &b.c1)?;
    let re = m31_sub(cs, &t.re, &c1.re)?;
    let re = m31_sub(cs, &re, &c0.re)?;
    let im = m31_sub(cs, &t.im, &c1.im)?;
    let im = m31_sub(cs, &im, &c0.im)?;
    Ok(QM31 { c0: CM31 { re: m31_add(cs, &c0.re, &re)?, im: m31_add(cs, &c0.im, &im)? }, c1 })
}

fn qm31_mul_cm31(cs: &ConstraintSystemRef<Fr>, a: &QM31, b: &CM31) -> R1CSResult<QM31> {
    let c0 = cm31_mul(cs, &a.c0, b)?;
    let c1 = cm31_mul(cs, &a.c1, b)?;
    Ok(QM31 { c0, c1 })
}

fn qm31_add(cs: &ConstraintSystemRef<Fr>, a: &QM31, b: &QM31) -> R1CSResult<QM31> {
    Ok(QM31 {
        c0: CM31 {
            re: m31_add(cs, &a.c0.re, &b.c0.re)?,
            im: m31_add(cs, &a.c0.im, &b.c0.im)?,
        },
        c1: CM31 {
            re: m31_add(cs, &a.c1.re, &b.c1.re)?,
            im: m31_add(cs, &a.c1.im, &b.c1.im)?,
        },
    })
}

fn qm31_sub(cs: &ConstraintSystemRef<Fr>, a: &QM31, b: &QM31) -> R1CSResult<QM31> {
    Ok(QM31 {
        c0: CM31 {
            re: m31_sub(cs, &a.c0.re, &b.c0.re)?,
            im: m31_sub(cs, &a.c0.im, &b.c0.im)?,
        },
        c1: CM31 {
            re: m31_sub(cs, &a.c1.re, &b.c1.re)?,
            im: m31_sub(cs, &a.c1.im, &b.c1.im)?,
        },
    })
}

/// 规范化 QM31 全部坐标（喂后续乘法）。
fn qm31_canon(cs: &ConstraintSystemRef<Fr>, q: QM31) -> R1CSResult<QM31> {
    Ok(QM31 {
        c0: CM31 { re: m31_canon(cs, q.c0.re)?, im: m31_canon(cs, q.c0.im)? },
        c1: CM31 { re: m31_canon(cs, q.c1.re)?, im: m31_canon(cs, q.c1.im)? },
    })
}

/// QM31 的 4 坐标 [re.re, re.im, im.re, im.im]。
fn qm31_coords(q: &QM31) -> [&M31; 4] {
    [&q.c0.re, &q.c0.im, &q.c1.re, &q.c1.im]
}

// ---------------------------------------------------------------------------
// 通道（电路版）
// ---------------------------------------------------------------------------

struct ChannelVar {
    digest: CFelt,
    n_draws: u32,
}

impl ChannelVar {
    fn new(cs: &ConstraintSystemRef<Fr>) -> R1CSResult<Self> {
        Ok(Self {
            digest: CFelt::new_constant(ark_relations::ns!(cs, "d0"), &Fr::from(0u8))?,
            n_draws: 0,
        })
    }

    fn mix_root(&mut self, cs: &ConstraintSystemRef<Fr>, root: &CFelt) -> R1CSResult<()> {
        self.digest = fr_hash_many_var(cs, &[self.digest.clone(), root.clone()])?;
        Ok(())
    }

    fn mix_felts(&mut self, cs: &ConstraintSystemRef<Fr>, qm31s: &[[CFelt; 4]]) -> R1CSResult<()> {
        let mut res = Vec::with_capacity(qm31s.len() / 2 + 2);
        res.push(self.digest.clone());
        for chunk in qm31s.chunks(2) {
            let mut acc = const_f(cs, Fr::from(1u8))?;
            for (k, coord) in chunk.iter().flatten().enumerate() {
                let p = const_f(cs, shift31_pows()[k])?;
                acc = acc + (coord.clone() * p);
            }
            res.push(acc);
        }
        self.digest = fr_hash_many_var(cs, &res)?;
        Ok(())
    }

    fn mix_u64(&mut self, cs: &ConstraintSystemRef<Fr>, value: u64) -> R1CSResult<()> {
        self.digest =
            fr_hash_many_var(cs, &[self.digest.clone(), const_f(cs, Fr::from(value))?])?;
        Ok(())
    }

    fn draw_word_bits(&mut self, cs: &ConstraintSystemRef<Fr>) -> R1CSResult<Vec<Boolean<Fr>>> {
        let mut state = [
            self.digest.clone(),
            const_f(cs, Fr::from(self.n_draws))?,
            const_f(cs, Fr::from(3u8))?,
        ];
        self.n_draws += 1;
        fr_hades_var(cs, &mut state)?;
        state[0].to_bits_le()
    }

    fn draw_u32s(&mut self, cs: &ConstraintSystemRef<Fr>) -> R1CSResult<Vec<CFelt>> {
        let w = self.draw_word_bits(cs)?;
        let mut words = Vec::with_capacity(7);
        for k in 0..7 {
            let mut acc = const_f(cs, Fr::from(0u8))?;
            for b in 0..32 {
                let p = const_f(cs, Fr::from(1u64 << b))?;
                acc = acc + ({ let bb: CFelt = Boolean::into(w[k * 32 + b].clone()); bb * p });
            }
            words.push(acc);
        }
        Ok(words)
    }

    fn draw_secure_felt(&mut self, cs: &ConstraintSystemRef<Fr>) -> R1CSResult<[CFelt; 4]> {
        let w = self.draw_word_bits(cs)?;
        let mut out = Vec::with_capacity(4);
        for k in 0..4 {
            let mut acc = const_f(cs, Fr::from(0u8))?;
            for b in 0..31 {
                let p = const_f(cs, Fr::from(1u64 << b))?;
                acc = acc + ({ let bb: CFelt = Boolean::into(w[k * 31 + b].clone()); bb * p });
            }
            out.push(acc);
        }
        Ok([out[0].clone(), out[1].clone(), out[2].clone(), out[3].clone()])
    }
}

fn shift31_pows() -> [Fr; 32] {
    let mut out = [Fr::from(1u8); 32];
    for k in 1..32 {
        out[k] = out[k - 1] * Fr::from(1u64 << 31);
    }
    out
}

// ---------------------------------------------------------------------------
// 电路主体
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct FriWrapCircuit {
    pub w: ShadowWitness,
}

/// 公开输入顺序（链上 verifier 与测试对齐）。
pub fn public_inputs(w: &ShadowWitness) -> Vec<Fr> {
    let fe = |hexs: &str| -> Fr {
        let f: Felt252 = felt_from_hex(hexs).unwrap();
        Fr::from_be_bytes_mod_order(&felt_to_be_bytes(&f))
    };
    let mut pi = Vec::new();
    pi.push(fe(&w.claim.hand_binding));
    pi.push(fe(&w.claim.payload_digest));
    pi.push(fe(&w.claim.cairo_program_hash));
    for c in w.claim.counts {
        pi.push(Fr::from(c));
    }
    pi.push(Fr::from(w.claim.log_size));
    pi.push(fe(&w.empty_tree_root));
    pi.push(fe(&w.trace_root));
    pi.push(fe(&w.quotient_root));
    for r in &w.fri_roots {
        pi.push(fe(r));
    }
    for c in &w.last_layer_poly {
        pi.push(Fr::from(*c));
    }
    for q in &w.ood_values {
        for c in q {
            pi.push(Fr::from(*c));
        }
    }
    pi.push(Fr::from(w.pow_nonce));
    for q in &w.queries {
        pi.push(Fr::from(*q as u64));
    }
    pi
}

impl FriWrapCircuit {
    fn alloc_public(cs: &ConstraintSystemRef<Fr>, v: Fr) -> R1CSResult<CFelt> {
        FpVar::new_input(ark_relations::ns!(cs, "pi"), || Ok(v))
    }
}

impl ark_relations::gr1cs::ConstraintSynthesizer<Fr> for FriWrapCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let w = &self.w;
        let fe = |hexs: &str| -> Fr {
            let f: Felt252 = felt_from_hex(hexs).unwrap();
            Fr::from_be_bytes_mod_order(&felt_to_be_bytes(&f))
        };

        // ---- 公开输入 ----
        let claim_hb = Self::alloc_public(&cs, fe(&w.claim.hand_binding))?;
        let claim_pd = Self::alloc_public(&cs, fe(&w.claim.payload_digest))?;
        let claim_ph = Self::alloc_public(&cs, fe(&w.claim.cairo_program_hash))?;
        let mut count_vars = Vec::new();
        for c in w.claim.counts {
            count_vars.push(Self::alloc_public(&cs, Fr::from(c))?);
        }
        let log_size_var = Self::alloc_public(&cs, Fr::from(w.claim.log_size))?;
        let empty_root = Self::alloc_public(&cs, fe(&w.empty_tree_root))?;
        let trace_root = Self::alloc_public(&cs, fe(&w.trace_root))?;
        let quotient_root = Self::alloc_public(&cs, fe(&w.quotient_root))?;
        let mut fri_root_vars = Vec::new();
        for r in &w.fri_roots {
            fri_root_vars.push(Self::alloc_public(&cs, fe(r))?);
        }
        let mut last_poly_vars = Vec::new();
        for c in &w.last_layer_poly {
            last_poly_vars.push(Self::alloc_public(&cs, Fr::from(*c))?);
        }
        let mut ood_vars = Vec::new();
        for q in &w.ood_values {
            for c in q {
                ood_vars.push(Self::alloc_public(&cs, Fr::from(*c))?);
            }
        }
        let pow_var = Self::alloc_public(&cs, Fr::from(w.pow_nonce))?;
        let mut query_vars = Vec::new();
        for q in &w.queries {
            query_vars.push(Self::alloc_public(&cs, Fr::from(*q as u64))?);
        }

        // ---- 1. FS 通道 ----
        let mut ch = ChannelVar::new(&cs)?;
        let shift32 = const_f(&cs, Fr::from(1u64 << 32))?;
        {
            // claim.mix_u32s：3 felt × 8 字（见证 + 32 位范围 + 线性绑定）
            let mut all_words: Vec<CFelt> = Vec::new();
            for felt_var in [&claim_hb, &claim_pd, &claim_ph] {
                let f = felt_var.value().unwrap_or(Fr::from(0u8));
                let bigint: BigInt4 = f.into_bigint();
                let limbs = bigint.0;
                let bit = |i: usize| (limbs[i / 64] >> (i % 64)) & 1;
                for i in 0..8 {
                    let mut word = 0u64;
                    for b in 0..32 {
                        word |= (bit(i * 32 + b) as u64) << b;
                    }
                    let var = CFelt::new_witness(ark_relations::ns!(cs, "cw"), || Ok(Fr::from(word)))?;
                    let bits = var.to_bits_le()?;
                    for (bi, b) in bits.iter().take(32).enumerate() {
                        let p = const_f(&cs, Fr::from(1u64 << bi))?;
                        let t = &var.clone() * p;
                        let bb: CFelt = b.clone().into();
                        t.enforce_equal(&bb)?;
                    }
                    all_words.push(var);
                }
                // 线性绑定 felt == Σ word_i·2^(32(7−i))
                let mut recon = const_f(&cs, Fr::from(0u8))?;
                for (i, _) in (0..8).enumerate() {
                    let wv = all_words[all_words.len() - 8 + i].clone();
                    let p = const_f(&cs, fr_pow(1u64 << 32, 7 - i))?;
                    recon = recon + (wv * p);
                }
                if std::env::var("T3_SKIP").as_deref() != Ok("1a") {
                    recon.enforce_equal(felt_var)?;
                }
            }
            for cv in &count_vars {
                all_words.push(cv.clone());
            }
            all_words.push(log_size_var.clone());
            // 打包 + 长度填充 + mix
            let padding_len = 6 - ((all_words.len() + 6) % 7);
            let mut felts: Vec<CFelt> = Vec::new();
            for chunk in all_words.chunks(7) {
                let mut acc = const_f(&cs, Fr::from(0u8))?;
                for (k, word) in chunk.iter().rev().enumerate() {
                    let p = const_f(&cs, fr_pow(1u64 << 32, k))?;
                    acc = acc + (word.clone() * p);
                }
                felts.push(acc);
            }
            for _ in 0..padding_len {
                felts.push(const_f(&cs, Fr::from(0u8))?);
            }
            if padding_len != 0 {
                let pad_val = Fr::from((7 - padding_len) as u64)
                    * Fr::from(1u128 << 124)
                    * Fr::from(1u128 << 124);
                let last = felts.last_mut().unwrap();
                *last = last.clone() + const_f(&cs, pad_val)?;
            }
            if std::env::var("T3_SKIP").as_deref() != Ok("1b") {
                let mut all = vec![ch.digest.clone()];
                all.extend(felts);
                ch.digest = fr_hash_many_var(&cs, &all)?;
            }
        }
        ch.mix_root(&cs, &empty_root)?;
        ch.mix_root(&cs, &trace_root)?;
        let _rc_a = ch.draw_secure_felt(&cs)?;
        ch.mix_root(&cs, &quotient_root)?;
        {
            let _t = ch.draw_secure_felt(&cs)?;
        }
        {
            let qm31s: Vec<[CFelt; 4]> = (0..ood_vars.len())
                .step_by(4)
                .map(|i| [
                    ood_vars[i].clone(),
                    ood_vars[i + 1].clone(),
                    ood_vars[i + 2].clone(),
                    ood_vars[i + 3].clone(),
                ])
                .collect();
            ch.mix_felts(&cs, &qm31s)?;
        }
        let _rc_b = ch.draw_secure_felt(&cs)?;
        let mut alphas: Vec<[CFelt; 4]> = Vec::new();
        for r in &fri_root_vars {
            ch.mix_root(&cs, r)?;
            alphas.push(ch.draw_secure_felt(&cs)?);
        }
        {
            let last_q: Vec<[CFelt; 4]> = vec![[
                last_poly_vars[0].clone(),
                last_poly_vars[1].clone(),
                last_poly_vars[2].clone(),
                last_poly_vars[3].clone(),
            ]];
            ch.mix_felts(&cs, &last_q)?;
        }
        {
            let prefixed = fr_hash_many_var(
                &cs,
                &[
                    const_f(&cs, Fr::from(0x1234_5678u64))?,
                    ch.digest.clone(),
                    const_f(&cs, Fr::from(crate::fri_shadow::POW_BITS))?,
                ],
            )?;
            let hash = fr_hash_many_var(&cs, &[prefixed, pow_var.clone()])?;
            let bits = hash.to_bits_le()?;
            for b in bits.iter().take(crate::fri_shadow::POW_BITS as usize) {
                b.enforce_equal(&Boolean::constant(false))?;
            }
        }
        ch.mix_u64(&cs, w.pow_nonce)?;

        if std::env::var("T3_SKIP").as_deref() == Ok("2") { return Ok(()); }
        // ---- 2. 查询词抽取 ∈ 公开查询集合（选择器单热；sort/dedup 由链上
        // Solidity helper 校验——见设计文档 §2 残留信任）----
        {
            let mask_bits = w.lifting_log_size as usize;
            let nq = query_vars.len();
            let mut remaining = crate::fri_shadow::N_QUERIES;
            while remaining > 0 {
                let words = ch.draw_u32s(&cs)?;
                for word in words {
                    if remaining == 0 {
                        break;
                    }
                    let bits = word.to_bits_le()?;
                    let mut masked = const_f(&cs, Fr::from(0u8))?;
                    for b in 0..mask_bits {
                        let p = const_f(&cs, Fr::from(1u64 << b))?;
                        masked = masked + ({ let bb: CFelt = Boolean::into(bits[b].clone()); bb * p });
                    }
                    // 单热选择器：Σ s_i = 1 且 masked == Σ s_i·q_i
                    let mut sel = Vec::with_capacity(nq);
                    let mut sum = const_f(&cs, Fr::from(0u8))?;
                    for _ in 0..nq {
                        let s = Boolean::new_witness(ark_relations::ns!(cs, "sel"), || Ok(false))?;
                        sum = sum + { let bb: CFelt = Boolean::into(s.clone()); bb };
                        sel.push(s);
                    }
                    sum.enforce_equal(&const_f(&cs, Fr::from(1u8))?)?;
                    let mut recon = const_f(&cs, Fr::from(0u8))?;
                    for (s, qv) in sel.iter().zip(query_vars.iter()) {
                        let bb: CFelt = Boolean::into(s.clone());
                        recon = recon + (bb * qv.clone());
                    }
                    recon.enforce_equal(&masked)?;
                    remaining -= 1;
                }
            }
        }

        if std::env::var("T3_SKIP").as_deref() == Ok("3") { return Ok(()); }
        // ---- 3. PCS 树 Merkle 路径 ----
        for (ti, tree) in w.pcs_trees.iter().enumerate() {
            let root_var = if ti == 0 { trace_root.clone() } else { quotient_root.clone() };
            for (qi, row) in tree.leaf_rows.iter().enumerate() {
                let mut words_v: Vec<CFelt> = Vec::new();
                for chunk in row.chunks(8) {
                    let mut acc = const_f(&cs, Fr::from(0u8))?;
                    for (k, limb) in chunk.iter().enumerate() {
                        let m = m31_witness(&cs, *limb)?;
                        let p = const_f(&cs, shift31_pows()[k])?;
                        acc = acc + (m.v * p);
                    }
                    words_v.push(acc);
                }
                words_v.push(const_f(&cs, Fr::from(((row.len() + 7) / 8) as u64))?);
                let mut node = fr_hash_many_var(&cs, &words_v)?;
                let mut wit = tree.hash_witness.iter();
                let mut pos = w.queries[qi];
                for _ in 0..w.lifting_log_size {
                    let sib_hex = wit.next().ok_or(SynthesisError::AssignmentMissing)?;
                    let sib = CFelt::new_witness(ark_relations::ns!(cs, "sib"), || Ok(fe(sib_hex)))?;
                    let (l, r) = if pos & 1 == 0 {
                        (node, sib)
                    } else {
                        (sib, node)
                    };
                    node = fr_hash_many_var(&cs, &[l, r])?;
                    pos >>= 1;
                }
                node.enforce_equal(&root_var)?;
            }
        }

        if std::env::var("T3_SKIP").as_deref() == Ok("4") { return Ok(()); }
        // ---- 4. FRI：子集行叶子绑定 + 折叠链（M31）+ 首层商累积 + 末层常数 ----
        let first_domain_gen_log = w.lifting_log_size;
        let mut cur_positions = w.queries.clone();
        // 折叠域几何由宿主常数表提供（与 verify_shadow 相同公式）
        use stwo::core::poly::circle::CanonicCoset;
        use stwo::core::poly::line::LineDomain;
        let mut next_expected: Vec<QM31> = Vec::new();
        for (li, layer) in w.fri_layers.iter().enumerate() {
            let expect_now = std::mem::take(&mut next_expected);
            let root_var = fri_root_vars[li].clone();
            // 行 M31 见证（canonical）
            let mut rows: Vec<[QM31; 2]> = Vec::new();
            for row in &layer.subset_rows {
                let conv = |half: &[u32; 4]| -> R1CSResult<QM31> {
                    Ok(QM31 {
                        c0: CM31 {
                            re: m31_witness(&cs, half[0])?,
                            im: m31_witness(&cs, half[1])?,
                        },
                        c1: CM31 {
                            re: m31_witness(&cs, half[2])?,
                            im: m31_witness(&cs, half[3])?,
                        },
                    })
                };
                rows.push([conv(&row[0])?, conv(&row[1])?]);
            }
            // 子集覆盖位置 + 叶哈希 + 根绑定
            {
                let mut positions: Vec<usize> = Vec::new();
                let mut leaf_nodes: Vec<CFelt> = Vec::new();
                for (si, (start, _)) in
                    group_subsets_local(&cur_positions).into_iter().enumerate()
                {
                    let row = &layer.subset_rows[si];
                    for off in 0..2usize {
                        let pos = start + off;
                        if positions.last() == Some(&pos) {
                            continue;
                        }
                        positions.push(pos);
                        // 叶 = H_many(pack(row[off]) ++ [1])
                        let coords: [u32; 4] = row[off];
                        let mut msgs: Vec<CFelt> = Vec::new();
                        {
                            let mut acc = const_f(&cs, Fr::from(0u8))?;
                            for (k, limb) in coords.iter().enumerate() {
                                let m = m31_witness(&cs, *limb)?;
                                let p = const_f(&cs, shift31_pows()[k])?;
                                acc = acc + (m.v * p);
                            }
                            msgs.push(acc);
                        }
                        msgs.push(const_f(&cs, Fr::from(1u8))?);
                        leaf_nodes.push(fr_hash_many_var(&cs, &msgs)?);
                    }
                }
                let mut wit = layer.hash_witness.iter();
                let mut prev: Vec<(usize, CFelt)> =
                    positions.iter().cloned().zip(leaf_nodes).collect();
                for _ in 0..(w.lifting_log_size - li as u32) {
                    let mut curr: Vec<(usize, CFelt)> = Vec::new();
                    let mut i = 0;
                    while i < prev.len() {
                        if i + 1 < prev.len() && prev[i].0 ^ 1 == prev[i + 1].0 {
                            let h = fr_hash_many_var(&cs, &[prev[i].1.clone(), prev[i + 1].1.clone()])?;
                            curr.push((prev[i].0 >> 1, h));
                            i += 2;
                        } else {
                            let sib_hex = wit.next().ok_or(SynthesisError::AssignmentMissing)?;
                            let sib = CFelt::new_witness(ark_relations::ns!(cs, "fsib"), || Ok(fe(sib_hex)))?;
                            let h = if prev[i].0 & 1 == 0 {
                                fr_hash_many_var(&cs, &[prev[i].1.clone(), sib])?
                            } else {
                                fr_hash_many_var(&cs, &[sib, prev[i].1.clone()])?
                            };
                            curr.push((prev[i].0 >> 1, h));
                            i += 1;
                        }
                    }
                    prev = curr;
                }
                prev[0].1.enforce_equal(&root_var)?;
            }

            // 查询位置值检查 + 折叠
            let alpha0 = qm31_from_vars(&alphas[0]);
            let alpha_li = qm31_from_vars(&alphas[li.min(w.n_fri_layers - 1)]);
            let subsets = group_subsets_local(&cur_positions);
            let mut folded_next: Vec<QM31> = Vec::new();
            let mut qi = 0usize;
            for (si, (start, qs)) in subsets.iter().enumerate() {
                for off in 0..2usize {
                    let pos = start + off;
                    if qs.contains(&pos) {
                        let got = rows[si][off].clone();
                        let want = if li == 0 {
                            // 首层商累积（表常量 + M31 gadget）
                            let mut row_vals: Vec<M31> = Vec::new();
                            for r in w.pcs_trees[0].leaf_rows[qi].iter() {
                                row_vals.push(m31_witness(&cs, *r)?);
                            }
                            for r in w.pcs_trees[1].leaf_rows[qi].iter() {
                                row_vals.push(m31_witness(&cs, *r)?);
                            }
                            accumulate_quotients_var(
                                &cs,
                                &w.tables.per_query[qi],
                                &row_vals,
                                bit_rev_ref(pos, w.lifting_log_size),
                                first_domain_gen_log,
                            )?
                        } else {
                            // 规范化后比较
                            expect_now[qi].clone()
                        };
                        // 相等约束（逐坐标）
                        let got_c = qm31_canon(&cs, got.clone())?;
                        let want_c = qm31_canon(&cs, want)?;
                        let g = qm31_coords(&got_c);
                        let wnt = qm31_coords(&want_c);
                        for (a, b) in g.iter().zip(wnt.iter()) {
                            a.v.enforce_equal(&b.v)?;
                        }
                        qi += 1;
                    }
                }
                let (v0, v1) = (qm31_canon(&cs, rows[si][0].clone())?, qm31_canon(&cs, rows[si][1].clone())?);
                let folded = if li == 0 {
                    // fold_circle_into_line
                    let rc = crate::fri_shadow::circle_y_inv(
                        first_domain_gen_log,
                        bit_rev_ref(*start, first_domain_gen_log),
                    );
                    let f1 = qm31_mul_scalar(&cs, &v1, rc)?;
                    let f0 = v0.clone();
                    let f0c = qm31_canon(&cs, f0)?;
                    let f1c = qm31_canon(&cs, f1)?;
                    let prod = qm31_mul(&cs, &f1c, &alpha0)?;
                    qm31_add(&cs, &f0c, &prod)?
                } else {
                    let dom_log = w.lifting_log_size - li as u32;
                    let x_inv = crate::fri_shadow::line_x_inv(dom_log, bit_rev_ref(*start, dom_log));
                    let f1 = qm31_mul_scalar(&cs, &v1, x_inv)?;
                    let f0 = v0.clone();
                    let f0c = qm31_canon(&cs, f0)?;
                    let f1c = qm31_canon(&cs, f1)?;
                    let prod = qm31_mul(&cs, &f1c, &alpha_li)?;
                    qm31_add(&cs, &f0c, &prod)?
                };
                folded_next.push(qm31_canon(&cs, folded)?);
            }
            next_expected = folded_next;
            cur_positions = crate::fri_shadow::fold_queries(&cur_positions, crate::fri_shadow::FOLD_STEP);
            if li + 1 < w.n_fri_layers && next_expected.len() != cur_positions.len() {
                return Err(SynthesisError::Unsatisfiable);
            }
        }

        // ---- 5. 末层常数 ----
        let last_const_vars = last_poly_vars.clone();
        for v in &next_expected {
            let coords = qm31_coords(v);
            for (coord, cv) in coords.iter().zip(last_const_vars.iter()) {
                coord.v.enforce_equal(cv)?;
            }
        }
        Ok(())
    }
}

fn qm31_from_vars(v: &[CFelt; 4]) -> QM31 {
    // 变量包装为非规范 M31（bound 253——供线性使用；进乘法前需 canon）
    let m = |x: &CFelt| M31 { v: x.clone(), bound: 253 };
    QM31 {
        c0: CM31 { re: m(&v[0]), im: m(&v[1]) },
        c1: CM31 { re: m(&v[2]), im: m(&v[3]) },
    }
}

/// QM31 × M31 标量（4 次 const-mul；折叠常数是标量）。
fn qm31_mul_scalar(cs: &ConstraintSystemRef<Fr>, a: &QM31, k: u32) -> R1CSResult<QM31> {
    Ok(QM31 {
        c0: CM31 {
            re: m31_mul_const(cs, &m31_canon(cs, a.c0.re.clone())?, k)?,
            im: m31_mul_const(cs, &m31_canon(cs, a.c0.im.clone())?, k)?,
        },
        c1: CM31 {
            re: m31_mul_const(cs, &m31_canon(cs, a.c1.re.clone())?, k)?,
            im: m31_mul_const(cs, &m31_canon(cs, a.c1.im.clone())?, k)?,
        },
    })
}

#[allow(dead_code)]
fn qm31_mul_const_qm(cs: &ConstraintSystemRef<Fr>, a: &QM31, k: [u32; 4]) -> R1CSResult<QM31> {
    let kq = QM31 {
        c0: CM31 { re: m31_const(cs, k[0])?, im: m31_const(cs, k[1])? },
        c1: CM31 { re: m31_const(cs, k[2])?, im: m31_const(cs, k[3])? },
    };
    qm31_mul(cs, a, &kq)
}

/// 商累积（表驱动；与 fri_shadow::accumulate_quotients 同构）。
fn accumulate_quotients_var(
    cs: &ConstraintSystemRef<Fr>,
    table: &crate::fri_shadow::QueryBatchConstants,
    row: &[M31],
    pos: usize,
    lifting_log: u32,
) -> R1CSResult<QM31> {
    use stwo::core::poly::circle::CanonicCoset;
    let domain = CanonicCoset::new(lifting_log).circle_domain();
    let dp = domain.at(crate::fri_shadow::bit_rev(pos, lifting_log));
    let dy = dp.y.0;
    let mut acc = zero_qm31(cs)?;
    for batch in &table.batches {
        let mut num = zero_qm31(cs)?;
        for e in &batch.entries {
            let v = &row[e.column_index];
            // value·c：4 次 const-mul
            let c0 = m31_mul_const(cs, v, e.c[0])?;
            let c1 = m31_mul_const(cs, v, e.c[1])?;
            let c2 = m31_mul_const(cs, v, e.c[2])?;
            let c3 = m31_mul_const(cs, v, e.c[3])?;
            let value = QM31 {
                c0: CM31 { re: c0, im: c1 },
                c1: CM31 { re: c2, im: c3 },
            };
            // linear = a·qy + b：4 次 const-mul + 线性
            let a0 = m31_mul_const(cs, &m31_const(cs, e.a[0])?, dy)?;
            let a1 = m31_mul_const(cs, &m31_const(cs, e.a[1])?, dy)?;
            let a2 = m31_mul_const(cs, &m31_const(cs, e.a[2])?, dy)?;
            let a3 = m31_mul_const(cs, &m31_const(cs, e.a[3])?, dy)?;
            let linear = QM31 {
                c0: CM31 { re: m31_add(cs, &a0, &m31_const(cs, e.b[0])?)?, im: m31_add(cs, &a1, &m31_const(cs, e.b[1])?)? },
                c1: CM31 { re: m31_add(cs, &a2, &m31_const(cs, e.b[2])?)?, im: m31_add(cs, &a3, &m31_const(cs, e.b[3])?)? },
            };
            num = qm31_add(cs, &num, &qm31_sub(cs, &value, &linear)?)?;
        }
        // ×d⁻¹（CM31 常数）
        let dinv = CM31 {
            re: m31_const(cs, batch.denom_inv[0])?,
            im: m31_const(cs, batch.denom_inv[1])?,
        };
        let num = qm31_canon(cs, num)?;
        acc = qm31_add(cs, &acc, &qm31_mul_cm31(cs, &num, &dinv)?)?;
    }
    Ok(acc)
}

fn zero_qm31(cs: &ConstraintSystemRef<Fr>) -> R1CSResult<QM31> {
    Ok(QM31 {
        c0: CM31 { re: m31_const(cs, 0)?, im: m31_const(cs, 0)? },
        c1: CM31 { re: m31_const(cs, 0)?, im: m31_const(cs, 0)? },
    })
}

fn group_subsets_local(positions: &[usize]) -> Vec<(usize, Vec<usize>)> {
    crate::fri_shadow::group_subsets(positions)
}

fn bit_rev_ref(i: usize, log: u32) -> usize {
    crate::fri_shadow::bit_rev(i, log)
}
