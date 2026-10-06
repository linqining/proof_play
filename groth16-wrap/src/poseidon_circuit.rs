//! Starknet Poseidon 的 R1CS 电路实现（BN254 Fr 上的非原生 Fp252 算术）。
//!
//! 与 [`crate::poseidon`]（宿主参照）同构：Hades 布局、轮常量、MDS 优化形式
//! （线性组合，零乘法成本）、x³ sbox（ALPHA=3，2 次非原生乘法）逐项一致。
//! 一致性由 `tests/roundtrip.rs` 的 witness 满足性 + 金向量钉死。

use crate::felt::{Felt252, Fr};
use crate::poseidon::{ROUND_CONSTANTS, N_FULL_ROUNDS, N_PARTIAL_ROUNDS, STATE_WIDTH};
use ark_ff::{One, Zero};
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::fields::emulated_fp::EmulatedFpVar;
use ark_relations::gr1cs::{ConstraintSystemRef, Result as R1CSResult};

/// 电路中的 felt252 变量（BN254 Fr 上的非原生 Fp252）。
pub type CircuitFelt = EmulatedFpVar<Felt252, Fr>;

/// 常量 felt 变量（不产生约束）。
pub fn constant_felt(cs: ConstraintSystemRef<Fr>, v: Felt252) -> R1CSResult<CircuitFelt> {
    CircuitFelt::new_constant(ark_relations::ns!(cs, "felt_const"), &v)
}

/// 见证 felt 变量。
pub fn witness_felt(cs: ConstraintSystemRef<Fr>, v: Felt252) -> R1CSResult<CircuitFelt> {
    CircuitFelt::new_witness(ark_relations::ns!(cs, "felt_witness"), || Ok(v))
}

#[inline]
fn sbox3(x: &CircuitFelt) -> R1CSResult<CircuitFelt> {
    let x2 = x * x;
    Ok(x2 * x)
}

/// 把宿主轮常量（`&Felt252`）映射为电路常量；启动后 `ROUND_CONSTANTS` 已解析。
fn rc_circuit(cs: &ConstraintSystemRef<Fr>, index: usize) -> R1CSResult<CircuitFelt> {
    constant_felt(cs.clone(), ROUND_CONSTANTS[index])
}

#[inline]
fn full_round(cs: &ConstraintSystemRef<Fr>, state: &mut [CircuitFelt; STATE_WIDTH], index: usize) -> R1CSResult<()> {
    for i in 0..STATE_WIDTH {
        let rc = rc_circuit(cs, index + i)?;
        let added = &state[i] + &rc;
        state[i] = added;
        state[i] = sbox3(&state[i])?;
    }
    mix(state);
    Ok(())
}

#[inline]
fn partial_round(cs: &ConstraintSystemRef<Fr>, state: &mut [CircuitFelt; STATE_WIDTH], index: usize) -> R1CSResult<()> {
    let rc = rc_circuit(cs, index)?;
    let added = &state[2] + &rc;
    state[2] = sbox3(&added)?;
    mix(state);
    Ok(())
}

/// MDS（优化形式）：t = s0+s1+s2; s0' = t+2s0; s1' = t-2s1; s2' = t-3s2。
/// 纯线性组合 —— 电路零乘法成本。
#[inline]
fn mix(state: &mut [CircuitFelt; STATE_WIDTH]) {
    let t = &state[0] + &state[1] + &state[2];
    let s0 = &t + &state[0] + &state[0];
    let s1 = &t - &state[1] - &state[1];
    let s2 = &t - &state[2] - &state[2] - &state[2];
    *state = [s0, s1, s2];
}

/// Hades 置换（电路版，与 `crate::poseidon::hades_permutation` 同构）。
pub fn hades_permutation(cs: &ConstraintSystemRef<Fr>, state: &mut [CircuitFelt; STATE_WIDTH]) -> R1CSResult<()> {
    let mut index = 0;
    for _ in 0..N_FULL_ROUNDS / 2 {
        full_round(cs, state, index)?;
        index += STATE_WIDTH;
    }
    for _ in 0..N_PARTIAL_ROUNDS {
        partial_round(cs, state, index)?;
        index += 1;
    }
    for _ in 0..N_FULL_ROUNDS / 2 {
        full_round(cs, state, index)?;
        index += STATE_WIDTH;
    }
    debug_assert_eq!(index, ROUND_CONSTANTS.len());
    Ok(())
}

/// `poseidon_hash_many`（电路版）：与宿主同一 sponge（成对吸收 s0/s1、
/// 耗尽补 1、末尾再置换一次、取 s0）。
pub fn poseidon_hash_many(cs: &ConstraintSystemRef<Fr>, msgs: &[CircuitFelt]) -> R1CSResult<CircuitFelt> {
    let zero = constant_felt(cs.clone(), Felt252::zero())?;
    let one = constant_felt(cs.clone(), Felt252::one())?;
    let mut state = [zero.clone(), zero.clone(), zero];
    let mut iter = msgs.iter();

    loop {
        match iter.next() {
            Some(v) => {
                let s = &state[0] + v;
                state[0] = s;
            }
            None => {
                let s = &state[0] + &one;
                state[0] = s;
                break;
            }
        }
        match iter.next() {
            Some(v) => {
                let s = &state[1] + v;
                state[1] = s;
            }
            None => {
                let s = &state[1] + &one;
                state[1] = s;
                break;
            }
        }
        hades_permutation(cs, &mut state)?;
    }
    hades_permutation(cs, &mut state)?;

    Ok(state[0].clone())
}


#[cfg(test)]
mod debug_tests {
    use super::*;
    use crate::felt::{felt_from_hex, felt_to_hex};
    use ark_r1cs_std::eq::EqGadget;
    use ark_r1cs_std::GR1CSVar;

    /// 纯常量置换：电路 hades 与宿主 hades 必须逐点一致。
    #[test]
    fn circuit_hades_constants_only() {
        let cs = ark_relations::gr1cs::ConstraintSystem::<Fr>::new_ref();
        let mut state = [
            constant_felt(cs.clone(), felt_from_hex("0x9").unwrap()).unwrap(),
            constant_felt(cs.clone(), felt_from_hex("0xb").unwrap()).unwrap(),
            constant_felt(cs.clone(), felt_from_hex("0x2").unwrap()).unwrap(),
        ];
        hades_permutation(&cs, &mut state).unwrap();
        let expect = [
            "0x510f3a3faf4084e3b1e95fd44c30746271b48723f7ea9c8be6a9b6b5408e7e6",
            "0x4f511749bd4101266904288021211333fb0a514cb15381af087462fa46e6bd9",
            "0x186f6dd1a6e79cb1b66d505574c349272cd35c07c223351a0990410798bb9d8",
        ];
        for (i, (got, want)) in state.iter().zip(expect).enumerate() {
            let want = felt_from_hex(want).unwrap();
            let got_v = got.value().unwrap();
            println!("state[{i}] circuit={} expect={}", felt_to_hex(&got_v), felt_to_hex(&want));
            got.enforce_equal(&constant_felt(cs.clone(), want).unwrap()).unwrap();
        }
        assert!(cs.is_satisfied().unwrap(), "circuit hades (constants) mismatch");
    }

    /// 见证 felt 进哈希预映像（无位绑定）：结果必须等于宿主 fact 常量。
    #[test]
    fn circuit_hash_many_with_witness_vars() {
        let program_hash = felt_from_hex(
            "0x744d16d382e7940b7b93c0a069ab0df04704c5b28d6476d23cca6c2370a7ad4",
        )
        .unwrap();
        let out_hex = [
            "0xf", "0x5350324d5f4f4b", "0x2a",
            "0x5364144191559f1422d70c68e974e5989e264e83fb0e794c23b60dcf03f6643",
            "0x3", "0xa6aa",
            "0x1995ebc947b50c02308072edc9387047e415b0519d6ff88920ed4eae2aa803e",
            "0x0", "0x0", "0x0", "0x0", "0x0", "0x0", "0x0",
            "0x429d069189e0000",
            "0x7655f9f71d5bbf3607ad0c2921cfa3b28d24cd6cdd4f5407059ba1293697a01",
        ];
        let mut msgs = vec![program_hash];
        msgs.extend(out_hex.iter().map(|h| felt_from_hex(h).unwrap()));
        let host = crate::poseidon::poseidon_hash_many(&msgs);

        let cs = ark_relations::gr1cs::ConstraintSystem::<Fr>::new_ref();
        cs.set_optimization_goal(ark_relations::gr1cs::OptimizationGoal::Constraints);
        let msg_vars: Vec<CircuitFelt> = msgs
            .iter()
            .map(|m| witness_felt(cs.clone(), *m).unwrap())
            .collect();
        let out = poseidon_hash_many(&cs, &msg_vars).unwrap();
        let out_v = ark_r1cs_std::GR1CSVar::<Fr>::value(&out).unwrap();
        println!("witness hash out = {} host = {}", felt_to_hex(&out_v), felt_to_hex(&host));
        out.enforce_equal(&constant_felt(cs.clone(), host).unwrap()).unwrap();
        let unsat = cs.which_is_unsatisfied().unwrap_or(None);
        assert!(
            cs.is_satisfied().unwrap(),
            "witness hash mismatch; unsatisfied = {unsat:?}"
        );
    }


    /// 9 次置换逐轮检查：定位哪一轮开始不满足。
    #[test]
    fn circuit_round_by_round() {
        let cs = ark_relations::gr1cs::ConstraintSystem::<Fr>::new_ref();
        let msg_vars: Vec<CircuitFelt> = vec![
            witness_felt(cs.clone(), felt_from_hex("0x1234").unwrap()).unwrap(),
            witness_felt(cs.clone(), felt_from_hex("0x5350324d5f4f4b").unwrap()).unwrap(),
            witness_felt(cs.clone(), felt_from_hex("0x2a").unwrap()).unwrap(),
        ];
        // 手工 sponge（与 hash_many 相同结构，3 个消息 = 1 轮吸收 + 1 终置换）
        let zero = constant_felt(cs.clone(), Felt252::zero()).unwrap();
        let one = constant_felt(cs.clone(), Felt252::one()).unwrap();
        let mut state = [zero.clone(), zero, one.clone()];
        let s0 = &state[0] + &msg_vars[0];
        state[0] = s0;
        let s1 = &state[1] + &msg_vars[1];
        state[1] = s1;
        println!("after absorb: satisfied = {}", cs.is_satisfied().unwrap());
        hades_permutation(&cs, &mut state).unwrap();
        println!("after perm1: satisfied = {}", cs.is_satisfied().unwrap());
        // 再来一轮吸收+置换
        let s0 = &state[0] + &msg_vars[2];
        state[0] = s0;
        let s1 = &state[1] + &one;
        state[1] = s1;
        println!("after absorb2: satisfied = {}", cs.is_satisfied().unwrap());
        hades_permutation(&cs, &mut state).unwrap();
        println!("after perm2: satisfied = {}", cs.is_satisfied().unwrap());
        let _ = ark_r1cs_std::GR1CSVar::value(&state[0]).unwrap();
    }

    /// 逐操作二分：定位不满足约束的最低层操作。
    #[test]
    fn circuit_op_bisect() {
        use ark_r1cs_std::GR1CSVar;
        use ark_r1cs_std::eq::EqGadget;
        let cs = ark_relations::gr1cs::ConstraintSystem::<Fr>::new_ref();
        let x = witness_felt(cs.clone(), felt_from_hex("0x1234").unwrap()).unwrap();
        let y = witness_felt(cs.clone(), felt_from_hex("0x5350324d5f4f4b").unwrap()).unwrap();
        println!("init satisfied = {}", cs.is_satisfied().unwrap());

        let x2 = &x * &x;
        println!("after x*x: satisfied = {}", cs.is_satisfied().unwrap());

        let x3 = &x2 * &y;
        println!("after x2*y: satisfied = {}", cs.is_satisfied().unwrap());

        let s = &x3 + &y;
        println!("after +: satisfied = {}", cs.is_satisfied().unwrap());

        let d = &s - &y;
        println!("after -: satisfied = {}", cs.is_satisfied().unwrap());

        // 线性 mix 形状
        let t = &x + &y + &d;
        let m0 = &t + &x + &x;
        let m1 = &t - &y - &y;
        let m2 = &t - &d - &d - &d;
        let _ = (m0.value().unwrap(), m1.value().unwrap(), m2.value().unwrap());
        println!("after mix: satisfied = {}", cs.is_satisfied().unwrap());

        // enforce_equal 到 witness 重构值
        m0.enforce_equal(&witness_felt(cs.clone(), m0.value().unwrap()).unwrap()).unwrap();
        println!("after enforce_eq: satisfied = {}", cs.is_satisfied().unwrap());

        // 单次 full_round
        let mut st = [
            witness_felt(cs.clone(), felt_from_hex("0x9").unwrap()).unwrap(),
            witness_felt(cs.clone(), felt_from_hex("0xb").unwrap()).unwrap(),
            witness_felt(cs.clone(), felt_from_hex("0x2").unwrap()).unwrap(),
        ];
        let r0 = full_round(&cs, &mut st, 0);
        println!("full_round err = {:?}, satisfied = {}", r0.is_err(), cs.is_satisfied().unwrap());
    }

    /// 纯常量 hash_many：电路 fact 与宿主 fact 必须一致。
    #[test]
    fn circuit_hash_many_constants_only() {
        let program_hash = felt_from_hex(
            "0x744d16d382e7940b7b93c0a069ab0df04704c5b28d6476d23cca6c2370a7ad4",
        )
        .unwrap();
        let out_hex = [
            "0xf", "0x5350324d5f4f4b", "0x2a",
            "0x5364144191559f1422d70c68e974e5989e264e83fb0e794c23b60dcf03f6643",
            "0x3", "0xa6aa",
            "0x1995ebc947b50c02308072edc9387047e415b0519d6ff88920ed4eae2aa803e",
            "0x0", "0x0", "0x0", "0x0", "0x0", "0x0", "0x0",
            "0x429d069189e0000",
            "0x7655f9f71d5bbf3607ad0c2921cfa3b28d24cd6cdd4f5407059ba1293697a01",
        ];
        let mut msgs = vec![program_hash];
        msgs.extend(out_hex.iter().map(|h| felt_from_hex(h).unwrap()));
        let host = crate::poseidon::poseidon_hash_many(&msgs);

        let cs = ark_relations::gr1cs::ConstraintSystem::<Fr>::new_ref();
        let msg_vars: Vec<CircuitFelt> = msgs
            .iter()
            .map(|m| constant_felt(cs.clone(), *m).unwrap())
            .collect();
        let out = poseidon_hash_many(&cs, &msg_vars).unwrap();
        out.enforce_equal(&constant_felt(cs.clone(), host).unwrap()).unwrap();
        assert!(cs.is_satisfied().unwrap(), "circuit hash_many (constants) mismatch, host={}", felt_to_hex(&host));
    }
}