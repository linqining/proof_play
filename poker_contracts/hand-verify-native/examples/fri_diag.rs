// 诊断:真实小证明的提取形状
use hand_verify_native::air::{HandBatchClaim, KindCounts};
use hand_verify_native::prove::{prove_claim, verify_stark_against};

fn main() {
    let claim = HandBatchClaim::new(
        starknet_crypto::Felt::from(12345u64),
        starknet_crypto::Felt::from(67890u64),
        KindCounts { n_own: 1, n_reveal: 1, n_leave: 0, n_recon: 0 },
        starknet_crypto::Felt::ZERO,
    );
    println!("log_size = {}", claim.log_size);
    let t0 = std::time::Instant::now();
    let hand = prove_claim(&claim).unwrap();
    println!("prove: {:?}, log_size={}", t0.elapsed(), claim.log_size);
    verify_stark_against(&claim, &hand.stark_proof).unwrap();
    println!("stwo verify: OK");
    let p = &hand.stark_proof;
    println!("commitments = {}", p.commitments.0.len());
    println!("fri inner layers = {}", p.fri_proof.inner_layers.len());
    println!("last_layer_poly len = {:?}", p.fri_proof.last_layer_poly.len());
    for (ti, t) in p.sampled_values.0.iter().enumerate() {
        let cols: Vec<usize> = t.iter().map(|c| c.len()).collect();
        println!("sampled_values tree{ti}: {} cols, lens={:?}", t.len(), &cols[..cols.len().min(20)]);
    }
    // z vs z^2 检查:重新走 verify_ex 前半段拿 oods_point
    use stwo::core::channel::{Channel, MerkleChannel, Poseidon252Channel};
    use stwo::core::vcs_lifted::poseidon252_merkle::Poseidon252MerkleChannel;
    use stwo::core::pcs::utils::get_lifting_log_size;
    use stwo::core::verifier::COMPOSITION_LOG_SPLIT;
    use stwo_constraint_framework::{FrameworkComponent, TraceLocationAllocator};
    use stwo::core::fields::qm31::SecureField;
    use stwo::core::air::{Component, Components};
    let mut allocator = TraceLocationAllocator::default();
    let component = FrameworkComponent::new(&mut allocator, hand_verify_native::air::HandBatchEval::new(&claim), SecureField::from(0u32));
    let components = Components { components: vec![&component], n_preprocessed_columns: 0 };
    let comp_bound = components.composition_log_degree_bound();
    let config = hand_verify_native::prove::protocol_pcs_config();
    let lifting = get_lifting_log_size(&config, comp_bound - COMPOSITION_LOG_SPLIT + config.fri_config.log_blowup_factor);
    let max_bound = lifting - config.fri_config.log_blowup_factor;
    println!("comp_bound={comp_bound} lifting={lifting} max_bound={max_bound}");
    let mut ch = Poseidon252Channel::default();
    claim.mix_into(&mut ch);
    Poseidon252MerkleChannel::mix_root(&mut ch, p.commitments.0[0]);
    Poseidon252MerkleChannel::mix_root(&mut ch, p.commitments.0[1]);
    let _rc_a = ch.draw_secure_felt();
    Poseidon252MerkleChannel::mix_root(&mut ch, p.commitments.0[2]);
    let oods = stwo::core::circle::CirclePoint::<SecureField>::get_random_point(&mut ch);
    let sp = components.mask_points(oods, max_bound, false);
    let z = oods;
    let z2 = z.double();
    for (ti, t) in sp.0.iter().enumerate() {
        for (ci, col) in t.iter().enumerate() {
            for (si, pt) in col.iter().enumerate() {
                let is_z = pt.x == z.x && pt.y == z.y;
                let is_z2 = pt.x == z2.x && pt.y == z2.y;
                if !is_z && !is_z2 {
                    println!("tree{ti} col{ci} sample{si}: NEITHER z nor z2!");
                } else if ti == 1 && ci < 3 || ti == 2 {
                    println!("tree{ti} col{ci} sample{si}: {} {}", if is_z {"z"} else {""}, if is_z2 {"z2"} else {""});
                }
            }
        }
    }
    let _ = z2;
    let mut w = hand_verify_native::prove::protocol_pcs_config();
    let _ = &mut w;
}
