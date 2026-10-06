//! Dual-proof settlement contract (docs/design/DUAL_PROOF_PROTOCOL.md §7.1, MVP).
//!
//! Two proof tracks must agree before chips move:
//!
//! - **P** (poker_protocol, BN254 G1 direct-sigma): every per-player proof is
//!   verified **on-chain** through [`super::dual::sigma_verifier`] — this
//!   contract is the strongest verifier, not a digest registrar.
//! - **G** (牌局过程 STARK): Phase 1 MVP = host-verified canonical STARK whose
//!   commitments are registered here via the unified `hand_binding`
//!   (Phase 2 on-chain STARK verification is §7.3, four routes).
//!
//! Binding invariants (§6): a hand settles only when
//! (a) the `hand_binding` was registered and is not yet settled,
//! (b) the recomputed Poseidon `settlement_digest` matches the registered one,
//! (c) every player's P proof verifies on-chain,
//! (d) the deltas are zero-sum.
use openzeppelin::access::ownable::OwnableComponent;
use starknet::ContractAddress;

#[starknet::interface]
pub trait IPokerDualSettlement<TContractState> {
    /// Register a hand's unified binding (authorized prover only).
    ///
    /// `hand_binding` — Poseidon digest over the documented §6 field order
    /// (Rust: `poker_texas_air::hand_binding`).
    /// `settlement_digest` — the existing settlement commitment
    /// (#18 Phase B: `poseidon([hand_id] ++ Σ(player, sign, |delta|)
    /// ++ [action_log_digest])`).
    /// `action_log_digest` — the hand's action-log hash (starknet_keccak chain
    /// over the accepted/auto actions). Stored so the v2 private settle can
    /// pin the proven public segment's action-log word to the registered one.
    /// `g_attestation` — Phase 1 registration of the host-verified G-STARK
    /// commitments (Poseidon over binding + settlement + state roots).
    /// `expected_n_reveal/leave/recon` — completeness hardening: the
    /// caller's expected bucket counts for the hand-batch header
    /// (words 2..4: [n_reveal, n_leave, n_recon]). They are stored packed
    /// as one felt and the linear settle entry asserts the submitted batch
    /// header matches exactly when the packed value is non-zero; **all-zero
    /// = unconstrained** (the legacy default — existing registrants keep
    /// working, and the Rust server currently registers zeros).
    fn register_hand(
        ref self: TContractState,
        hand_binding: felt252,
        settlement_digest: felt252,
        g_attestation: felt252,
        action_log_digest: felt252,
        expected_n_reveal: felt252,
        expected_n_leave: felt252,
        expected_n_recon: felt252,
    );

    /// Plan D STARK-curve variant of `verify_and_settle_dapv`: the P layer
    /// folds on the Cairo-native STARK curve via the EC_OP builtin
    /// (`dual::hand_batch_stark::verify_hand_batch_stark`). Payload words
    /// are felt252-range u256s (coordinates/scalars are < n < P and convert
    /// losslessly); challenges and rho are Poseidon (host
    /// `StarkCurve::hash_to_scalar`), transcript domain stays keccak.
    /// `action_log_digest` (#18 Phase B) is the hand's action-log hash —
    /// recomputed into the settlement digest and compared with the
    /// registered root.
    fn verify_and_settle_dapv_stark(
        ref self: TContractState,
        hand_binding: felt252,
        hand_id_bytes: Span<u8>,
        hand_id: u64,
        action_log_digest: felt252,
        players: Span<ContractAddress>,
        deltas: Span<i128>,
        p_batch: Span<felt252>,
    );

    fn set_prover(ref self: TContractState, prover: ContractAddress);
    fn remove_prover(ref self: TContractState, prover: ContractAddress);
    fn is_prover(self: @TContractState, prover: ContractAddress) -> bool;
    fn hand_binding(self: @TContractState, binding: felt252) -> (felt252, felt252, felt252);
    fn hand_settled(self: @TContractState, binding: felt252) -> bool;
    fn vault(self: @TContractState) -> ContractAddress;
    /// View: the registered action-log commitment for `hand_binding`
    /// (#18 Phase B; 0 for bindings registered before it existed).
    fn hand_action_log(self: @TContractState, binding: felt252) -> felt252;

    /// Part A Phase 1（docs/design/SETTLEMENT_PRIVACY_PLAN.md §4）：隐私结算入口。
    /// 与 `verify_and_settle_dapv_stark` 相同的 DAPV 校验与 digest 断言，
    /// 但派奖方式不同：
    /// - 输家（delta < 0）仍经 vault.apply_settlement 公开扣款
    ///   （Phase 1 已知残余，Phase 2 由 ZK 消除）；
    /// - 赢家（delta > 0）不再记入公开 chip 余额，改为按座位写入认领
    ///   承诺 `cm = poseidon(commitment, hand_binding, amount_lo,
    ///   amount_hi)`（commitment 为玩家在 vault 注册的 payout 承诺
    ///   `poseidon(secret)`），并把赢家总额经 `vault.settlement_fund_escrow`
    ///   划入认领托管；
    /// - 赢家凭 secret 原像经 STRK20 池私密认领（见
    ///   SettlementPayoutAnonymizer）。
    /// `settlement_digest` 仍约束同一 (players, deltas) 明文——Phase 2 用
    /// Stwo 把"开根"搬进证明后，明文才真正离开 calldata。
    fn verify_and_settle_dapv_stark_private(
        ref self: TContractState,
        hand_binding: felt252,
        hand_id_bytes: Span<u8>,
        hand_id: u64,
        action_log_digest: felt252,
        players: Span<ContractAddress>,
        deltas: Span<i128>,
        p_batch: Span<felt252>,
    );

    /// P2-M3（docs/design/SETTLEMENT_PRIVACY_PLAN.md §4 Phase 2）：零明文结算入口。
    /// calldata 只含 (hand_binding, hand_id, segment)，**不含 players/deltas**；
    /// segment 是 settlement_private 电路（program_hash 钉死）的公开段：
    /// `[MAGIC, hand_id, digest, n, binding, cm_0..cm_8, total_winnings,
    /// action_log_digest]`（16 felt，#18 Phase B + 9 人桌迁移）。
    /// 信任锚为 fact-registry：`fact = poseidon([program_hash ++ segment])`
    /// 须已由授权 prover/owner 登记（Stwo Cairo verifier 上链前的过渡形态，
    /// 与 G 层 host-verified 同一 residual-trust 口径）；托管金额取自公开段
    /// total_winnings（零和由电路证明，Σ claim ≤ escrow 由 vault 余额封顶）；
    /// segment 尾词（动作日志哈希）必须等于注册承诺——把零明文结算锚定到
    /// 带审计日志的完整动作序列。

    /// P2-M3（docs/design/SETTLEMENT_PRIVACY_PLAN.md §4 Phase 2）：零明文结算入口。
    /// calldata 只含 (hand_binding, hand_id, segment)，**不含 players/deltas**；
    /// segment 是 settlement_private 电路（program_hash 钉死）的公开段：
    /// `[MAGIC, hand_id, digest, n, binding, cm_0..cm_8, total_winnings]`。
    /// 信任锚为 fact-registry：`fact = poseidon([program_hash ++ segment])`
    /// 须已由授权 prover/owner 登记（Stwo Cairo verifier 上链前的过渡形态，
    /// 与 G 层 host-verified 同一 residual-trust 口径）；托管金额取自公开段
    /// total_winnings（零和由电路证明，Σ claim ≤ escrow 由 vault 余额封顶）。
    fn verify_and_settle_dapv_stark_private_v2(
        ref self: TContractState,
        hand_binding: felt252,
        hand_id: u64,
        segment: Span<felt252>,
    );
    /// P2-M5（SNIP-36）：v3 双门私密结算——**协议内证明优先，fact-registry
    /// 降级**。calldata 与 v2 完全一致；验证门（对齐 starknet-privacy 参考实现
    /// `validate_proof` 的两笔交易模式）：
    ///   (a) SNIP-36：提交侧先用 `emit_settlement_proof_message` 生成
    ///       create_proof 交易并送 `starknet_proveTransaction` 证明，随后本
    ///       入口作为**第二笔**交易携带 proof/proof_facts 上链。合约经
    ///       `get_execution_info_v3_syscall` 读 `tx_info.proof_facts`，断言
    ///       `facts[1]`（program variant）== "VIRTUAL_SNOS" 且 `facts[2]`
    ///       （virtual SNOS program hash——**Starknet 虚拟 OS 的固定程序
    ///       哈希，非本方电路哈希**）== 钉死的 `virtual_snos_program_hash`，
    ///       且 `facts[8]`（首条 L2→L1 消息哈希）==
    ///       `poseidon(本合约地址, 0, segment 长度, segment)`——公开段即
    ///       create_proof 交易发出的消息 payload，把证明绑定到本手公开段；
    ///   (b) 降级：无 proof_facts 时走 v2 同款 fact-registry 门。
    /// 派奖/幂等/事件与 v2 完全一致。
    fn verify_and_settle_dapv_stark_private_v3(
        ref self: TContractState,
        hand_binding: felt252,
        hand_id: u64,
        segment: Span<felt252>,
    );
    /// P2-M6（SNIP-36 create_proof 形态）：被 `starknet_proveTransaction`
    /// 证明的**第一笔**交易入口——校验公开段与注册态一致后，发出
    /// `to_address=0`、`payload=segment` 的 L2→L1 消息。虚拟执行中该消息
    /// 哈希进入 proof_facts[8]，从而把证明与本手的公开段绑定。本入口不写
    /// 存储、不结算（结算只发生在携带 proof 的 v3 第二笔交易）。
    fn emit_settlement_proof_message(
        ref self: TContractState,
        hand_binding: felt252,
        hand_id: u64,
        segment: Span<felt252>,
    );
    /// Owner-gated: 钉死电路 program hash（fact 的绑定根，换电路须重设）。
    fn set_circuit_program_hash(ref self: TContractState, program_hash: felt252);
    /// Owner-gated: 钉死 Starknet 虚拟 OS（VIRTUAL_SNOS）program hash
    /// ——SNIP-36 proof_facts[2] 的绑定根（随 Starknet 版本演进须重设；
    /// 槽位/取值上链前用 sepolia 真实样本对拍冻结）。
    fn set_virtual_snos_program_hash(ref self: TContractState, program_hash: felt252);
    /// View: 钉死的虚拟 OS program hash。
    fn virtual_snos_program_hash(self: @TContractState) -> felt252;
    /// Prover/owner-gated: 登记已生成证明的 fact（prove-hand 后由运营侧调用）。
    fn register_settlement_fact(ref self: TContractState, fact: felt252);
    /// View: 钉死的电路 program hash。
    fn circuit_program_hash(self: @TContractState) -> felt252;
    /// View: fact 是否已登记。
    fn settlement_fact(self: @TContractState, fact: felt252) -> bool;
    /// Owner-gated: 钉死 hand_verify（hand_batch σ 批量校验 STARK）的
    /// program hash——proved_private 双证明之一的绑定根（换 hand_verify
    /// 电路须重设）。
    fn set_hand_verify_program_hash(ref self: TContractState, program_hash: felt252);
    /// Proved 私密结算注册：除常规注册字段外钉住 (p_batch_commitment,
    /// p_batch_len)——p_batch 全文不上链，由 hand_verify 证明在承诺下
    /// 背书。prover-gated，与 register_hand 同门；期望桶计数沿用
    /// register calldata 形状（proved 结算不上链批次，仅作注册侧留痕）。
    fn register_hand_proved(
        ref self: TContractState,
        hand_binding: felt252,
        settlement_digest: felt252,
        g_attestation: felt252,
        action_log_digest: felt252,
        p_batch_commitment: felt252,
        p_batch_len: felt252,
        expected_n_reveal: felt252,
        expected_n_leave: felt252,
        expected_n_recon: felt252,
    );
    /// P2-M4：proved × private 双证明结算入口（hand_verify + stark verify）。
    /// 双 fact 认证：
    ///   (a) hand_verify：fact = poseidon([hand_verify_program_hash,
    ///       p_batch_commitment])——外部 hand_verify 证明「注册的 p_batch
    ///       承诺下的 hand_batch σ 批量校验成立」（p_batch 全文不上链）；
    ///   (b) stark verify：fact = poseidon([circuit_program_hash, segment])——
    ///       settlement_private 电路对公开段的证明（与 v2 同锚）。
    /// 派奖与 v2 private 相同：金额藏在公开段 cm（claim 承诺），escrow 按
    /// 公开段 total_winnings 划转，players/deltas 不出现。
    fn verify_and_settle_dapv_proved_private(
        ref self: TContractState,
        hand_binding: felt252,
        hand_id: u64,
        segment: Span<felt252>,
        p_batch_commitment: felt252,
        p_batch_len: u32,
    );
    /// 合并信封（2026-09-29）：**一份** Stwo 证明同时覆盖 P 层（hand_verify
    /// σ 批量校验，EC_OP 进 trace）与 settlement_private 语句，公开段
    /// 17 词 = `[chain_acc, MAGIC, hand_id, digest, n, binding, cm_0..cm_8,
    /// total_winnings, action_log_digest]`（v2 16 词段前置 chain_acc）。
    /// 单 fact 门：`fact = poseidon([combined_program_hash ++ segment])`——
    /// 电路内已断言每条 P 任务的 hand_binding == settle 段 binding，故单
    /// fact 即同时锚定「这手的签名验证」与「这手的结算语句」。派奖/幂等/
    /// 事件与 v2 一致；chain_acc 仅随事件 emit（PCD 链尾锚，供第三方复验）。
    fn verify_and_settle_dapv_combined_private(
        ref self: TContractState,
        hand_binding: felt252,
        hand_id: u64,
        segment: Span<felt252>,
    );
    /// Owner-gated：钉死合并信封程序的 program hash（fact 绑定根）。
    fn set_combined_program_hash(ref self: TContractState, program_hash: felt252);
    /// View：钉死的合并信封 program hash。
    fn combined_program_hash(self: @TContractState) -> felt252;
    /// fold 链注册面（规格 out/fold-spec.md §4.2）：owner-gated 一次性注册
    /// 一张桌的 roster。链上重算
    /// `roster_digest = poseidon(['poker/fold-batch/roster.v1', n] ++ pks)`
    /// ——标签与 fold 电路 `fold_batch.cairo` 的 ROSTER_LABEL 常量逐字节
    /// 一致，使注册值与电路公式同源（消费面对照 = segment[17] 直读）。
    /// `n` 限 2..=9、`pks.len() == 2·n`（≤ 18 词）；不验 on-curve（合约无 EC 能力，
    /// 垃圾 pks 只会登记一个电路必然 panic 的 digest，不出证即不出金）。
    /// digest 已注册时拒绝（注册值不可改写）；pks 全文随事件可取，供
    /// 玩家自核注册面。
    fn register_roster(ref self: TContractState, table_id: u64, n: felt252, pks: Span<felt252>);
    /// View：roster_digest 是否已注册。
    fn roster_registered(self: @TContractState, roster_digest: felt252) -> bool;
    /// Owner-gated：钉死 fold 批程序的 program hash（fold 入口 fact 绑定
    /// 根，与 combined_program_hash 分槽——两链禁混批的承重件之一）。
    fn set_fold_program_hash(ref self: TContractState, program_hash: felt252);
    /// View：钉死的 fold 批程序 program hash。
    fn fold_program_hash(self: @TContractState) -> felt252;
    /// fold 链批结算入口（规格 §4.4）：18 词公开段 = combined 17 词信封
    /// 原样 + 尾插 roster_digest（index 17）。校验序列与 combined 入口
    /// 逐项同构，仅两处增量：段长 18 与 segment[17] 对照 roster 注册面。
    /// fact 门复用 settlement_facts（owner/prover 登记），绑 fold 哈希。
    fn verify_and_settle_dapv_fold_private(
        ref self: TContractState,
        hand_binding: felt252,
        hand_id: u64,
        segment: Span<felt252>,
    );
    /// View: 该手是否为 v2（金额藏在 cm 中，consume_claim 走隐藏模式）。
    fn amounts_hidden(self: @TContractState, hand_binding: felt252) -> bool;
    /// Owner-gated: set the claim escrow helper that receives the winners'
    /// pot via `vault.settlement_fund_escrow`.
    fn set_claim_helper(ref self: TContractState, helper: ContractAddress);
    /// View: the stored claim commitment for (hand_binding, seat_index).
    fn claim_cm(self: @TContractState, hand_binding: felt252, seat_index: u32) -> felt252;
    /// View: the claimable amount for (hand_binding, seat_index).
    fn claim_amount(self: @TContractState, hand_binding: felt252, seat_index: u32) -> u256;
    /// Claim-helper gated: consume a claim (idempotence + amount assert).
    fn consume_claim(
        ref self: TContractState,
        hand_binding: felt252,
        seat_index: u32,
        amount: u256,
    );
    /// View: the configured claim helper.
    fn claim_helper(self: @TContractState) -> ContractAddress;
}

#[starknet::contract]
pub mod PokerDualSettlement {
    use openzeppelin::access::ownable::OwnableComponent;
    use starknet::ContractAddress;
    use starknet::syscalls::{get_execution_info_v3_syscall, send_message_to_l1_syscall};
    use starknet::SyscallResultTrait;
    use core::num::traits::Zero;
    use core::hash::HashStateTrait;
    use core::poseidon::{poseidon_hash_span, PoseidonTrait};
    use starknet::storage::{
        Map, StorageMapReadAccess, StorageMapWriteAccess, StoragePointerReadAccess,
        StoragePointerWriteAccess,
    };
    use super::super::dual::hand_batch_stark::verify_hand_batch_stark;
    use super::IVaultDispatcherDispatcherTrait;

    // P2-M3 公开段常量与 fact 公式（与 proving-tool/src/settlement_private.cairo
    // 及 texas/src/starknet/settlement_prover.rs 三方一致）。
    // #18 Phase B：段长 14 → 15（尾词 = 动作日志哈希，对注册承诺比对）。
    const SETTLEMENT_SEGMENT_MAGIC: felt252 = 0x5350324d5f4f4b;
    const SETTLEMENT_SEGMENT_LEN: usize = 16;
    /// 合并信封公开段：v2 16 词前置 chain_acc（fact 消费整段 17 词）。
    const COMBINED_SEGMENT_LEN: usize = 17;
    /// fold 批公开段：combined 17 词信封原样 + 尾插 roster_digest
    /// （index 17；word 0–16 与 combined 逐词同位，规格 out/fold-spec.md D1）。
    /// 三态共存：各入口自断言各段长，禁混批（D3c 第 3 层）。
    /// 9 人桌迁移：语句段 cm×8→cm×9，三段长各 +1。
    const FOLD_SEGMENT_LEN: usize = 18;
    /// roster 域标签（与 fold_batch.cairo 电路 ROSTER_LABEL 常量逐字节一致）。
    const ROSTER_LABEL: felt252 = 'poker/fold-batch/roster.v1';

    /// SNIP-36 proof_facts 布局常量（对齐 starknet-privacy 参考实现的
    /// ProofFacts 序列化与 sequencer `starknet_proof_verifier` 0.14.3 回归
    /// 样本）：proof_facts[1] = "VIRTUAL_SNOS" ASCII（program variant），
    /// proof_facts[2] = 虚拟 OS program hash，[7] = L2→L1 消息数（1），
    /// [8] = 首条消息哈希。槽位上链前仍须用 sepolia 真实样本对拍冻结。
    const VIRTUAL_SNOS_VARIANT: felt252 = 0x5649525455414c5f534e4f53;

    /// SNIP-36 消息哈希公式（skill 参考实现口径；上链前需用真实 proof_facts
/// 样本对拍冻结——槽位/公式以 SNIP-36 最终规范为准）：
/// `poseidon([合约地址, 0, payload_len, payload...])`。
fn snip36_message_hash(contract_addr: ContractAddress, segment: Span<felt252>) -> felt252 {
    let mut h = PoseidonTrait::new();
    h = h.update(contract_addr.into());
    h = h.update(0);
    h = h.update(segment.len().into());
    let mut w: u32 = 0;
    while w < segment.len() {
        h = h.update(*segment.at(w));
        w += 1;
    }
    h.finalize()
}

fn fact_for_segment(program_hash: felt252, segment: Span<felt252>) -> felt252 {
        let mut h = PoseidonTrait::new();
        h = h.update(program_hash);
        let mut w: u32 = 0;
        while w < segment.len() {
            h = h.update(*segment.at(w));
            w += 1;
        }
        h.finalize()
    }

/// Big-endian bytes → felt252 (Horner). Used to bind the DAPV batch's
/// hand-domain input to the registered `hand_binding` felt.
fn bytes_to_felt(bytes: Span<u8>) -> felt252 {
    let mut acc: felt252 = 0;
    let mut i: u32 = 0;
    while i < bytes.len() {
        acc = acc * 256 + (*bytes.at(i)).into();
        i += 1;
    }
    acc
}

/// Shared settlement-digest recompute (settlement_hash.cairo layout):
/// Poseidon over [hand_id, (player, sign, |delta|)*, action_log_digest] —
/// the tail word (#18 Phase B) binds the settlement to the hand's
/// audited action log. Keeping ONE copy is also what keeps the contract's
/// CASM under the Starknet bytecode limit — every settle entry must compare
/// against the registered digest through this helper, not inline its own loop.
fn compute_settlement_digest(
    hand_id: u64,
    action_log_digest: felt252,
    players: Span<ContractAddress>,
    deltas: Span<i128>,
) -> felt252 {
    let mut felements: Array<felt252> = array![hand_id.into()];
    let mut i: u32 = 0;
    while i < players.len() {
        felements.append((*players.at(i)).into());
        let delta = *deltas.at(i);
        if delta >= 0_i128 {
            let as_u: u64 = delta.try_into().expect('delta fits u64');
            felements.append(1);
            felements.append(as_u.into());
        } else {
            let abs_delta = -delta;
            let as_u: u64 = abs_delta.try_into().expect('abs delta fits u64');
            felements.append(0);
            felements.append(as_u.into());
        }
        i += 1;
    }
    felements.append(action_log_digest);
    poseidon_hash_span(felements.span())
}

/// Shared zero-sum assertion (settlement invariant (d)).
fn assert_zero_sum(deltas: Span<i128>) {
    let zero: i128 = 0_i128;
    let mut sum: i128 = 0_i128;
    let mut d: u32 = 0;
    while d < deltas.len() {
        sum += *deltas.at(d);
        d += 1;
    }
    assert!(sum == zero, "Settlement not zero-sum");
}

/// Shared per-player net-delta application through the vault.
fn apply_deltas_through_vault(
    vault_addr: ContractAddress,
    players: Span<ContractAddress>,
    deltas: Span<i128>,
) {
    let mut m: u32 = 0;
    while m < players.len() {
        let player = *players.at(m);
        let delta = *deltas.at(m);
        let vault = super::IVaultDispatcherDispatcher { contract_address: vault_addr };
        vault.apply_settlement(player, delta);
        m += 1;
    }
}

/// Shared registration read: the (settlement_digest, g_attestation, flag)
/// tuple read + flag assert, deduplicated across the settle entries
/// (one shared copy of the tuple-read code, not three).
fn read_registered_digest(self: @ContractState, hand_binding: felt252) -> felt252 {
    let (registered_digest, _g_attestation, registered_flag) =
        self.bindings.read(hand_binding);
    assert!(registered_flag == 1, "Binding not registered");
    registered_digest
}

/// Shared v3/create_proof 公开段校验（P2-M6 抽取：两笔交易跑同一组
/// 完整性断言，防 create_proof 消息与结算 calldata 漂移）。返回注册的
/// settlement digest。
fn validate_settlement_segment(
    self: @ContractState,
    hand_binding: felt252,
    hand_id: u64,
    segment: Span<felt252>,
) -> felt252 {
    assert!(hand_binding != 0, "Zero binding");
    assert!(segment.len() == SETTLEMENT_SEGMENT_LEN, "Segment length mismatch");
    assert!(
        *segment.at(0) == SETTLEMENT_SEGMENT_MAGIC,
        "Segment magic mismatch"
    );
    assert!(*segment.at(1) == hand_id.into(), "Segment hand_id mismatch");
    assert!(*segment.at(4) == hand_binding, "Segment binding mismatch");
    let n: u32 = (*segment.at(3)).try_into().expect('n fits u32');
    assert!(n >= 2_u32 && n <= 9_u32, "Participant count out of range");
    let registered_digest = read_registered_digest(self, hand_binding);
    assert!(*segment.at(2) == registered_digest, "Segment digest mismatch");
    assert!(
        *segment.at(15) == self.action_logs.read(hand_binding),
        "Segment action log mismatch"
    );
    registered_digest
}

/// Shared settle-entry preamble: binding sanity, players/deltas bounds and
/// replay protection.
fn assert_settle_common(
    self: @ContractState,
    hand_binding: felt252,
    players: Span<ContractAddress>,
    deltas: Span<i128>,
) {
    assert!(hand_binding != 0, "Zero binding");
    assert!(players.len() == deltas.len(), "Players/deltas mismatch");
    assert!(players.len() > 0_u32, "No participants");
    assert!(players.len() < 10_u32, "Too many participants");
    assert!(!self.settled_bindings.read(hand_binding), "Hand already settled");
}

/// Expected bucket counts are packed into one felt as
/// `n_reveal + n_leave·2^64 + n_recon·2^128` (each count < 2^64): one
/// scalar storage cell + one felt equality instead of a tuple read.
/// Packing is injective for any batch that can pass the fold: counts are
/// bounded by the actual payload length (a count ≥ 2^60 could never fit in
/// a real calldata Span), so distinct small triples give distinct integers
/// < 2^192 < P.
const EXPECTED_PACK_SHIFT: felt252 = 0x10000000000000000; // 2^64
const EXPECTED_PACK_SHIFT2: felt252 =
    0x100000000000000000000000000000000; // 2^128

fn pack_expected_counts(
    n_reveal: felt252,
    n_leave: felt252,
    n_recon: felt252,
) -> felt252 {
    n_reveal + n_leave * EXPECTED_PACK_SHIFT + n_recon * EXPECTED_PACK_SHIFT2
}

/// Shared registration write (deduplicates the dup-check, bindings tuple
/// write, action-log write, expected-counts write and event across
/// registration callers): the FIRST registration of a binding — linear or
/// proved — locks it.
fn write_registration(
    ref self: ContractState,
    hand_binding: felt252,
    settlement_digest: felt252,
    g_attestation: felt252,
    action_log_digest: felt252,
    expected_n_reveal: felt252,
    expected_n_leave: felt252,
    expected_n_recon: felt252,
) {
    let (existing_digest, _, existing_flag) = self.bindings.read(hand_binding);
    assert!(
        existing_flag == 0 && existing_digest == 0,
        "Binding already registered"
    );
    self.bindings.write(hand_binding, (settlement_digest, g_attestation, 1));
    self.action_logs.write(hand_binding, action_log_digest);
    self.expected_packed.write(
        hand_binding,
        pack_expected_counts(expected_n_reveal, expected_n_leave, expected_n_recon),
    );
    self.emit(HandRegistered { hand_binding, settlement_digest, g_attestation });
}

/// Shared DAPV prelude (linear + proved entries): common bounds/replay
/// checks, batch-domain binding, registration read and settlement-digest
/// recompute. Returns the registered digest.
fn dapv_prelude(
    self: @ContractState,
    hand_binding: felt252,
    hand_id_bytes: Span<u8>,
    hand_id: u64,
    action_log_digest: felt252,
    players: Span<ContractAddress>,
    deltas: Span<i128>,
) -> felt252 {
    assert_settle_common(self, hand_binding, players, deltas);
    assert!(
        bytes_to_felt(hand_id_bytes) == hand_binding,
        "Batch domain not bound to hand_binding"
    );
    let registered_digest = read_registered_digest(self, hand_binding);
    let computed = compute_settlement_digest(hand_id, action_log_digest, players, deltas);
    assert!(computed == registered_digest, "Settlement digest mismatch");
    registered_digest
}

    component!(path: OwnableComponent, storage: ownable, event: OwnableEvent);

    #[abi(embed_v0)]
    impl OwnableMixinImpl = OwnableComponent::OwnableMixinImpl<ContractState>;
    impl OwnableInternalImpl = OwnableComponent::InternalImpl<ContractState>;

    #[storage]
    struct Storage {
        /// Authorized operators (Phase 1: control G registration).
        provers: Map<ContractAddress, bool>,
        /// Vault contract holding chip balances.
        vault_address: ContractAddress,
        /// Registered bindings: binding → (settlement_digest, g_attestation,
        /// registered flag as 1).
        bindings: Map<felt252, (felt252, felt252, felt252)>,
        /// Completeness hardening: registered expected bucket counts,
        /// packed (see `pack_expected_counts`); 0 = unconstrained.
        expected_packed: Map<felt252, felt252>,
        /// Settled bindings (replay protection).
        settled_bindings: Map<felt252, bool>,
        /// Part A Phase 1: claim escrow helper receiving winners' pots.
        claim_helper: ContractAddress,
        /// (hand_binding, seat_index) → claim commitment
        /// `poseidon(pk_lo, pk_hi, hand_binding, amount_lo, amount_hi)`.
        claim_cms: Map<(felt252, u32), felt252>,
        /// (hand_binding, seat_index) → claimable amount.
        claim_amounts: Map<(felt252, u32), u256>,
        /// (hand_binding, seat_index) → consumed flag (anti double-claim).
        claims_consumed: Map<(felt252, u32), bool>,
        /// P2-M3：钉死的 settlement_private 电路 program hash（fact 绑定根）。
        circuit_program_hash: felt252,
        /// P2-M6：钉死的 Starknet 虚拟 OS（VIRTUAL_SNOS）program hash——
        /// SNIP-36 proof_facts[2] 的绑定根（注意：这是 Starknet 侧被证明
        /// 对象的程序哈希，与本方 settlement 电路哈希无关）。
        virtual_snos_program_hash: felt252,
        /// P2-M3：已登记的证明 fact（fact-registry 过渡形态）。
        settlement_facts: Map<felt252, bool>,
        /// P2-M3：v2 手的金额藏在 cm 中（consume_claim 走隐藏模式）。
        amounts_hidden: Map<felt252, bool>,
        /// register_hand_proved 钉住的 p_batch 承诺/长度（hand_verify 绑定根）。
        p_batch_commitments: Map<felt252, felt252>,
        p_batch_lens: Map<felt252, u32>,
        /// hand_verify（hand_batch σ 批量校验 STARK）的 program hash。
        hand_verify_program_hash: felt252,
        /// 合并信封（P 层 + settlement 一份证明）的 program hash。
        combined_program_hash: felt252,
        /// #18 Phase B：注册时钉住的每手动作日志承诺
        /// （v2 公开段尾词必须逐 felt 等于该值）。
        action_logs: Map<felt252, felt252>,
        /// fold 链注册面：roster_digest → 已注册（键 = fold 公开段
        /// segment[17] 的值本身——电路输出词即注册成员证明）。
        roster_registry: Map<felt252, bool>,
        /// fold 链程序哈希（fold 入口 fact 绑定根，与 combined_program_hash
        /// 分槽——两链禁混批 D3c 第 2 层的承重件）。
        fold_program_hash: felt252,
        #[substorage(v0)]
        ownable: OwnableComponent::Storage,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        #[flat]
        OwnableEvent: OwnableComponent::Event,
        HandRegistered: HandRegistered,
        DualProofSettled: DualProofSettled,
        ProverSet: ProverSet,
        ClaimHelperSet: ClaimHelperSet,
        DualProofSettledPrivate: DualProofSettledPrivate,
        ClaimConsumed: ClaimConsumed,
        SettlementFactRegistered: SettlementFactRegistered,
        DualProofSettledPrivateV2: DualProofSettledPrivateV2,
        DualProofSettledProvedPrivate: DualProofSettledProvedPrivate,
        DualProofSettledSnip36: DualProofSettledSnip36,
        DualProofSettledCombined: DualProofSettledCombined,
        RosterRegistered: RosterRegistered,
        DualProofSettledFold: DualProofSettledFold,
    }

    #[derive(Drop, starknet::Event)]
    struct ClaimHelperSet {
        helper: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    struct DualProofSettledPrivate {
        hand_binding: felt252,
        settlement_digest: felt252,
        participant_count: u32,
        total_winnings: u256,
    }

    #[derive(Drop, starknet::Event)]
    struct ClaimConsumed {
        hand_binding: felt252,
        seat_index: u32,
        amount: u256,
    }

    #[derive(Drop, starknet::Event)]
    struct SettlementFactRegistered {
        fact: felt252,
    }

    #[derive(Drop, starknet::Event)]
    struct DualProofSettledPrivateV2 {
        hand_binding: felt252,
        settlement_digest: felt252,
        participant_count: u32,
        total_winnings: u256,
    }

    #[derive(Drop, starknet::Event)]
    struct DualProofSettledProvedPrivate {
        hand_binding: felt252,
        settlement_digest: felt252,
        participant_count: u32,
        p_batch_commitment: felt252,
        total_winnings: u256,
    }

    #[derive(Drop, starknet::Event)]
    struct DualProofSettledCombined {
        hand_binding: felt252,
        settlement_digest: felt252,
        participant_count: u32,
        /// 合并信封公开输出的累计承诺链值（PCD 链尾锚，第三方复验入口）。
        chain_acc: felt252,
        total_winnings: u256,
    }

    /// roster 注册事件：pks 全文随事件可取，供玩家自核注册面
    /// （规格 out/fold-spec.md §4.2 / 提案 F-4 纪律的取数入口）。
    #[derive(Drop, starknet::Event)]
    struct RosterRegistered {
        table_id: u64,
        n: felt252,
        roster_digest: felt252,
        pks: Span<felt252>,
    }

    /// fold 批结算事件：DualProofSettledCombined 加 roster_digest 一字段
    /// （规格 §4.4 表 #13）。
    #[derive(Drop, starknet::Event)]
    struct DualProofSettledFold {
        hand_binding: felt252,
        settlement_digest: felt252,
        participant_count: u32,
        /// fold 链累计承诺（公开段 word 0，fold 链自己的 PCD 锚）。
        chain_acc: felt252,
        /// 本批 roster 承诺（公开段 word 16，已对照注册面）。
        roster_digest: felt252,
        total_winnings: u256,
    }

    #[derive(Drop, starknet::Event)]
    struct DualProofSettledSnip36 {
        hand_binding: felt252,
        settlement_digest: felt252,
        participant_count: u32,
        /// 验证门路径：true = SNIP-36 协议内验证；false = fact-registry 降级。
        via_snip36: bool,
        total_winnings: u256,
    }

    #[derive(Drop, starknet::Event)]
    struct HandRegistered {
        hand_binding: felt252,
        settlement_digest: felt252,
        g_attestation: felt252,
    }

    #[derive(Drop, starknet::Event)]
    struct DualProofSettled {
        hand_binding: felt252,
        settlement_digest: felt252,
        participant_count: u32,
        p_proofs_verified: u32,
    }

    #[derive(Drop, starknet::Event)]
    struct ProverSet {
        prover: ContractAddress,
        authorized: bool,
    }

    #[constructor]
    fn constructor(
        ref self: ContractState,
        owner: ContractAddress,
        vault_address: ContractAddress,
        initial_prover: ContractAddress,
    ) {
        self.ownable.initializer(owner);
        self.vault_address.write(vault_address);
        if !initial_prover.is_zero() {
            self.provers.write(initial_prover, true);
        }
    }

    #[abi(embed_v0)]
    impl IPokerDualSettlementImpl of super::IPokerDualSettlement<ContractState> {
        fn register_hand(
            ref self: ContractState,
            hand_binding: felt252,
            settlement_digest: felt252,
            g_attestation: felt252,
            action_log_digest: felt252,
            expected_n_reveal: felt252,
            expected_n_leave: felt252,
            expected_n_recon: felt252,
        ) {
            let caller = starknet::get_caller_address();
            assert!(self.provers.read(caller), "Caller not authorized prover");
            assert!(hand_binding != 0, "Zero binding");
            write_registration(
                ref self,
                hand_binding,
                settlement_digest,
                g_attestation,
                action_log_digest,
                expected_n_reveal,
                expected_n_leave,
                expected_n_recon,
            );
        }

        fn verify_and_settle_dapv_stark(
            ref self: ContractState,
            hand_binding: felt252,
            hand_id_bytes: Span<u8>,
            hand_id: u64,
            action_log_digest: felt252,
            players: Span<ContractAddress>,
            deltas: Span<i128>,
            p_batch: Span<felt252>,
        ) {
            let registered_digest = dapv_prelude(
                @self, hand_binding, hand_id_bytes, hand_id, action_log_digest, players, deltas,
            );

            assert!(p_batch.len() >= 1_u32, "Empty batch");
            let n_own: u32 = (*p_batch.at(0)).try_into().expect('n_own fits u32');
            assert!(
                n_own == players.len(),
                "Every participant needs an endorsement"
            );

            // Completeness hardening (pk binding): the ownership bucket pks
            // must be pairwise DISTINCT — without this, one player's
            // endorsement could be repeated to pad `n_own` up to
            // players.len(). O(n²) compares on pk_x; n_own < 10 so this is
            // trivial cost. NOTE: full pk↔player-address binding needs a
            // player→pk registry which does not exist yet (known seam —
            // deliberately not invented here). Cursors advance by 5 (one
            // own-entry stride) instead of recomputing 5+5*i per compare.
            let own_end: u32 = 5 + 5 * n_own;
            // audit C1：ownership 去重循环读取 [5, own_end) 前先钉住长度，
            // 否则构造端 batch_words 缺词时 Span::at 越界 panic → 结算交易
            // 持续 revert（该手链上结算丢失）。
            assert!(p_batch.len() >= own_end, "batch too short for ownership");
            let mut a_off: u32 = 5;
            while a_off < own_end {
                let mut b_off: u32 = a_off + 5;
                while b_off < own_end {
                    assert!(
                        *p_batch.at(a_off) != *p_batch.at(b_off),
                        "Duplicate ownership pk"
                    );
                    b_off += 5;
                }
                a_off += 5;
            }

            // Completeness hardening (expected bucket counts): when the
            // registrar pinned non-zero expected counts, the submitted
            // batch header must match. The three counts are stored and
            // compared as ONE packed felt (n_reveal + n_leave·2^64 +
            // n_recon·2^128 — counts are < 2^64), both to keep the storage
            // read scalar and the comparison a single felt equality; an
            // all-zero packed value = unconstrained (legacy default, keeps
            // existing registrations working).
            let expected_packed = self.expected_packed.read(hand_binding);
            let header_packed = *p_batch.at(2)
                + *p_batch.at(3) * EXPECTED_PACK_SHIFT
                + *p_batch.at(4) * EXPECTED_PACK_SHIFT2;
            assert!(
                expected_packed == 0 || header_packed == expected_packed,
                "Bucket counts != registered expectation"
            );

            assert!(
                verify_hand_batch_stark(hand_binding, p_batch),
                "DAPV STARK batch rejected"
            );

            assert_zero_sum(deltas);

            let vault_addr = self.vault_address.read();
            apply_deltas_through_vault(vault_addr, players, deltas);

            self.settled_bindings.write(hand_binding, true);
            self.emit(
                DualProofSettled {
                    hand_binding,
                    settlement_digest: registered_digest,
                    participant_count: players.len(),
                    p_proofs_verified: n_own,
                },
            );
        }

        /// Proved-mode settlement (see the interface doc for the honest
        /// interim trust model): p_batch stays off-chain; the caller must
        /// be a whitelisted prover and must present exactly the
        /// (p_batch_commitment, p_batch_len) recorded at registration.
        ///
        /// Everything the linear entry checks inside the batch — the ρ-fold
        /// residual, distinct ownership pks, `n_own == players.len()` and
        /// the expected bucket counts stored below — is attested by the
        /// prover OFF-CHAIN; a future STARK fact-registry / SNIP-36
        /// verifier replaces the whitelist with proof verification.
        fn set_prover(ref self: ContractState, prover: ContractAddress) {
            self.ownable.assert_only_owner();
            if !prover.is_zero() {
                self.provers.write(prover, true);
                self.emit(ProverSet { prover, authorized: true });
            }
        }

        fn remove_prover(ref self: ContractState, prover: ContractAddress) {
            self.ownable.assert_only_owner();
            self.provers.write(prover, false);
            self.emit(ProverSet { prover, authorized: false });
        }

        fn is_prover(self: @ContractState, prover: ContractAddress) -> bool {
            self.provers.read(prover)
        }

        fn hand_binding(self: @ContractState, binding: felt252) -> (felt252, felt252, felt252) {
            self.bindings.read(binding)
        }

        fn hand_settled(self: @ContractState, binding: felt252) -> bool {
            self.settled_bindings.read(binding)
        }

        fn vault(self: @ContractState) -> ContractAddress {
            self.vault_address.read()
        }

        fn hand_action_log(self: @ContractState, binding: felt252) -> felt252 {
            self.action_logs.read(binding)
        }

        fn set_claim_helper(ref self: ContractState, helper: ContractAddress) {
            self.ownable.assert_only_owner();
            self.claim_helper.write(helper);
            self.emit(ClaimHelperSet { helper });
        }

        /// Part A Phase 1 隐私结算（见接口文档）。DAPV 校验逐字复用
        /// `verify_and_settle_dapv_stark` 的路径；派奖按赢家/输家分流。
        fn verify_and_settle_dapv_stark_private(
            ref self: ContractState,
            hand_binding: felt252,
            hand_id_bytes: Span<u8>,
            hand_id: u64,
            action_log_digest: felt252,
            players: Span<ContractAddress>,
            deltas: Span<i128>,
            p_batch: Span<felt252>,
        ) {
            let registered_digest = dapv_prelude(
                @self, hand_binding, hand_id_bytes, hand_id, action_log_digest, players, deltas,
            );

            assert!(p_batch.len() >= 1_u32, "Empty batch");
            let n_own: u32 = (*p_batch.at(0)).try_into().expect('n_own fits u32');
            assert!(
                n_own == players.len(),
                "Every participant needs an endorsement"
            );
            assert!(
                verify_hand_batch_stark(hand_binding, p_batch),
                "DAPV STARK batch rejected"
            );

            assert_zero_sum(deltas);

            // 派奖分流：输家公开扣款（Phase 1 残余）；赢家进认领托管。
            let vault_addr = self.vault_address.read();
            let helper = self.claim_helper.read();
            assert!(!helper.is_zero(), "Claim helper not set");
            let mut total_winnings: u256 = 0;
            let mut i: u32 = 0;
            while i < players.len() {
                let player = *players.at(i);
                let delta = *deltas.at(i);
                if delta > 0_i128 {
                    // 赢家：公开 chip 余额不动，改为写认领承诺并 funding 托管。
                    let delta_u64: u64 = delta.try_into().expect('win fits u64');
                    let amount: u256 = delta_u64.into();
                    let vault = super::IVaultDispatcherDispatcher { contract_address: vault_addr };
                    let commitment = vault.payout_commitment(player);
                    assert!(commitment != 0, "Payout commitment not registered");
                    // cm = poseidon(commitment, hand_binding, amount_lo, amount_hi)：
                    // 认领方须揭示 commitment 的原像 secret（capability 模型）。
                    let cm = poseidon_hash_span(
                        array![
                            commitment,
                            hand_binding,
                            amount.low.into(),
                            amount.high.into()
                        ]
                        .span(),
                    );
                    self.claim_cms.write((hand_binding, i), cm);
                    self.claim_amounts.write((hand_binding, i), amount);
                    self.claims_consumed.write((hand_binding, i), false);
                    total_winnings += amount;
                } else if delta < 0_i128 {
                    // 输家：公开扣款（Phase 1 已知残余，Phase 2 ZK 消除）。
                    let vault = super::IVaultDispatcherDispatcher { contract_address: vault_addr };
                    vault.apply_settlement(player, delta);
                }
                i += 1;
            }
            assert!(total_winnings > 0_u256, "No winnings to escrow");
            let vault = super::IVaultDispatcherDispatcher { contract_address: vault_addr };
            vault.settlement_fund_escrow(helper, hand_binding, total_winnings);

            self.settled_bindings.write(hand_binding, true);
            self.emit(
                DualProofSettledPrivate {
                    hand_binding,
                    settlement_digest: registered_digest,
                    participant_count: players.len(),
                    total_winnings,
                },
            );
        }

        fn claim_cm(self: @ContractState, hand_binding: felt252, seat_index: u32) -> felt252 {
            self.claim_cms.read((hand_binding, seat_index))
        }

        fn claim_amount(
            self: @ContractState,
            hand_binding: felt252,
            seat_index: u32,
        ) -> u256 {
            self.claim_amounts.read((hand_binding, seat_index))
        }

        fn consume_claim(
            ref self: ContractState,
            hand_binding: felt252,
            seat_index: u32,
            amount: u256,
        ) {
            let caller = starknet::get_caller_address();
            assert!(caller == self.claim_helper.read(), "Only claim helper");
            let expected = self.claim_amounts.read((hand_binding, seat_index));
            assert!(expected == amount, "Claim amount mismatch");
            assert!(
                !self.claims_consumed.read((hand_binding, seat_index)),
                "Claim already consumed"
            );
            self.claims_consumed.write((hand_binding, seat_index), true);
            self.emit(ClaimConsumed { hand_binding, seat_index, amount });
        }

        fn claim_helper(self: @ContractState) -> ContractAddress {
            self.claim_helper.read()
        }

        fn set_circuit_program_hash(ref self: ContractState, program_hash: felt252) {
            self.ownable.assert_only_owner();
            assert!(program_hash != 0, "Zero program hash");
            self.circuit_program_hash.write(program_hash);
        }

        fn set_virtual_snos_program_hash(ref self: ContractState, program_hash: felt252) {
            self.ownable.assert_only_owner();
            assert!(program_hash != 0, "Zero program hash");
            self.virtual_snos_program_hash.write(program_hash);
        }

        fn virtual_snos_program_hash(self: @ContractState) -> felt252 {
            self.virtual_snos_program_hash.read()
        }

        /// P2-M6：SNIP-36 create_proof 形态（被证明的第一笔交易）。校验
        /// 公开段后发出 `to=0、payload=segment` 的 L2→L1 消息——虚拟执行中
        /// 其哈希进入 proof_facts[8]（`snip36_message_hash` 同式），把证明
        /// 绑定到本手公开段。不写存储、不结算：结算只发生在携带 proof 的
        /// v3 第二笔交易（防重放：重复证明同一手只多付一次证明费，无状态
        /// 影响；submit 侧由 v3 的 settled_bindings 门兜底）。
        fn emit_settlement_proof_message(
            ref self: ContractState,
            hand_binding: felt252,
            hand_id: u64,
            segment: Span<felt252>,
        ) {
            validate_settlement_segment(@self, hand_binding, hand_id, segment);
            send_message_to_l1_syscall(
                to_address: Zero::zero(), payload: segment,
            )
            .unwrap_syscall();
        }

        fn register_settlement_fact(ref self: ContractState, fact: felt252) {
            let caller = starknet::get_caller_address();
            assert!(
                caller == self.ownable.owner() || self.provers.read(caller),
                "Caller not authorized"
            );
            assert!(fact != 0, "Zero fact");
            self.settlement_facts.write(fact, true);
            self.emit(SettlementFactRegistered { fact });
        }

        fn circuit_program_hash(self: @ContractState) -> felt252 {
            self.circuit_program_hash.read()
        }

        fn settlement_fact(self: @ContractState, fact: felt252) -> bool {
            self.settlement_facts.read(fact)
        }

        fn amounts_hidden(self: @ContractState, hand_binding: felt252) -> bool {
            self.amounts_hidden.read(hand_binding)
        }

        /// Owner-gated：钉死 hand_verify（hand_batch σ 批量校验）program hash。
        fn set_hand_verify_program_hash(ref self: ContractState, program_hash: felt252) {
            self.ownable.assert_only_owner();
            self.hand_verify_program_hash.write(program_hash);
        }

        /// Proved 私密结算注册：与 register_hand 同门（prover-gated）、
        /// 同一 write_registration（一次性），另钉 (p_batch_commitment,
        /// p_batch_len)。calldata 形状与 Rust ProvedSettlement.register_calldata
        /// 逐字对齐：[binding, digest, g_att, action_log, commitment, len,
        /// exp_reveal, exp_leave, exp_recon]。
        fn register_hand_proved(
            ref self: ContractState,
            hand_binding: felt252,
            settlement_digest: felt252,
            g_attestation: felt252,
            action_log_digest: felt252,
            p_batch_commitment: felt252,
            p_batch_len: felt252,
            expected_n_reveal: felt252,
            expected_n_leave: felt252,
            expected_n_recon: felt252,
        ) {
            let caller = starknet::get_caller_address();
            assert!(self.provers.read(caller), "Caller not authorized prover");
            assert!(hand_binding != 0, "Zero binding");
            write_registration(
                ref self,
                hand_binding,
                settlement_digest,
                g_attestation,
                action_log_digest,
                expected_n_reveal,
                expected_n_leave,
                expected_n_recon,
            );
            let len: u32 = p_batch_len.try_into().expect('batch len fits u32');
            self.p_batch_commitments.write(hand_binding, p_batch_commitment);
            self.p_batch_lens.write(hand_binding, len);
        }

        /// P2-M4：proved × private 双证明结算入口。
        /// (a) hand_verify fact = poseidon([hand_verify_program_hash,
        ///     p_batch_commitment])——校验「承诺下的 hand_batch σ 批量校验」
        ///     已由授权 prover 登记（证明工件在链下，fact 上链）；
        /// (b) stark verify fact = poseidon([circuit_program_hash, segment])——
        ///     settlement_private 电路对公开段的证明（与 v2 同锚）。
        /// 其余校验与派奖与 verify_and_settle_dapv_stark_private_v2 一致。
        fn verify_and_settle_dapv_proved_private(
            ref self: ContractState,
            hand_binding: felt252,
            hand_id: u64,
            segment: Span<felt252>,
            p_batch_commitment: felt252,
            p_batch_len: u32,
        ) {
            assert!(hand_binding != 0, "Zero binding");
            assert!(
                !self.settled_bindings.read(hand_binding),
                "Hand already settled"
            );
            assert!(segment.len() == SETTLEMENT_SEGMENT_LEN, "Segment length mismatch");
            assert!(
                *segment.at(0) == SETTLEMENT_SEGMENT_MAGIC,
                "Segment magic mismatch"
            );
            assert!(*segment.at(1) == hand_id.into(), "Segment hand_id mismatch");
            assert!(*segment.at(4) == hand_binding, "Segment binding mismatch");
            let n: u32 = (*segment.at(3)).try_into().expect('n fits u32');
            assert!(n >= 2_u32 && n <= 9_u32, "Participant count out of range");
            let registered_digest = read_registered_digest(@self, hand_binding);
            assert!(*segment.at(2) == registered_digest, "Segment digest mismatch");
            assert!(
                *segment.at(15) == self.action_logs.read(hand_binding),
                "Segment action log mismatch"
            );

            // —— 双证明之一：hand_verify 绑定到注册的 p_batch 承诺 ——
            let registered_commitment = self.p_batch_commitments.read(hand_binding);
            assert!(registered_commitment != 0, "p_batch commitment not registered");
            assert!(
                p_batch_commitment == registered_commitment,
                "p_batch commitment mismatch"
            );
            let registered_len: u32 = self.p_batch_lens.read(hand_binding);
            assert!(p_batch_len == registered_len, "p_batch length mismatch");
            let hv_program = self.hand_verify_program_hash.read();
            assert!(hv_program != 0, "Hand verify program hash not set");
            let mut hf = PoseidonTrait::new();
            hf = hf.update(hv_program);
            hf = hf.update(p_batch_commitment);
            assert!(
                self.settlement_facts.read(hf.finalize()),
                "Hand verify fact not registered"
            );

            // —— 双证明之二：stark verify 锚定公开段 ——
            let program_hash = self.circuit_program_hash.read();
            assert!(program_hash != 0, "Circuit program hash not set");
            let fact = fact_for_segment(program_hash, segment);
            assert!(
                self.settlement_facts.read(fact),
                "Settlement fact not registered"
            );

            // —— 私密派奖（与 v2 private 相同）——
            let total_u128: u128 = (*segment.at(14)).try_into().expect('total fits u128');
            let total_winnings: u256 = total_u128.into();
            assert!(total_winnings > 0_u256, "No winnings to escrow");
            let vault_addr = self.vault_address.read();
            let helper = self.claim_helper.read();
            assert!(!helper.is_zero(), "Claim helper not set");
            let vault = super::IVaultDispatcherDispatcher { contract_address: vault_addr };
            vault.settlement_fund_escrow(helper, hand_binding, total_winnings);
            let mut i: u32 = 0;
            while i < 9_u32 {
                self.claim_cms.write((hand_binding, i), *segment.at(5 + i));
                i += 1;
            }
            self.amounts_hidden.write(hand_binding, true);
            self.settled_bindings.write(hand_binding, true);
            self.emit(
                DualProofSettledProvedPrivate {
                    hand_binding,
                    settlement_digest: registered_digest,
                    participant_count: n,
                    p_batch_commitment,
                    total_winnings,
                },
            );
        }

        /// P2-M5：v3 双门——SNIP-36 协议内验证优先，fact-registry 降级。
        fn verify_and_settle_dapv_stark_private_v3(
            ref self: ContractState,
            hand_binding: felt252,
            hand_id: u64,
            segment: Span<felt252>,
        ) {
            assert!(
                !self.settled_bindings.read(hand_binding),
                "Hand already settled"
            );
            let registered_digest =
                validate_settlement_segment(@self, hand_binding, hand_id, segment);

            // ===== 双门：SNIP-36 优先（两笔交易模式：本笔携带 proof/proof_facts，
            // 前一笔 create_proof 交易已 emit_settlement_proof_message 并被
            // starknet_proveTransaction 证明）=====
            let virtual_hash = self.virtual_snos_program_hash.read();
            assert!(virtual_hash != 0, "Virtual SNOS program hash not set");
            let mut via_snip36 = false;
            let exec_info = get_execution_info_v3_syscall()
                .unwrap_syscall();
            // 类型不标注：get_execution_info_v3_syscall 返回 info::v3::ExecutionInfo，
            // 其 tx_info 为 v3::TxInfo（携带 proof_facts）；corelib 的 info 模块
            // 私有、仅选择性再导出 v2（starknet::TxInfo=v2，无 proof_facts），
            // 标注 v2 会类型错配——推断直接落 v3（cairo ≥2.15）。
            let tx_info = exec_info.tx_info.unbox();
            let facts: Span<felt252> = tx_info.proof_facts;
            if facts.len() >= 9 {
                // facts[1] = program variant（"VIRTUAL_SNOS"）；facts[2] =
                // 虚拟 OS program hash（Starknet 侧被证明对象，非本方电路）；
                // facts[8] = 首条 L2→L1 消息哈希（payload = segment）
                if *facts.at(1) == VIRTUAL_SNOS_VARIANT
                    && *facts.at(2) == virtual_hash
                    && *facts.at(8) == snip36_message_hash(
                        starknet::get_contract_address(), segment,
                    )
                {
                    via_snip36 = true;
                }
            }
            if !via_snip36 {
                // 降级门：fact-registry（v2 同款）
                let program_hash = self.circuit_program_hash.read();
                assert!(program_hash != 0, "Circuit program hash not set");
                let fact = fact_for_segment(program_hash, segment);
                assert!(
                    self.settlement_facts.read(fact),
                    "Settlement fact not registered"
                );
            }

            // ===== 派奖（与 v2 完全一致）=====
            let n: u32 = (*segment.at(3)).try_into().expect('n fits u32');
            let total_u128: u128 = (*segment.at(14)).try_into().expect('total fits u128');
            let total_winnings: u256 = total_u128.into();
            assert!(total_winnings > 0_u256, "No winnings to escrow");
            let vault_addr = self.vault_address.read();
            let helper = self.claim_helper.read();
            assert!(!helper.is_zero(), "Claim helper not set");
            let vault = super::IVaultDispatcherDispatcher { contract_address: vault_addr };
            vault.settlement_fund_escrow(helper, hand_binding, total_winnings);
            let mut i: u32 = 0;
            while i < 9_u32 {
                self.claim_cms.write((hand_binding, i), *segment.at(5 + i));
                i += 1;
            }
            self.amounts_hidden.write(hand_binding, true);
            self.settled_bindings.write(hand_binding, true);
            self.emit(
                DualProofSettledSnip36 {
                    hand_binding,
                    settlement_digest: registered_digest,
                    participant_count: n,
                    via_snip36,
                    total_winnings,
                },
            );
        }

        /// P2-M3：零明文结算（见接口文档）。digest 取注册值，托管金额与
        /// claim_cms 全部来自已证明的公开段。
        fn verify_and_settle_dapv_stark_private_v2(
            ref self: ContractState,
            hand_binding: felt252,
            hand_id: u64,
            segment: Span<felt252>,
        ) {
            assert!(hand_binding != 0, "Zero binding");
            assert!(
                !self.settled_bindings.read(hand_binding),
                "Hand already settled"
            );
            assert!(segment.len() == SETTLEMENT_SEGMENT_LEN, "Segment length mismatch");
            assert!(
                *segment.at(0) == SETTLEMENT_SEGMENT_MAGIC,
                "Segment magic mismatch"
            );
            assert!(*segment.at(1) == hand_id.into(), "Segment hand_id mismatch");
            assert!(*segment.at(4) == hand_binding, "Segment binding mismatch");
            let n: u32 = (*segment.at(3)).try_into().expect('n fits u32');
            assert!(n >= 2_u32 && n <= 9_u32, "Participant count out of range");
            // digest 取 register_aggregate 时的注册值（无明文参与比对）
            let registered_digest = read_registered_digest(@self, hand_binding);
            assert!(*segment.at(2) == registered_digest, "Segment digest mismatch");
            // #18 Phase B：公开段尾词（动作日志哈希）必须等于注册承诺——
            // 把零明文结算锚定到注册时刻钉住的动作日志（审计/auto 标记）。
            assert!(
                *segment.at(15) == self.action_logs.read(hand_binding),
                "Segment action log mismatch"
            );
            // fact-registry 锚：fact = poseidon([program_hash ++ segment])，
            // 由授权 prover/owner 在 prove-hand 之后登记。
            let program_hash = self.circuit_program_hash.read();
            assert!(program_hash != 0, "Circuit program hash not set");
            let fact = fact_for_segment(program_hash, segment);
            assert!(
                self.settlement_facts.read(fact),
                "Settlement fact not registered"
            );

            let total_u128: u128 = (*segment.at(14)).try_into().expect('total fits u128');
            let total_winnings: u256 = total_u128.into();
            assert!(total_winnings > 0_u256, "No winnings to escrow");
            let vault_addr = self.vault_address.read();
            let helper = self.claim_helper.read();
            assert!(!helper.is_zero(), "Claim helper not set");
            let vault = super::IVaultDispatcherDispatcher { contract_address: vault_addr };
            vault.settlement_fund_escrow(helper, hand_binding, total_winnings);
            let mut i: u32 = 0;
            while i < 9_u32 {
                self.claim_cms.write((hand_binding, i), *segment.at(5 + i));
                i += 1;
            }
            self.amounts_hidden.write(hand_binding, true);
            self.settled_bindings.write(hand_binding, true);
            self.emit(
                DualProofSettledPrivateV2 {
                    hand_binding,
                    settlement_digest: registered_digest,
                    participant_count: n,
                    total_winnings,
                },
            );
        }

        fn set_combined_program_hash(ref self: ContractState, program_hash: felt252) {
            self.ownable.assert_only_owner();
            assert!(program_hash != 0, "Zero program hash");
            self.combined_program_hash.write(program_hash);
        }

        fn combined_program_hash(self: @ContractState) -> felt252 {
            self.combined_program_hash.read()
        }

        /// fold 链注册面（规格 out/fold-spec.md §4.2）：owner-gated +
        /// 链上重算 roster_digest（与电路公式同源）+ 一次性写入。
        fn register_roster(
            ref self: ContractState,
            table_id: u64,
            n: felt252,
            pks: Span<felt252>,
        ) {
            self.ownable.assert_only_owner();
            let n_u32: u32 = n.try_into().expect('n fits u32');
            assert!(n_u32 >= 2_u32 && n_u32 <= 9_u32, "Participant count out of range");
            assert!(pks.len() == 2 * n_u32, "Roster pks length mismatch");
            // 与 fold_batch.cairo 电路 ROSTER_LABEL 常量同式：poseidon([LABEL, n] ++ pks)。
            let mut roster_in: Array<felt252> = array![ROSTER_LABEL, n];
            let mut w: u32 = 0;
            while w < pks.len() {
                roster_in.append(*pks.at(w));
                w += 1;
            }
            let roster_digest = poseidon_hash_span(roster_in.span());
            // 一次性：注册值不可改写（键 = 电路公开输出词本身）。
            assert!(
                !self.roster_registry.read(roster_digest),
                "Roster already registered"
            );
            self.roster_registry.write(roster_digest, true);
            self.emit(RosterRegistered { table_id, n, roster_digest, pks });
        }

        fn roster_registered(self: @ContractState, roster_digest: felt252) -> bool {
            self.roster_registry.read(roster_digest)
        }

        /// Owner-gated：钉死 fold 批程序的 program hash（逐字复刻
        /// set_combined_program_hash 模式：owner + 非零断言 + 独立存储槽）。
        fn set_fold_program_hash(ref self: ContractState, program_hash: felt252) {
            self.ownable.assert_only_owner();
            assert!(program_hash != 0, "Zero program hash");
            self.fold_program_hash.write(program_hash);
        }

        fn fold_program_hash(self: @ContractState) -> felt252 {
            self.fold_program_hash.read()
        }

        /// 合并信封私密结算：17 词公开段（v2 段前置 chain_acc）+ 单 fact 门。
        /// 字段校验与 v2 逐项对齐（索引 +1）；chain_acc 随事件 emit。
        fn verify_and_settle_dapv_combined_private(
            ref self: ContractState,
            hand_binding: felt252,
            hand_id: u64,
            segment: Span<felt252>,
        ) {
            assert!(hand_binding != 0, "Zero binding");
            assert!(
                !self.settled_bindings.read(hand_binding),
                "Hand already settled"
            );
            assert!(
                segment.len() == COMBINED_SEGMENT_LEN,
                "Segment length mismatch"
            );
            assert!(
                *segment.at(1) == SETTLEMENT_SEGMENT_MAGIC,
                "Segment magic mismatch"
            );
            assert!(*segment.at(2) == hand_id.into(), "Segment hand_id mismatch");
            assert!(*segment.at(5) == hand_binding, "Segment binding mismatch");
            let n: u32 = (*segment.at(4)).try_into().expect('n fits u32');
            assert!(n >= 2_u32 && n <= 9_u32, "Participant count out of range");
            let registered_digest = read_registered_digest(@self, hand_binding);
            assert!(*segment.at(3) == registered_digest, "Segment digest mismatch");
            assert!(
                *segment.at(16) == self.action_logs.read(hand_binding),
                "Segment action log mismatch"
            );
            // 单 fact 门：合并证明（P 层 + settlement）锚定整段 17 词。
            let program_hash = self.combined_program_hash.read();
            assert!(program_hash != 0, "Combined program hash not set");
            let fact = fact_for_segment(program_hash, segment);
            assert!(
                self.settlement_facts.read(fact),
                "Settlement fact not registered"
            );
            let chain_acc = *segment.at(0);

            let total_u128: u128 = (*segment.at(15)).try_into().expect('total fits u128');
            let total_winnings: u256 = total_u128.into();
            assert!(total_winnings > 0_u256, "No winnings to escrow");
            let vault_addr = self.vault_address.read();
            let helper = self.claim_helper.read();
            assert!(!helper.is_zero(), "Claim helper not set");
            let vault = super::IVaultDispatcherDispatcher { contract_address: vault_addr };
            vault.settlement_fund_escrow(helper, hand_binding, total_winnings);
            let mut i: u32 = 0;
            while i < 9_u32 {
                self.claim_cms.write((hand_binding, i), *segment.at(6 + i));
                i += 1;
            }
            self.amounts_hidden.write(hand_binding, true);
            self.settled_bindings.write(hand_binding, true);
            self.emit(
                DualProofSettledCombined {
                    hand_binding,
                    settlement_digest: registered_digest,
                    participant_count: n,
                    chain_acc,
                    total_winnings,
                },
            );
        }

        /// fold 批私密结算：18 词公开段（combined 17 词信封 + 尾插
        /// roster_digest）。校验序列与 combined 入口逐项同构，仅两处增量：
        /// 段长 18（FOLD_SEGMENT_LEN）与 segment[17] 对照 roster 注册面
        /// （规格 out/fold-spec.md §4.4 #10——C1 的闭合点）。fact 门复用
        /// settlement_facts（不新增 ACL），绑 fold_program_hash 分槽哈希。
        fn verify_and_settle_dapv_fold_private(
            ref self: ContractState,
            hand_binding: felt252,
            hand_id: u64,
            segment: Span<felt252>,
        ) {
            assert!(hand_binding != 0, "Zero binding");
            assert!(
                !self.settled_bindings.read(hand_binding),
                "Hand already settled"
            );
            assert!(
                segment.len() == FOLD_SEGMENT_LEN,
                "Segment length mismatch"
            );
            assert!(
                *segment.at(1) == SETTLEMENT_SEGMENT_MAGIC,
                "Segment magic mismatch"
            );
            assert!(*segment.at(2) == hand_id.into(), "Segment hand_id mismatch");
            assert!(*segment.at(5) == hand_binding, "Segment binding mismatch");
            let n: u32 = (*segment.at(4)).try_into().expect('n fits u32');
            assert!(n >= 2_u32 && n <= 9_u32, "Participant count out of range");
            let registered_digest = read_registered_digest(@self, hand_binding);
            assert!(*segment.at(3) == registered_digest, "Segment digest mismatch");
            assert!(
                *segment.at(16) == self.action_logs.read(hand_binding),
                "Segment action log mismatch"
            );
            // —— fold 增量 1：roster 对照（段尾词必须已注册且非零）——
            let roster_digest = *segment.at(17);
            assert!(
                roster_digest != 0 && self.roster_registry.read(roster_digest),
                "Roster not registered"
            );
            // —— fact 门：fold 哈希分槽（两链禁混批 D3c 第 2/3 层）——
            let program_hash = self.fold_program_hash.read();
            assert!(program_hash != 0, "Fold program hash not set");
            let fact = fact_for_segment(program_hash, segment);
            assert!(
                self.settlement_facts.read(fact),
                "Settlement fact not registered"
            );
            let chain_acc = *segment.at(0);

            // —— 派奖：与 combined 入口同构 ——
            let total_u128: u128 = (*segment.at(15)).try_into().expect('total fits u128');
            let total_winnings: u256 = total_u128.into();
            assert!(total_winnings > 0_u256, "No winnings to escrow");
            let vault_addr = self.vault_address.read();
            let helper = self.claim_helper.read();
            assert!(!helper.is_zero(), "Claim helper not set");
            let vault = super::IVaultDispatcherDispatcher { contract_address: vault_addr };
            vault.settlement_fund_escrow(helper, hand_binding, total_winnings);
            let mut i: u32 = 0;
            while i < 9_u32 {
                self.claim_cms.write((hand_binding, i), *segment.at(6 + i));
                i += 1;
            }
            self.amounts_hidden.write(hand_binding, true);
            self.settled_bindings.write(hand_binding, true);
            self.emit(
                DualProofSettledFold {
                    hand_binding,
                    settlement_digest: registered_digest,
                    participant_count: n,
                    chain_acc,
                    roster_digest,
                    total_winnings,
                },
            );
        }
    }
}


/// Minimal vault interface consumed by the settlement contract.
#[starknet::interface]
pub trait IVaultDispatcher<TContractState> {
    fn apply_settlement(ref self: TContractState, player: ContractAddress, delta: i128);
    /// Part A Phase 1: read the player's registered payout commitment.
    fn payout_commitment(self: @TContractState, player: ContractAddress) -> felt252;
    /// Part A Phase 1: fund the claim escrow with the winners' pot.
    fn settlement_fund_escrow(
        ref self: TContractState,
        escrow: ContractAddress,
        hand_binding: felt252,
        amount: u256,
    );
}

// ============================================================
// Tests (snforge): mock vault + deploy through the dispatcher so
// register/settle run through the real prover-gate paths.
// ============================================================

// ============================================================
// Tests (snforge): P2-M3 零明文结算 v2 — fact-registry 锚定公开段。
// MockVault 记录 escrow 划转；register 用 prover 授权（test 合约即
// initial_prover）；电路公开段由测试内 Poseidon 复算（与 Cairo 电路
// 及 Rust 参考三方一致）。
// ============================================================

#[cfg(test)]
mod settlement_private_v2_tests {
    use core::hash::HashStateTrait;
    use core::poseidon::PoseidonTrait;
    use starknet::{ContractAddress, get_contract_address};
    use snforge_std::{ContractClassTrait, DeclareResultTrait, declare};

    use super::mock_vault::IMockVaultDispatcherTrait;
    use super::mock_vault::IMockVaultDispatcher;
    use super::{
        IPokerDualSettlement, IPokerDualSettlementDispatcher,
        IPokerDualSettlementDispatcherTrait,
    };

    const MAGIC: felt252 = 0x5350324d5f4f4b;
    const PROGRAM_HASH: felt252 = 0xabcdef;

    fn deploy_contract(name: ByteArray, calldata: @Array<felt252>) -> ContractAddress {
        let class = declare(name).unwrap().contract_class();
        let (address, _) = class.deploy(calldata).unwrap();
        address
    }

    struct Setup {
        dual: IPokerDualSettlementDispatcher,
        vault: IMockVaultDispatcher,
        hand_binding: felt252,
        digest: felt252,
        segment: Array<felt252>,
        total: felt252,
        /// 注册时钉住的动作日志承诺（#18 Phase B）。
        action_log: felt252,
    }

    /// 部署 mock vault + dual（test 合约为 owner 与 initial_prover），
    /// 注册 binding（digest=0x99..、action_log=0xA11CE）、钉 program hash，
    /// 构造诚实公开段并登记 fact。`tamper` 可选：覆盖 segment 的 digest 槽。
    fn setup(tamper_digest: bool, with_fact: bool) -> Setup {
        let test_addr = get_contract_address();
        let vault = deploy_contract("MockVault", @array![]);
        let dual_addr = deploy_contract(
            "PokerDualSettlement",
            @array![test_addr.into(), vault.into(), test_addr.into()],
        );
        let dual = IPokerDualSettlementDispatcher { contract_address: dual_addr };
        dual.set_claim_helper(test_addr);
        dual.set_circuit_program_hash(PROGRAM_HASH);

        let hand_binding: felt252 = 0xBBBB;
        let hand_id: u64 = 42;
        let digest: felt252 = 0x9900;
        let action_log: felt252 = 0xA11CE;
        // 与 register_hand 一致的注册（prover = test_addr）
        dual.register_hand(hand_binding, digest, 0, action_log, 0, 0, 0);

        // 公开段：赢家 seat0（+3000），输家 seat1/2，其余零变动
        let mut cms = array![];
        let mut total: felt252 = 0;
        let commitment = 0x21;
        let binding = hand_binding;
        let mut i: u32 = 0;
        while i < 9_u32 {
            let (s, m): (felt252, felt252) = if i == 0 {
                (1, 3000)
            } else if i == 1 {
                (0, 2000)
            } else if i == 2 {
                (0, 1000)
            } else {
                (1, 0)
            };
            i += 1;
            if s == 1 {
                if m != 0 {
                    total += m;
                    let mut ch = PoseidonTrait::new();
                    ch = ch.update(commitment);
                    ch = ch.update(binding);
                    ch = ch.update(m);
                    ch = ch.update(0);
                    cms.append(ch.finalize());
                } else {
                    cms.append(0);
                };
            } else {
                cms.append(0);
            };
        }

        // tamper_digest：segment 的 digest 槽换成 0xDEAD（注册值仍是真 digest）
        let digest_in_segment: felt252 = if tamper_digest { 0xDEAD } else { digest };
        let mut segment = array![MAGIC, hand_id.into(), digest_in_segment, 3, binding];
        let mut w: u32 = 0;
        while w < 9_u32 {
            segment.append(*cms.at(w));
            w += 1;
        };
        segment.append(total);
        // #18 Phase B：公开段尾词 = 动作日志哈希（16 felt 段，cm×9）。
        segment.append(action_log);

        if with_fact {
            // fact = poseidon([program_hash ++ segment])（与合约公式一致）
            let mut f = PoseidonTrait::new();
            f = f.update(PROGRAM_HASH);
            let mut w: u32 = 0;
            while w < segment.len() {
                f = f.update(*segment.at(w));
                w += 1;
            }
            dual.register_settlement_fact(f.finalize());
        }

        Setup {
            dual,
            vault: IMockVaultDispatcher { contract_address: vault },
            hand_binding,
            digest,
            segment,
            total,
            action_log,
        }
    }

    #[test]
    fn v2_honest_segment_settles_without_plaintext_calldata() {
        let s = setup(false, true);
        // 注册承诺可见（view），公开段尾词与其一致
        assert!(s.dual.hand_action_log(s.hand_binding) == s.action_log, "action log view");
        assert!(*s.segment.at(15) == s.action_log, "segment tail is the action log");
        // v2 calldata：只有 (hand_binding, hand_id, segment)——无 players/deltas
        s.dual
            .verify_and_settle_dapv_stark_private_v2(s.hand_binding, 42, s.segment.span());
        assert!(s.dual.hand_settled(s.hand_binding), "hand must be settled");
        // claim_cms 来自公开段（seat0 = 赢家承诺）
        let mut ch = PoseidonTrait::new();
        ch = ch.update(0x21);
        ch = ch.update(s.hand_binding);
        ch = ch.update(3000);
        ch = ch.update(0);
        assert!(s.dual.claim_cm(s.hand_binding, 0) == ch.finalize(), "cm0");
        assert!(s.dual.claim_cm(s.hand_binding, 1) == 0, "non-winner cm must be zero");
        // 托管金额 = 公开段 total_winnings
        let total_u256: u256 = s.total.into();
        assert!(
            s.vault.escrowed_for(s.hand_binding) == total_u256,
            "escrow must equal total_winnings"
        );
    }

    #[test]
    #[should_panic(expected: "Segment digest mismatch")]
    fn v2_tampered_digest_reverts() {
        let s = setup(true, true);
        s.dual
            .verify_and_settle_dapv_stark_private_v2(s.hand_binding, 42, s.segment.span());
    }

    #[test]
    #[should_panic(expected: "Segment action log mismatch")]
    fn v2_tampered_action_log_reverts() {
        // #18 Phase B：公开段尾词 ≠ 注册承诺 → 拒绝（绑定注册时刻的动作日志）。
        let s = setup(false, true);
        // 重建整段：仅把尾词换成 0xFEED。
        let mut tampered_segment = array![];
        let mut w: u32 = 0;
        while w < s.segment.len() {
            let v = if w == 15_u32 { 0xFEED } else { *s.segment.at(w) };
            tampered_segment.append(v);
            w += 1;
        }
        // fact 锚覆盖整段：换词后必须重登记 fact 才能走到 action-log 断言。
        let mut f = PoseidonTrait::new();
        f = f.update(PROGRAM_HASH);
        let mut w: u32 = 0;
        while w < tampered_segment.len() {
            f = f.update(*tampered_segment.at(w));
            w += 1;
        }
        s.dual.register_settlement_fact(f.finalize());
        s.dual
            .verify_and_settle_dapv_stark_private_v2(s.hand_binding, 42, tampered_segment.span());
    }

    #[test]
    #[should_panic(expected: "Settlement fact not registered")]
    fn v2_missing_fact_reverts() {
        let s = setup(false, false);
        s.dual
            .verify_and_settle_dapv_stark_private_v2(s.hand_binding, 42, s.segment.span());
    }

    #[test]
    #[should_panic(expected: "Hand already settled")]
    fn v2_replay_reverts() {
        let s = setup(false, true);
        s.dual
            .verify_and_settle_dapv_stark_private_v2(s.hand_binding, 42, s.segment.span());
        s.dual
            .verify_and_settle_dapv_stark_private_v2(s.hand_binding, 42, s.segment.span());
    }
}

// ============================================================
// Tests (snforge): 合并信封结算——单 fact 门消费 17 词公开段
// （v2 段前置 chain_acc），派奖/幂等与 v2 一致。
// ============================================================

#[cfg(test)]
mod settlement_combined_private_tests {
    use core::hash::HashStateTrait;
    use core::poseidon::PoseidonTrait;
    use starknet::{ContractAddress, get_contract_address};
    use snforge_std::{ContractClassTrait, DeclareResultTrait, declare};
    use super::mock_vault::IMockVaultDispatcherTrait;
    use super::mock_vault::IMockVaultDispatcher;
    use super::{
        IPokerDualSettlement, IPokerDualSettlementDispatcher,
        IPokerDualSettlementDispatcherTrait,
    };

    const COMBINED_HASH: felt252 = 0xC0FFEE;
    const MAGIC: felt252 = 0x5350324d5f4f4b;

    fn deploy_contract(name: ByteArray, calldata: @Array<felt252>) -> ContractAddress {
        let class = declare(name).unwrap().contract_class();
        let (address, _) = class.deploy(calldata).unwrap();
        address
    }

    #[derive(Drop)]
    struct Setup {
        dual: IPokerDualSettlementDispatcher,
        vault: IMockVaultDispatcher,
        hand_binding: felt252,
        segment: Array<felt252>,
        total: felt252,
        chain_acc: felt252,
    }

    fn setup(with_fact: bool) -> Setup {
        let test_addr = get_contract_address();
        let vault = deploy_contract("MockVault", @array![]);
        let dual_addr = deploy_contract(
            "PokerDualSettlement",
            @array![test_addr.into(), vault.into(), test_addr.into()],
        );
        let dual = IPokerDualSettlementDispatcher { contract_address: dual_addr };
        dual.set_claim_helper(test_addr);
        dual.set_circuit_program_hash(0x1111);
        dual.set_combined_program_hash(COMBINED_HASH);

        let hand_binding: felt252 = 0xDDDD;
        let hand_id: u64 = 42;
        let digest: felt252 = 0x9900;
        let action_log: felt252 = 0xA11CE;
        dual.register_hand(hand_binding, digest, 0, action_log, 0, 0, 0);

        // 17 词合并段 = [chain_acc] ++ 16 词 v2 段（赢家 seat0 +3000）。
        let chain_acc: felt252 = 0xACCE55;
        let mut segment = array![chain_acc, MAGIC, hand_id.into(), digest, 3, hand_binding];
        // cm0 = poseidon([0x21, binding, 3000, 0])，其余 0。
        let mut ch = PoseidonTrait::new();
        ch = ch.update(0x21);
        ch = ch.update(hand_binding);
        ch = ch.update(3000);
        ch = ch.update(0);
        let cm0 = ch.finalize();
        segment.append(cm0);
        let mut w: u32 = 0;
        while w < 8_u32 {
            segment.append(0);
            w += 1;
        }
        segment.append(3000);
        segment.append(action_log);

        if with_fact {
            let mut f = PoseidonTrait::new();
            f = f.update(COMBINED_HASH);
            let mut w: u32 = 0;
            while w < segment.len() {
                f = f.update(*segment.at(w));
                w += 1;
            }
            dual.register_settlement_fact(f.finalize());
        }

        Setup { dual, vault: IMockVaultDispatcher { contract_address: vault }, hand_binding, segment, total: 3000, chain_acc }
    }

    #[test]
    fn combined_honest_segment_settles_with_single_fact() {
        let s = setup(true);
        assert!(s.dual.combined_program_hash() == COMBINED_HASH, "hash view");
        s.dual
            .verify_and_settle_dapv_combined_private(s.hand_binding, 42, s.segment.span());
        assert!(s.dual.hand_settled(s.hand_binding), "hand must be settled");
        let mut ch = PoseidonTrait::new();
        ch = ch.update(0x21);
        ch = ch.update(s.hand_binding);
        ch = ch.update(3000);
        ch = ch.update(0);
        assert!(s.dual.claim_cm(s.hand_binding, 0) == ch.finalize(), "cm0 from segment");
        assert!(s.dual.claim_cm(s.hand_binding, 1) == 0, "non-winner cm zero");
        let total_u256: u256 = s.total.into();
        assert!(
            s.vault.escrowed_for(s.hand_binding) == total_u256,
            "escrow equals total_winnings"
        );
    }

    #[test]
    #[should_panic(expected: "Settlement fact not registered")]
    fn combined_missing_fact_reverts() {
        let s = setup(false);
        s.dual
            .verify_and_settle_dapv_combined_private(s.hand_binding, 42, s.segment.span());
    }

    #[test]
    #[should_panic(expected: "Segment length mismatch")]
    fn combined_wrong_length_reverts() {
        let s = setup(true);
        // 16 词段（v2 形态）必须被拒绝——合并入口只吃 17 词。
        let mut short = array![];
        let mut w: u32 = 1;
        while w < s.segment.len() {
            short.append(*s.segment.at(w));
            w += 1;
        }
        s.dual
            .verify_and_settle_dapv_combined_private(s.hand_binding, 42, short.span());
    }

    #[test]
    #[should_panic(expected: "Hand already settled")]
    fn combined_replay_reverts() {
        let s = setup(true);
        s.dual
            .verify_and_settle_dapv_combined_private(s.hand_binding, 42, s.segment.span());
        s.dual
            .verify_and_settle_dapv_combined_private(s.hand_binding, 42, s.segment.span());
    }

    #[test]
    #[should_panic(expected: "Segment length mismatch")]
    fn combined_rejects_18_word_fold_segment() {
        // 消费面禁混批（规格 out/fold-spec.md D3c 第 3 层镜像）：fold 的
        // 18 词段（combined 17 词信封 + 尾插 roster 词）过不了 combined
        // 入口——combined fallback 只吃 17 词，行为不得被 fold 增量破坏。
        let s = setup(true);
        let mut longer = array![];
        let mut w: u32 = 0;
        while w < s.segment.len() {
            longer.append(*s.segment.at(w));
            w += 1;
        }
        longer.append(0x5157); // 伪装 roster 词
        s.dual
            .verify_and_settle_dapv_combined_private(s.hand_binding, 42, longer.span());
    }
}

// ============================================================
// Tests (snforge): P2-M4 proved × private 双证明结算——hand_verify
// （绑定 p_batch 承诺）+ stark verify（绑定公开段）双 fact，派奖与 v2 同。
// ============================================================

#[cfg(test)]
mod settlement_proved_private_tests {
    use core::hash::HashStateTrait;
    use core::poseidon::PoseidonTrait;
    use starknet::{ContractAddress, get_contract_address};
    use snforge_std::{ContractClassTrait, DeclareResultTrait, declare};

    use super::mock_vault::IMockVaultDispatcherTrait;
    use super::mock_vault::IMockVaultDispatcher;
    use super::{
        IPokerDualSettlement, IPokerDualSettlementDispatcher,
        IPokerDualSettlementDispatcherTrait,
    };

    const MAGIC: felt252 = 0x5350324d5f4f4b;
    const PROGRAM_HASH: felt252 = 0xabcdef;
    const HAND_VERIFY_PROGRAM_HASH: felt252 = 0x1234;

    fn deploy_contract(name: ByteArray, calldata: @Array<felt252>) -> ContractAddress {
        let class = declare(name).unwrap().contract_class();
        let (address, _) = class.deploy(calldata).unwrap();
        address
    }

    struct Setup {
        dual: IPokerDualSettlementDispatcher,
        vault: IMockVaultDispatcher,
        hand_binding: felt252,
        segment: Array<felt252>,
        total: felt252,
        /// 注册并进入 hand_verify fact 的 p_batch 承诺。
        p_commitment: felt252,
        batch_len: u32,
    }

    /// 部署 mock vault + dual（test 合约为 owner 与 initial_prover），
    /// register_hand_proved 钉 (p_commitment, batch_len)，双 program hash
    /// 就位；`with_hand_fact`/`with_settlement_fact` 控制两个 fact 的登记。
    fn setup(with_hand_fact: bool, with_settlement_fact: bool) -> Setup {
        let test_addr = get_contract_address();
        let vault = deploy_contract("MockVault", @array![]);
        let dual_addr = deploy_contract(
            "PokerDualSettlement",
            @array![test_addr.into(), vault.into(), test_addr.into()],
        );
        let dual = IPokerDualSettlementDispatcher { contract_address: dual_addr };
        dual.set_claim_helper(test_addr);
        dual.set_circuit_program_hash(PROGRAM_HASH);
        dual.set_hand_verify_program_hash(HAND_VERIFY_PROGRAM_HASH);

        let hand_binding: felt252 = 0xCCCC;
        let hand_id: u64 = 43;
        let digest: felt252 = 0x9900;
        let action_log: felt252 = 0xA11CE;
        let p_commitment: felt252 = 0xC0BA;
        let batch_len: u32 = 37;

        dual.register_hand_proved(
            hand_binding, digest, 0, action_log,
            p_commitment, batch_len.into(), 0, 0, 0,
        );

        // 公开段（与 v2 测试同构：赢家 seat0 +3000，输家 seat1/2；
        // claim cm 的承诺根 = 赢家 payout commitment 0x21）
        let payout_commitment: felt252 = 0x21;
        let mut cms = array![];
        let mut total: felt252 = 0;
        let mut i: u32 = 0;
        while i < 9_u32 {
            let (s, m): (felt252, felt252) = if i == 0 {
                (1, 3000)
            } else if i == 1 {
                (0, 2000)
            } else if i == 2 {
                (0, 1000)
            } else {
                (1, 0)
            };
            i += 1;
            if s == 1 {
                if m != 0 {
                    total += m;
                    let mut ch = PoseidonTrait::new();
                    ch = ch.update(payout_commitment);
                    ch = ch.update(hand_binding);
                    ch = ch.update(m);
                    ch = ch.update(0);
                    cms.append(ch.finalize());
                } else {
                    cms.append(0);
                };
            } else {
                cms.append(0);
            };
        }

        let mut segment = array![MAGIC, hand_id.into(), digest, 3, hand_binding];
        let mut w: u32 = 0;
        while w < 9_u32 {
            segment.append(*cms.at(w));
            w += 1;
        };
        segment.append(total);
        segment.append(action_log);

        if with_settlement_fact {
            let mut f = PoseidonTrait::new();
            f = f.update(PROGRAM_HASH);
            let mut w2: u32 = 0;
            while w2 < segment.len() {
                f = f.update(*segment.at(w2));
                w2 += 1;
            }
            dual.register_settlement_fact(f.finalize());
        }
        if with_hand_fact {
            let mut hf = PoseidonTrait::new();
            hf = hf.update(HAND_VERIFY_PROGRAM_HASH);
            hf = hf.update(p_commitment);
            dual.register_settlement_fact(hf.finalize());
        }

        Setup {
            dual,
            vault: IMockVaultDispatcher { contract_address: vault },
            hand_binding,
            segment,
            total,
            p_commitment,
            batch_len,
        }
    }

    #[test]
    fn proved_private_honest_double_fact_settles() {
        let s = setup(true, true);
        s.dual.verify_and_settle_dapv_proved_private(
            s.hand_binding, 43, s.segment.span(), s.p_commitment, s.batch_len,
        );
        assert!(s.dual.hand_settled(s.hand_binding), "hand must be settled");
        assert!(s.dual.amounts_hidden(s.hand_binding), "amounts hidden");
        let total_u256: u256 = s.total.into();
        assert!(
            s.vault.escrowed_for(s.hand_binding) == total_u256,
            "escrow must equal total_winnings"
        );
        let mut ch = PoseidonTrait::new();
        ch = ch.update(0x21);
        ch = ch.update(s.hand_binding);
        ch = ch.update(3000);
        ch = ch.update(0);
        assert!(s.dual.claim_cm(s.hand_binding, 0) == ch.finalize(), "winner cm");
        assert!(s.dual.claim_cm(s.hand_binding, 1) == 0, "non-winner cm must be zero");
    }

    #[test]
    #[should_panic(expected: "p_batch commitment mismatch")]
    fn proved_private_rejects_wrong_commitment() {
        let s = setup(true, true);
        s.dual.verify_and_settle_dapv_proved_private(
            s.hand_binding, 43, s.segment.span(), s.p_commitment + 1, s.batch_len,
        );
    }

    #[test]
    #[should_panic(expected: "Hand verify fact not registered")]
    fn proved_private_requires_hand_verify_fact() {
        let s = setup(false, true);
        s.dual.verify_and_settle_dapv_proved_private(
            s.hand_binding, 43, s.segment.span(), s.p_commitment, s.batch_len,
        );
    }

    #[test]
    #[should_panic(expected: "Settlement fact not registered")]
    fn proved_private_requires_settlement_fact() {
        let s = setup(true, false);
        s.dual.verify_and_settle_dapv_proved_private(
            s.hand_binding, 43, s.segment.span(), s.p_commitment, s.batch_len,
        );
    }
}
// ============================================================
// Tests (snforge): fold 批结算——18 词公开段（combined 17 词信封 +
// 尾插 roster_digest），roster 注册面（owner-gated + 链上重算 digest）
// 与 fold 哈希分槽 fact 门。规格 out/fold-spec.md §4/D3c/D5。
// ============================================================

#[cfg(test)]
mod settlement_fold_private_tests {
    use core::hash::HashStateTrait;
    use core::poseidon::{poseidon_hash_span, PoseidonTrait};
    use starknet::{ContractAddress, get_contract_address};
    use snforge_std::{
        ContractClassTrait, DeclareResultTrait, declare, spy_events,
        EventSpyAssertionsTrait,
    };
    use snforge_std::cheatcodes::execution_info::caller_address::{
        start_cheat_caller_address,
    };

    use super::mock_vault::IMockVaultDispatcherTrait;
    use super::mock_vault::IMockVaultDispatcher;
    use super::{
        IPokerDualSettlement, IPokerDualSettlementDispatcher,
        IPokerDualSettlementDispatcherTrait,
    };

    /// roster 域标签（与合约常量及 fold_batch.cairo 电路 ROSTER_LABEL 逐字节一致）。
    const ROSTER_LABEL: felt252 = 'poker/fold-batch/roster.v1';
    const MAGIC: felt252 = 0x5350324d5f4f4b;
    /// fold 批程序哈希（与 combined 0xC0FFEE 分槽——禁混批 D3c 第 2 层）。
    const FOLD_HASH: felt252 = 0xF17D;
    const COMBINED_HASH: felt252 = 0xC0FFEE;

    /// 与合约事件同名的本地镜像（键 = sn_keccak(变体名)、数据 = 字段顺序
    /// 序列化）——合约内 Event 枚举未导出，按 snforge 标准做法本地重声明
    /// 同形枚举后 `assert_emitted` 逐字段比对。
    #[derive(Drop, starknet::Event)]
    struct RosterRegistered {
        table_id: u64,
        n: felt252,
        roster_digest: felt252,
        pks: Span<felt252>,
    }

    #[derive(Drop, starknet::Event)]
    struct DualProofSettledFold {
        hand_binding: felt252,
        settlement_digest: felt252,
        participant_count: u32,
        chain_acc: felt252,
        roster_digest: felt252,
        total_winnings: u256,
    }

    #[derive(Drop, starknet::Event)]
    enum MirrorEvent {
        RosterRegistered: RosterRegistered,
        DualProofSettledFold: DualProofSettledFold,
    }

    fn deploy_contract(name: ByteArray, calldata: @Array<felt252>) -> ContractAddress {
        let class = declare(name).unwrap().contract_class();
        let (address, _) = class.deploy(calldata).unwrap();
        address
    }

    /// 部署 mock vault + dual（test 合约为 owner 与 initial_prover），
    /// 不做任何注册——ACL 负例与注册正例测试各自补齐前置。
    fn deploy_dual() -> IPokerDualSettlementDispatcher {
        let test_addr = get_contract_address();
        let vault = deploy_contract("MockVault", @array![]);
        let dual_addr = deploy_contract(
            "PokerDualSettlement",
            @array![test_addr.into(), vault.into(), test_addr.into()],
        );
        IPokerDualSettlementDispatcher { contract_address: dual_addr }
    }

    /// 链上同式重算 roster_digest：poseidon([ROSTER_LABEL, n] ++ pks)
    /// （与合约 register_roster 及 fold_batch.cairo 电路 ROSTER_LABEL 常量同公式）。
    fn roster_digest_of(n: felt252, pks: Span<felt252>) -> felt252 {
        let mut roster_in = array![ROSTER_LABEL, n];
        let mut w: u32 = 0;
        while w < pks.len() {
            roster_in.append(*pks.at(w));
            w += 1;
        }
        poseidon_hash_span(roster_in.span())
    }

    #[derive(Drop)]
    struct FoldSetup {
        dual: IPokerDualSettlementDispatcher,
        vault: IMockVaultDispatcher,
        hand_binding: felt252,
        segment: Array<felt252>,
        total: felt252,
        chain_acc: felt252,
        roster_digest: felt252,
        pks: Array<felt252>,
        n: felt252,
    }

    /// 完整前置：部署 + claim helper + 三 program hash 就位 + register_hand
    /// （digest=0x9900、action_log=0xA11CE）+ register_roster（n=2、pks 4 词）
    /// + 构造 18 词 fold 段（赢家 seat0 +3000，cm0 = poseidon([0x21,
    /// binding, 3000, 0])，尾词 = roster_digest）+ `with_fold_fact` 控制
    /// fold 哈希 fact 登记。`tamper_roster` 把段尾换成未注册 digest。
    fn setup(tamper_roster: bool, with_fold_fact: bool) -> FoldSetup {
        let test_addr = get_contract_address();
        let vault = deploy_contract("MockVault", @array![]);
        let dual_addr = deploy_contract(
            "PokerDualSettlement",
            @array![test_addr.into(), vault.into(), test_addr.into()],
        );
        let dual = IPokerDualSettlementDispatcher { contract_address: dual_addr };
        dual.set_claim_helper(test_addr);
        dual.set_circuit_program_hash(0x1111);
        dual.set_combined_program_hash(COMBINED_HASH);
        dual.set_fold_program_hash(FOLD_HASH);

        let hand_binding: felt252 = 0xEEEE;
        let hand_id: u64 = 45;
        let digest: felt252 = 0x9900;
        let action_log: felt252 = 0xA11CE;
        dual.register_hand(hand_binding, digest, 0, action_log, 0, 0, 0);

        // roster 注册（owner = test 合约）。roster 人数 n=2 与该手公开段
        // participant 数 3 是两个独立量（规格 D2 槽语义分离）。
        let n: felt252 = 2;
        let pks = array![0xAA11, 0xBB22, 0xCC33, 0xDD44];
        let roster_digest = roster_digest_of(n, pks.span());
        dual.register_roster(7, n, pks.span());

        // 18 词 fold 段 = 17 词 combined 信封原样 + 尾插 roster_digest。
        let chain_acc: felt252 = 0xACCE55;
        let mut segment = array![chain_acc, MAGIC, hand_id.into(), digest, 3, hand_binding];
        let mut ch = PoseidonTrait::new();
        ch = ch.update(0x21);
        ch = ch.update(hand_binding);
        ch = ch.update(3000);
        ch = ch.update(0);
        segment.append(ch.finalize());
        let mut w: u32 = 0;
        while w < 8_u32 {
            segment.append(0);
            w += 1;
        }
        segment.append(3000);
        segment.append(action_log);
        let tail_roster: felt252 =
            if tamper_roster { roster_digest + 1 } else { roster_digest };
        segment.append(tail_roster);

        if with_fold_fact {
            let mut f = PoseidonTrait::new();
            f = f.update(FOLD_HASH);
            let mut w: u32 = 0;
            while w < segment.len() {
                f = f.update(*segment.at(w));
                w += 1;
            }
            dual.register_settlement_fact(f.finalize());
        }

        FoldSetup {
            dual,
            vault: IMockVaultDispatcher { contract_address: vault },
            hand_binding,
            segment,
            total: 3000,
            chain_acc,
            roster_digest,
            pks,
            n,
        }
    }

    // ===== 注册面正例 + 事件断言 =====

    #[test]
    fn fold_register_roster_emits_event_and_sets_view() {
        let dual = deploy_dual();
        let n: felt252 = 2;
        let pks = array![0x1234, 0x5678, 0x9ABC, 0xDEF0];
        let digest = roster_digest_of(n, pks.span());
        assert!(!dual.roster_registered(digest), "must be unregistered first");

        let mut spy = spy_events();
        dual.register_roster(3, n, pks.span());
        spy.assert_emitted(
            @array![(
                dual.contract_address,
                MirrorEvent::RosterRegistered(
                    RosterRegistered {
                        table_id: 3, n, roster_digest: digest, pks: pks.span(),
                    },
                ),
            )],
        );
        assert!(dual.roster_registered(digest), "roster must be registered");
    }

    #[test]
    fn fold_honest_segment_settles_and_emits_fold_event() {
        let s = setup(false, true);
        assert!(s.dual.fold_program_hash() == FOLD_HASH, "fold hash view");
        assert!(s.dual.roster_registered(s.roster_digest), "roster view");
        let mut spy = spy_events();
        s.dual.verify_and_settle_dapv_fold_private(s.hand_binding, 45, s.segment.span());
        spy.assert_emitted(
            @array![(
                s.dual.contract_address,
                MirrorEvent::DualProofSettledFold(
                    DualProofSettledFold {
                        hand_binding: s.hand_binding,
                        settlement_digest: 0x9900,
                        participant_count: 3,
                        chain_acc: s.chain_acc,
                        roster_digest: s.roster_digest,
                        total_winnings: s.total.into(),
                    },
                ),
            )],
        );
        assert!(s.dual.hand_settled(s.hand_binding), "hand must be settled");
        assert!(s.dual.amounts_hidden(s.hand_binding), "amounts hidden");
        // claim_cms 来自公开段 cm 槽（seat0 = 赢家承诺）。
        let mut ch = PoseidonTrait::new();
        ch = ch.update(0x21);
        ch = ch.update(s.hand_binding);
        ch = ch.update(3000);
        ch = ch.update(0);
        assert!(s.dual.claim_cm(s.hand_binding, 0) == ch.finalize(), "cm0 from segment");
        assert!(s.dual.claim_cm(s.hand_binding, 1) == 0, "non-winner cm zero");
        let total_u256: u256 = s.total.into();
        assert!(
            s.vault.escrowed_for(s.hand_binding) == total_u256,
            "escrow equals total_winnings"
        );
    }

    // ===== 注册面 ACL / 一次性 =====

    #[test]
    #[should_panic(expected: 'Caller is not the owner')]
    fn fold_register_roster_rejects_non_owner() {
        let dual = deploy_dual();
        let outsider: ContractAddress = 0xdead_beef.try_into().unwrap();
        start_cheat_caller_address(dual.contract_address, outsider);
        dual.register_roster(1, 2, array![1, 2, 3, 4].span());
    }

    #[test]
    #[should_panic(expected: 'Caller is not the owner')]
    fn fold_set_program_hash_rejects_non_owner() {
        let dual = deploy_dual();
        let outsider: ContractAddress = 0xdead_beef.try_into().unwrap();
        start_cheat_caller_address(dual.contract_address, outsider);
        dual.set_fold_program_hash(0x99);
    }

    #[test]
    #[should_panic(expected: "Roster already registered")]
    fn fold_register_roster_rejects_duplicate() {
        let s = setup(false, true); // setup 内已注册 (n=2, 同一组 pks)
        s.dual.register_roster(9, s.n, s.pks.span());
    }

    #[test]
    #[should_panic(expected: "Roster pks length mismatch")]
    fn fold_register_roster_rejects_bad_pks_len() {
        let dual = deploy_dual();
        // n=2 应配 4 词 pks，只给 3 词。
        dual.register_roster(1, 2, array![1, 2, 3].span());
    }

    #[test]
    #[should_panic(expected: "Participant count out of range")]
    fn fold_register_roster_rejects_n_out_of_window() {
        let dual = deploy_dual();
        // 9 人桌窗口为 2..=9；n=10（20 词 pks）必须仍被拒。
        dual.register_roster(
            1, 10, array![
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20
            ].span(),
        );
    }

    // ===== fold 结算负例（规格 D5 第 6 条：4 条 should_panic）=====

    #[test]
    #[should_panic(expected: "Roster not registered")]
    fn fold_unregistered_roster_reverts() {
        // 段尾 roster_digest 换成未注册值——roster 对照在 fact 门之前，
        // 无需 fact 即可命中断言。
        let s = setup(true, false);
        s.dual.verify_and_settle_dapv_fold_private(s.hand_binding, 45, s.segment.span());
    }

    #[test]
    #[should_panic(expected: "Segment length mismatch")]
    fn fold_rejects_17_word_combined_segment() {
        // 消费面禁混批（D3c 第 3 层）：combined 17 词段过不了 fold 入口。
        let s = setup(false, true);
        let mut short = array![];
        let mut w: u32 = 0;
        while w < 17_u32 {
            short.append(*s.segment.at(w));
            w += 1;
        }
        s.dual.verify_and_settle_dapv_fold_private(s.hand_binding, 45, short.span());
    }

    #[test]
    #[should_panic(expected: "Settlement fact not registered")]
    fn fold_rejects_combined_hash_fact() {
        // 两链 program_hash 分槽（D3c 第 2 层）：combined 哈希下登记的
        // fact 不能为 fold 段买单。
        let s = setup(false, false);
        let mut f = PoseidonTrait::new();
        f = f.update(COMBINED_HASH);
        let mut w: u32 = 0;
        while w < s.segment.len() {
            f = f.update(*s.segment.at(w));
            w += 1;
        }
        s.dual.register_settlement_fact(f.finalize());
        s.dual.verify_and_settle_dapv_fold_private(s.hand_binding, 45, s.segment.span());
    }

    #[test]
    #[should_panic(expected: "Hand already settled")]
    fn fold_replay_reverts() {
        let s = setup(false, true);
        s.dual.verify_and_settle_dapv_fold_private(s.hand_binding, 45, s.segment.span());
        s.dual.verify_and_settle_dapv_fold_private(s.hand_binding, 45, s.segment.span());
    }

    // ===== 多桌段测试（规格 out/fold-multitable-spec.md §7/§9 M9-5b）=====
    // 判定前提：fold 入口一次调用只吃一段 18 词且 segment[17] 逐手对照
    // roster_registry——多桌批 = 每手一次调用各携各桌 digest，入口对
    // 「批里还有别的桌」无感知（零合约改动的消费面证据）。

    struct MultiTableSetup {
        dual: IPokerDualSettlementDispatcher,
        vault: IMockVaultDispatcher,
        digest_a: felt252,
        digest_b: felt252,
    }

    /// 多桌共用前置：部署 + 三 program hash + 桌 A（table_id=11、n=2、
    /// 4 词 pks）与桌 B（table_id=22、n=3、6 词 pks）各自 register_roster
    /// ——两桌人数与键集都不同 ⇒ digest 不同（同式重算、独立键）。
    fn setup_multitable() -> MultiTableSetup {
        let test_addr = get_contract_address();
        let vault = deploy_contract("MockVault", @array![]);
        let dual_addr = deploy_contract(
            "PokerDualSettlement",
            @array![test_addr.into(), vault.into(), test_addr.into()],
        );
        let dual = IPokerDualSettlementDispatcher { contract_address: dual_addr };
        dual.set_claim_helper(test_addr);
        dual.set_circuit_program_hash(0x1111);
        dual.set_combined_program_hash(COMBINED_HASH);
        dual.set_fold_program_hash(FOLD_HASH);

        let pks_a = array![0xA001, 0xA002, 0xA003, 0xA004];
        let pks_b = array![0xB001, 0xB002, 0xB003, 0xB004, 0xB005, 0xB006];
        let digest_a = roster_digest_of(2, pks_a.span());
        let digest_b = roster_digest_of(3, pks_b.span());
        dual.register_roster(11, 2, pks_a.span());
        dual.register_roster(22, 3, pks_b.span());

        MultiTableSetup {
            dual,
            vault: IMockVaultDispatcher { contract_address: vault },
            digest_a,
            digest_b,
        }
    }

    /// 造一张桌的 18 词 fold 段：slot0 = 批终 chain_acc（多桌批内全段
    /// 同值——Q-1 语义），尾词 = 本桌 roster_digest；赢家 seat0 +total，
    /// cm0 = poseidon([0x21, binding, total, 0])。
    fn fold_segment_for(
        hand_binding: felt252,
        hand_id: u64,
        digest: felt252,
        action_log: felt252,
        total: felt252,
        chain_acc: felt252,
        roster_digest: felt252,
    ) -> Array<felt252> {
        let mut segment = array![chain_acc, MAGIC, hand_id.into(), digest, 3, hand_binding];
        let mut ch = PoseidonTrait::new();
        ch = ch.update(0x21);
        ch = ch.update(hand_binding);
        ch = ch.update(total);
        ch = ch.update(0);
        segment.append(ch.finalize());
        let mut w: u32 = 0;
        while w < 8_u32 {
            segment.append(0);
            w += 1;
        }
        segment.append(total);
        segment.append(action_log);
        segment.append(roster_digest);
        segment
    }

    /// 按折叠哈希算段的 fact（与合约 fact_for_segment 同式）。
    fn fold_fact_of(segment: Span<felt252>) -> felt252 {
        let mut f = PoseidonTrait::new();
        f = f.update(FOLD_HASH);
        let mut w: u32 = 0;
        while w < segment.len() {
            f = f.update(*segment.at(w));
            w += 1;
        }
        f.finalize()
    }

    #[test]
    fn fold_multitable_two_rosters_interleaved_settlement_settles() {
        let mt = setup_multitable();
        assert!(mt.dual.roster_registered(mt.digest_a), "table A registered");
        assert!(mt.dual.roster_registered(mt.digest_b), "table B registered");
        assert!(mt.digest_a != mt.digest_b, "two tables must have distinct digests");

        // 同批三手段（wire 串接序 A1→B1→A2）：slot0 = 同一批终 acc
        // （批终 acc 复制全段），slot16 = 各桌 digest。
        let binding_a1: felt252 = 0xAA01;
        let binding_b1: felt252 = 0xBB01;
        let binding_a2: felt252 = 0xAA02;
        mt.dual.register_hand(binding_a1, 0x9A01, 0, 0xA101, 0, 0, 0);
        mt.dual.register_hand(binding_b1, 0x9B01, 0, 0xB101, 0, 0, 0);
        mt.dual.register_hand(binding_a2, 0x9A02, 0, 0xA102, 0, 0, 0);

        let total_a1: felt252 = 3000;
        let total_b1: felt252 = 1500;
        let total_a2: felt252 = 2200;
        let chain_acc: felt252 = 0xBACC00;
        let seg_a1 = fold_segment_for(
            binding_a1, 101, 0x9A01, 0xA101, total_a1, chain_acc, mt.digest_a,
        );
        let seg_b1 = fold_segment_for(
            binding_b1, 201, 0x9B01, 0xB101, total_b1, chain_acc, mt.digest_b,
        );
        let seg_a2 = fold_segment_for(
            binding_a2, 102, 0x9A02, 0xA102, total_a2, chain_acc, mt.digest_a,
        );
        mt.dual.register_settlement_fact(fold_fact_of(seg_a1.span()));
        mt.dual.register_settlement_fact(fold_fact_of(seg_b1.span()));
        mt.dual.register_settlement_fact(fold_fact_of(seg_a2.span()));

        // 交错结算：每手一次调用、各携各桌 digest，桌序不影响入口判定。
        let mut spy = spy_events();
        mt.dual.verify_and_settle_dapv_fold_private(binding_a1, 101, seg_a1.span());
        mt.dual.verify_and_settle_dapv_fold_private(binding_b1, 201, seg_b1.span());
        mt.dual.verify_and_settle_dapv_fold_private(binding_a2, 102, seg_a2.span());

        spy.assert_emitted(
            @array![
                (
                    mt.dual.contract_address,
                    MirrorEvent::DualProofSettledFold(
                        DualProofSettledFold {
                            hand_binding: binding_a1,
                            settlement_digest: 0x9A01,
                            participant_count: 3,
                            chain_acc,
                            roster_digest: mt.digest_a,
                            total_winnings: total_a1.into(),
                        },
                    ),
                ),
                (
                    mt.dual.contract_address,
                    MirrorEvent::DualProofSettledFold(
                        DualProofSettledFold {
                            hand_binding: binding_b1,
                            settlement_digest: 0x9B01,
                            participant_count: 3,
                            chain_acc,
                            roster_digest: mt.digest_b,
                            total_winnings: total_b1.into(),
                        },
                    ),
                ),
                (
                    mt.dual.contract_address,
                    MirrorEvent::DualProofSettledFold(
                        DualProofSettledFold {
                            hand_binding: binding_a2,
                            settlement_digest: 0x9A02,
                            participant_count: 3,
                            chain_acc,
                            roster_digest: mt.digest_a,
                            total_winnings: total_a2.into(),
                        },
                    ),
                ),
            ],
        );

        assert!(mt.dual.hand_settled(binding_a1), "A1 settled");
        assert!(mt.dual.hand_settled(binding_b1), "B1 settled");
        assert!(mt.dual.hand_settled(binding_a2), "A2 settled");
        let escrow_a1: u256 = total_a1.into();
        let escrow_b1: u256 = total_b1.into();
        let escrow_a2: u256 = total_a2.into();
        assert!(mt.vault.escrowed_for(binding_a1) == escrow_a1, "A1 escrow");
        assert!(mt.vault.escrowed_for(binding_b1) == escrow_b1, "B1 escrow");
        assert!(mt.vault.escrowed_for(binding_a2) == escrow_a2, "A2 escrow");
    }

    #[test]
    #[should_panic(expected: "Roster not registered")]
    fn fold_multitable_unregistered_third_table_reverts() {
        let mt = setup_multitable();
        // 桌 A/B 已注册；构造第三桌（n=2、独立 pks、未注册）的手——
        // 即便 fact 齐备，roster 对照门（#10）在 fact 门之前先拒：
        // 未注册桌的手不结算。
        let binding_c: felt252 = 0xCC01;
        mt.dual.register_hand(binding_c, 0x9C01, 0, 0xC101, 0, 0, 0);
        let pks_c = array![0xC001, 0xC002, 0xC003, 0xC004];
        let digest_c = roster_digest_of(2, pks_c.span());
        assert!(!mt.dual.roster_registered(digest_c), "table C unregistered");
        let seg_c = fold_segment_for(binding_c, 301, 0x9C01, 0xC101, 700, 0xBACC00, digest_c);
        mt.dual.register_settlement_fact(fold_fact_of(seg_c.span()));
        mt.dual.verify_and_settle_dapv_fold_private(binding_c, 301, seg_c.span());
    }

    #[test]
    #[should_panic(expected: "Settlement fact not registered")]
    fn fold_multitable_cross_table_roster_swap_reverts() {
        let mt = setup_multitable();
        // 跨桌攻击消费面闭合（spec §5 第二重）：桌 A 手段的 fact 按诚实段
        // （尾词 = digest_a）登记；把尾词换成桌 B 的 digest 再提交——
        // roster 门放行（B 已注册），但 fact 对整段逐词吸收
        // （fact_for_segment），换词即换 fact ⇒ fact 门拒。
        let binding_a: felt252 = 0xAA01;
        mt.dual.register_hand(binding_a, 0x9A01, 0, 0xA101, 0, 0, 0);
        let seg_a = fold_segment_for(binding_a, 101, 0x9A01, 0xA101, 3000, 0xBACC00, mt.digest_a);
        mt.dual.register_settlement_fact(fold_fact_of(seg_a.span()));

        let mut swapped = array![];
        let mut w: u32 = 0;
        while w < 17_u32 {
            swapped.append(*seg_a.at(w));
            w += 1;
        }
        swapped.append(mt.digest_b); // 桌 B 的 roster 尾词
        mt.dual.verify_and_settle_dapv_fold_private(binding_a, 101, swapped.span());
    }

    #[test]
    fn fold_multitable_coexists_with_combined_fallback() {
        let mt = setup_multitable();
        // combined 回归保持：combined 手（17 词段 + combined 哈希 fact）
        // 与桌 A 的 fold 手（18 词段 + fold 哈希 fact）在同一合约实例上
        // 先后结算——combined fallback 行为不受多桌 fold 影响。
        let binding_c: felt252 = 0xDD01;
        let binding_f: felt252 = 0xAA01;
        mt.dual.register_hand(binding_c, 0x9D01, 0, 0xD101, 0, 0, 0);
        mt.dual.register_hand(binding_f, 0x9A01, 0, 0xA101, 0, 0, 0);

        let hand_id_c: u64 = 61;
        let total_c: felt252 = 900;
        let chain_acc: felt252 = 0xACCE55;
        let mut seg_c = array![chain_acc, MAGIC, hand_id_c.into(), 0x9D01, 3, binding_c];
        let mut ch = PoseidonTrait::new();
        ch = ch.update(0x21);
        ch = ch.update(binding_c);
        ch = ch.update(total_c);
        ch = ch.update(0);
        seg_c.append(ch.finalize());
        let mut w: u32 = 0;
        while w < 8_u32 {
            seg_c.append(0);
            w += 1;
        }
        seg_c.append(total_c);
        seg_c.append(0xD101);
        let mut fc = PoseidonTrait::new();
        fc = fc.update(COMBINED_HASH);
        let mut w: u32 = 0;
        while w < seg_c.len() {
            fc = fc.update(*seg_c.at(w));
            w += 1;
        }
        mt.dual.register_settlement_fact(fc.finalize());

        let total_f: felt252 = 3000;
        let seg_f = fold_segment_for(
            binding_f, 101, 0x9A01, 0xA101, total_f, chain_acc, mt.digest_a,
        );
        mt.dual.register_settlement_fact(fold_fact_of(seg_f.span()));

        mt.dual.verify_and_settle_dapv_combined_private(binding_c, hand_id_c, seg_c.span());
        mt.dual.verify_and_settle_dapv_fold_private(binding_f, 101, seg_f.span());

        assert!(mt.dual.hand_settled(binding_c), "combined hand settled");
        assert!(mt.dual.hand_settled(binding_f), "fold hand settled");
        let escrow_c: u256 = total_c.into();
        let escrow_f: u256 = total_f.into();
        assert!(mt.vault.escrowed_for(binding_c) == escrow_c, "combined escrow");
        assert!(mt.vault.escrowed_for(binding_f) == escrow_f, "fold escrow");
    }
}

/// P2-M3 测试用 MockVault：记录 escrow 划转，payout_commitment 返回常数。
#[cfg(test)]
mod mock_vault {
    use starknet::ContractAddress;
    use starknet::storage::{StorageMapReadAccess, StorageMapWriteAccess};

    #[starknet::interface]
    pub trait IMockVault<TContractState> {
        fn payout_commitment(self: @TContractState, player: ContractAddress) -> felt252;
        fn settlement_fund_escrow(
            ref self: TContractState,
            escrow: ContractAddress,
            hand_binding: felt252,
            amount: u256,
        );
        fn apply_settlement(ref self: TContractState, player: ContractAddress, delta: i128);
        fn escrowed_for(self: @TContractState, hand_binding: felt252) -> u256;
    }

    #[starknet::contract]
    pub mod MockVault {
        use starknet::ContractAddress;
        use starknet::storage::{Map, StorageMapReadAccess, StorageMapWriteAccess};

        #[storage]
        struct Storage {
            escrowed: Map<felt252, u256>,
        }

        #[event]
        #[derive(Drop, starknet::Event)]
        enum Event {
            EscrowFunded: EscrowFunded,
        }

        #[derive(Drop, starknet::Event)]
        struct EscrowFunded {
            escrow: ContractAddress,
            hand_binding: felt252,
            amount: u256,
        }

        #[constructor]
        fn constructor(ref self: ContractState) {}

        #[abi(embed_v0)]
        impl IMockVaultImpl of super::IMockVault<ContractState> {
            fn payout_commitment(self: @ContractState, player: ContractAddress) -> felt252 {
                0x1234
            }

            fn settlement_fund_escrow(
                ref self: ContractState,
                escrow: ContractAddress,
                hand_binding: felt252,
                amount: u256,
            ) {
                let current = self.escrowed.read(hand_binding);
                self.escrowed.write(hand_binding, current + amount);
                self.emit(EscrowFunded { escrow, hand_binding, amount });
            }

            fn apply_settlement(
                ref self: ContractState,
                player: ContractAddress,
                delta: i128,
            ) {
            }

            fn escrowed_for(self: @ContractState, hand_binding: felt252) -> u256 {
                self.escrowed.read(hand_binding)
            }
        }
    }


}

// ============================================================
// Tests (snforge 0.63): P2-M5 v3 双门入口 —— SNIP-36 proof_facts
// 优先（cheat_proof_facts 原生 mock）+ fact-registry 降级。
// ============================================================

#[cfg(test)]
mod settlement_snip36_v3_tests {
    use core::hash::HashStateTrait;
    use core::poseidon::PoseidonTrait;
    use starknet::{ContractAddress, get_contract_address};
    use snforge_std::{
        ContractClassTrait, DeclareResultTrait, declare, cheat_proof_facts, CheatSpan,
    };

    use super::mock_vault::IMockVaultDispatcherTrait;
    use super::mock_vault::IMockVaultDispatcher;
    use super::{
        IPokerDualSettlement, IPokerDualSettlementDispatcher,
        IPokerDualSettlementDispatcherTrait,
    };

    const MAGIC: felt252 = 0x5350324d5f4f4b;
    /// settlement_private 电路哈希（fact-registry 降级腿的绑定根）。
    const PROGRAM_HASH: felt252 = 0xabcdef;
    /// Starknet 虚拟 OS（VIRTUAL_SNOS）程序哈希（SNIP-36 腿 facts[2] 绑定根）。
    const VIRTUAL_SNOS_HASH: felt252 = 0x604b02;
    /// proof_facts[1] 的 program variant："VIRTUAL_SNOS" ASCII。
    const VIRTUAL_SNOS_VARIANT: felt252 = 0x5649525455414c5f534e4f53;

    fn deploy_contract(name: ByteArray, calldata: @Array<felt252>) -> ContractAddress {
        let class = declare(name).unwrap().contract_class();
        let (address, _) = class.deploy(calldata).unwrap();
        address
    }

    #[derive(Drop)]
    struct Setup {
        dual: IPokerDualSettlementDispatcher,
        vault: IMockVaultDispatcher,
        hand_binding: felt252,
        segment: Array<felt252>,
        total: felt252,
    }

    /// v2 测试同款部署/注册/公开段；`with_fact` 控制 fact-registry 登记。
    /// proof_facts 由各测试自行 cheat（SNIP-36 门）。
    fn setup(with_fact: bool) -> Setup {
        let test_addr = get_contract_address();
        let vault = deploy_contract("MockVault", @array![]);
        let dual_addr = deploy_contract(
            "PokerDualSettlement",
            @array![test_addr.into(), vault.into(), test_addr.into()],
        );
        let dual = IPokerDualSettlementDispatcher { contract_address: dual_addr };
        dual.set_claim_helper(test_addr);
        dual.set_circuit_program_hash(PROGRAM_HASH);
        dual.set_virtual_snos_program_hash(VIRTUAL_SNOS_HASH);

        let hand_binding: felt252 = 0xDDDD;
        let hand_id: u64 = 44;
        let digest: felt252 = 0x9900;
        let action_log: felt252 = 0xA11CE;
        dual.register_hand(hand_binding, digest, 0, action_log, 0, 0, 0);

        // 公开段：赢家 seat0（+3000），输家 seat1/2（承诺根 0x21）
        let payout_commitment: felt252 = 0x21;
        let mut cms = array![];
        let mut total: felt252 = 0;
        let mut i: u32 = 0;
        while i < 9_u32 {
            let (sgn, m): (felt252, felt252) = if i == 0 {
                (1, 3000)
            } else if i == 1 {
                (0, 2000)
            } else if i == 2 {
                (0, 1000)
            } else {
                (1, 0)
            };
            i += 1;
            if sgn == 1 {
                if m != 0 {
                    total += m;
                    let mut ch = PoseidonTrait::new();
                    ch = ch.update(payout_commitment);
                    ch = ch.update(hand_binding);
                    ch = ch.update(m);
                    ch = ch.update(0);
                    cms.append(ch.finalize());
                } else {
                    cms.append(0);
                };
            } else {
                cms.append(0);
            };
        }
        let mut segment = array![MAGIC, hand_id.into(), digest, 3, hand_binding];
        let mut w: u32 = 0;
        while w < 9_u32 {
            segment.append(*cms.at(w));
            w += 1;
        }
        segment.append(total);
        segment.append(action_log);

        if with_fact {
            let mut f = PoseidonTrait::new();
            f = f.update(PROGRAM_HASH);
            let mut w2: u32 = 0;
            while w2 < segment.len() {
                f = f.update(*segment.at(w2));
                w2 += 1;
            }
            dual.register_settlement_fact(f.finalize());
        }
        Setup { dual, vault: IMockVaultDispatcher { contract_address: vault }, hand_binding, segment, total }
    }

    /// 构造 SNIP-36 proof_facts（9 词，对齐 ProofFacts 序列化布局）：
    /// [0] proof_version（测试置零）、[1] program variant = "VIRTUAL_SNOS"，
    /// [2] 虚拟 OS program hash，[7] 消息数 = 1，[8] = 消息哈希
    /// （poseidon(合约地址, 0, len, segment)——与合约 snip36_message_hash
    /// 同公式）。
    fn make_facts(
        dual_addr: ContractAddress, segment: Span<felt252>, virtual_hash: felt252,
    ) -> Array<felt252> {
        let mut mh = PoseidonTrait::new();
        mh = mh.update(dual_addr.into());
        mh = mh.update(0);
        mh = mh.update(segment.len().into());
        let mut w: u32 = 0;
        while w < segment.len() {
            mh = mh.update(*segment.at(w));
            w += 1;
        }
        array![
            0, VIRTUAL_SNOS_VARIANT, virtual_hash, 0, 0, 0, 0, 1, mh.finalize(),
        ]
    }

    /// 重建 segment 并把 `at(4)`（binding 词）替换为 `binding_override`。
    fn segment_with_binding(
        segment: Span<felt252>, binding_override: felt252,
    ) -> Array<felt252> {
        let mut out = array![];
        let mut w: u32 = 0;
        while w < segment.len() {
            let v = *segment.at(w);
            out.append(if w == 4 { binding_override } else { v });
            w += 1;
        }
        out
    }

    #[test]
    fn v3_snip36_gate_settles_without_fact() {
        let s = setup(false); // 不登记 fact——只可能走 SNIP-36 门
        let facts = make_facts(
            s.dual.contract_address, s.segment.span(), VIRTUAL_SNOS_HASH,
        );
        cheat_proof_facts(s.dual.contract_address, facts.span(), CheatSpan::Indefinite);
        s.dual.verify_and_settle_dapv_stark_private_v3(s.hand_binding, 44, s.segment.span());
        assert!(s.dual.hand_settled(s.hand_binding), "settled via SNIP-36 gate");
        let total_u256: u256 = s.total.into();
        assert!(s.vault.escrowed_for(s.hand_binding) == total_u256, "escrow");
    }

    #[test]
    fn v3_falls_back_to_fact_registry() {
        let s = setup(true); // 登记 fact、无 proof_facts
        s.dual.verify_and_settle_dapv_stark_private_v3(s.hand_binding, 44, s.segment.span());
        assert!(s.dual.hand_settled(s.hand_binding), "settled via fact-registry fallback");
    }

    #[test]
    #[should_panic(expected: "Settlement fact not registered")]
    fn v3_wrong_virtual_snos_hash_rejected() {
        let s = setup(false);
        let facts = make_facts(
            s.dual.contract_address, s.segment.span(), VIRTUAL_SNOS_HASH + 1,
        );
        cheat_proof_facts(s.dual.contract_address, facts.span(), CheatSpan::Indefinite);
        s.dual.verify_and_settle_dapv_stark_private_v3(s.hand_binding, 44, s.segment.span());
    }

    #[test]
    #[should_panic(expected: "Settlement fact not registered")]
    fn v3_wrong_variant_rejected() {
        // facts[1] 不是 "VIRTUAL_SNOS"——真实 SNIP-36 交易的 program variant
        // 必须匹配，防其它证明形态伪造 facts。
        let s = setup(false);
        let mut facts = make_facts(
            s.dual.contract_address, s.segment.span(), VIRTUAL_SNOS_HASH,
        );
        let mut tampered = array![];
        let mut w: u32 = 0;
        while w < facts.len() {
            let v = *facts.at(w);
            tampered.append(if w == 1 { 0x1234 } else { v });
            w += 1;
        }
        cheat_proof_facts(s.dual.contract_address, tampered.span(), CheatSpan::Indefinite);
        s.dual.verify_and_settle_dapv_stark_private_v3(s.hand_binding, 44, s.segment.span());
    }

    #[test]
    #[should_panic(expected: "Settlement fact not registered")]
    fn v3_wrong_message_hash_rejected() {
        // facts[8] 用错合约地址重算（消息哈希不匹配 segment）
        let s = setup(false);
        let facts = make_facts(
            get_contract_address(), s.segment.span(), VIRTUAL_SNOS_HASH,
        );
        cheat_proof_facts(s.dual.contract_address, facts.span(), CheatSpan::Indefinite);
        s.dual.verify_and_settle_dapv_stark_private_v3(s.hand_binding, 44, s.segment.span());
    }

    // ===== P2-M6：create_proof 入口（被证明的第一笔交易）=====

    #[test]
    fn create_proof_entry_emits_message_without_state_change() {
        let s = setup(true);
        // 入口只发 L2→L1 消息：结算状态不得变化（v3 才结算）。
        s.dual
            .emit_settlement_proof_message(s.hand_binding, 44, s.segment.span());
        assert!(!s.dual.hand_settled(s.hand_binding), "create_proof must not settle");
        // 幂等：重复证明同一手可重放（仅多付证明费，无状态影响）。
        s.dual
            .emit_settlement_proof_message(s.hand_binding, 44, s.segment.span());
    }

    #[test]
    #[should_panic(expected: "Segment binding mismatch")]
    fn create_proof_entry_rejects_segment_binding_mismatch() {
        // 与 v3 同一组完整性断言：伪造公开段的证明材料在源头即被拒。
        let s = setup(true);
        let forged = segment_with_binding(s.segment.span(), 0xBAD);
        s.dual.emit_settlement_proof_message(s.hand_binding, 44, forged.span());
    }

    #[test]
    #[should_panic(expected: "Binding not registered")]
    fn create_proof_entry_rejects_unregistered_binding() {
        let s = setup(true);
        let ghost: felt252 = 0x90577;
        // 公开段的 binding 词同步替换，才能走到注册态检查。
        let forged = segment_with_binding(s.segment.span(), ghost);
        s.dual.emit_settlement_proof_message(ghost, 44, forged.span());
    }
}

