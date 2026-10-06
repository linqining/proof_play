//! `create_table` AIR — 创建新桌台。
//!
//! 移植自 [`poker_l1::contracts::texas_poker::dispatch::dispatch_create_table`]
//! 与 [`poker_l1::contracts::texas_poker::types::TexasPokerTable::new`]。
//!
//! ## 业务规约
//!
//! 输入 `CreateTableArgs { max_players, small_blind, big_blind, rit_mode }`：
//! 1. `max_players ∈ [2, 9]`
//! 2. `big_blind > 0`
//! 3. `small_blind <= big_blind`
//! 4. `rit_mode ∈ { RIT_MODE_DISABLED, RIT_MODE_TWICE }`（Run It Twice 桌面
//!    策略，缺省 DISABLED；`MAX_RUNOUTS = 2`，TWICE 在 contested all-in 时双跑）
//!
//! 展示名非共识（v34 起出热状态），不进入本 AIR 的公开输入与约束。
//!
//! 状态变更：
//! - `table_id` 保持不变
//! - `max_players/small_blind/big_blind/rit_mode` 写入 args 值
//! - `pot = 0, button = 0, round_state = ROUND_WAITING, version += 1`
//! - `seats = vec![Seat::empty(); max_players]`
//!
//! ## AIR 列布局
//!
//! - 通用列 37 个（见 [`crate::airs::common`]）
//! - 业务列 16 个：
//!   - `INPUT_MAX_PLAYERS` / `INPUT_SMALL_BLIND_BASE[4]` / `INPUT_BIG_BLIND_BASE[4]`
//!   - `OUTPUT_POT_BASE[4]` / `OUTPUT_BUTTON` / `OUTPUT_ROUND_STATE`
//!   - `INPUT_RIT_MODE`
//!
//! ## 约束清单（degree ≤ 3）
//!
//! 1. 通用约束（见 [`CommonConstraints::write`]）
//! 2. `max_players ∈ [2, 9]`：用 range check 拆解为 8 个 boolean bit
//! 3. `big_blind > 0`：`big_blind * is_nonzero = big_blind`（is_nonzero 是 witness）
//! 4. `small_blind <= big_blind`：`big_blind - small_blind - carry * 2^64 = 0`
//! 5. State 守恒：post_state_root 由 Poseidon252(post preimage) 计算
//! 6. `version += 1`：post_version = pre_version + 1
//! 7. `pot = 0`：post_pot == 0
//! 8. `button = 0`：post_button == 0
//! 9. `round_state = ROUND_WAITING`：post_round_state == 0
//! 10. `rit_mode` 绑定公开输入值，且公开值只能是 DISABLED/TWICE

use stwo::core::fields::m31::M31;
use stwo_constraint_framework::{EvalAtRow, FrameworkEval};

use crate::airs::common::{
    COMMON_NUM_COLUMNS, CommonConstraints, CommonRow, ZERO, u8_to_m31, u64_to_m31_limbs,
};
use crate::error::{TexasAirError, TexasAirResult};
use crate::method_kind::MethodKind;
use crate::public_inputs::TexasPublicInputs;
use crate::state_root::{state_root_to_air_limbs, table_from_state_preimage};

/// `create_table` 业务特定列布局（接在通用列之后）。
pub mod cols {
    use super::COMMON_NUM_COLUMNS;

    /// `INPUT_MAX_PLAYERS` 列索引。
    pub const INPUT_MAX_PLAYERS: usize = COMMON_NUM_COLUMNS + 0;
    /// `INPUT_SMALL_BLIND` 起始列索引（4 个 M31 limb）。
    pub const INPUT_SMALL_BLIND_BASE: usize = COMMON_NUM_COLUMNS + 1;
    /// `INPUT_BIG_BLIND` 起始列索引（4 个 M31 limb）。
    pub const INPUT_BIG_BLIND_BASE: usize = COMMON_NUM_COLUMNS + 5;
    /// `OUTPUT_POT` 起始列索引（4 个 M31 limb）。
    pub const OUTPUT_POT_BASE: usize = COMMON_NUM_COLUMNS + 9;
    /// `OUTPUT_BUTTON` 列索引。
    pub const OUTPUT_BUTTON: usize = COMMON_NUM_COLUMNS + 13;
    /// `OUTPUT_ROUND_STATE` 列索引。
    pub const OUTPUT_ROUND_STATE: usize = COMMON_NUM_COLUMNS + 14;
    /// `INPUT_RIT_MODE` 列索引。
    pub const INPUT_RIT_MODE: usize = COMMON_NUM_COLUMNS + 15;
    /// `create_table` AIR 总列数。
    pub const NUM_COLUMNS: usize = COMMON_NUM_COLUMNS + 16;
}

/// `create_table` AIR 输入参数。
#[derive(Debug, Clone)]
pub struct CreateTableInput {
    /// 最大玩家数（2..=9）。
    pub max_players: u8,
    /// 小盲注。
    pub small_blind: u64,
    /// 大盲注。
    pub big_blind: u64,
    /// Run It Twice 桌面策略（`RIT_MODE_DISABLED` / `RIT_MODE_TWICE`）。
    pub rit_mode: u8,
}

/// `create_table` AIR 公开输入。
#[derive(Debug, Clone)]
pub struct CreateTableAir {
    /// log2(trace 行数)。单方法默认使用低延迟的 8。
    pub log_size: u32,
    /// 输入参数（公开输入）。
    pub input: CreateTableInput,
    /// 调用前 state_root（公开输入，4 个 M31 limb）。
    pub pre_state_root: [M31; 4],
    /// 调用后 state_root（公开输入，4 个 M31 limb）。
    pub post_state_root: [M31; 4],
    /// 表台 ID（公开输入）。
    pub table_id: u64,
    /// 手牌序号。
    pub hand_id: u32,
    /// 调用序号。
    pub call_seq: u32,
    /// 调用前 version。
    pub pre_version: u64,
    /// 调用后 version。
    pub post_version: u64,
}

impl CreateTableAir {
    /// 构造 `create_table` AIR。
    #[must_use]
    pub fn new(
        log_size: u32,
        input: CreateTableInput,
        pre_state_root: [M31; 4],
        post_state_root: [M31; 4],
        table_id: u64,
        hand_id: u32,
        call_seq: u32,
        pre_version: u64,
        post_version: u64,
    ) -> Self {
        Self {
            log_size,
            input,
            pre_state_root,
            post_state_root,
            table_id,
            hand_id,
            call_seq,
            pre_version,
            post_version,
        }
    }

    /// 总列数。
    #[must_use]
    pub const fn num_columns() -> usize {
        cols::NUM_COLUMNS
    }
}

impl FrameworkEval for CreateTableAir {
    fn log_size(&self) -> u32 {
        self.log_size
    }

    /// 所有约束的最大总度 = 3（gating × binality）。
    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_size + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        // 1. 读取并约束通用列
        let statement = crate::airs::TexasAir::statement(self);
        let common = CommonConstraints::write(&mut eval, &statement);
        let is_active = common.is_active.clone();

        // 2. 读取业务列
        let input_max_players = eval.next_trace_mask();
        let input_small_blind: Vec<_> = (0..4).map(|_| eval.next_trace_mask()).collect();
        let input_big_blind: Vec<_> = (0..4).map(|_| eval.next_trace_mask()).collect();
        let output_pot_0 = eval.next_trace_mask();
        let output_pot_1 = eval.next_trace_mask();
        let output_pot_2 = eval.next_trace_mask();
        let output_pot_3 = eval.next_trace_mask();
        let output_button = eval.next_trace_mask();
        let output_round_state = eval.next_trace_mask();
        let input_rit_mode = eval.next_trace_mask();

        // 3. 业务约束 1：max_players ∈ [2, 9]。
        // `CreateTableInput` 是 verifier 重建的公开 statement，因此无效公开值可直接
        // 变成 active 行上的非零常量约束，无需额外 range witness。
        let expected_max_players: E::F = M31::from(u32::from(self.input.max_players)).into();
        let max_players_diff = input_max_players.clone() - expected_max_players;
        eval.add_constraint(is_active.clone() * max_players_diff);
        let invalid_max_players: E::F =
            M31::from(u32::from(!(2..=9).contains(&self.input.max_players))).into();
        eval.add_constraint(is_active.clone() * invalid_max_players);

        // 4-5. 完整绑定两个 64-bit blind，并在 AIR statement 内拒绝零大盲和倒置盲注。
        for limb in 0..4 {
            let expected_big: E::F =
                M31::from(((self.input.big_blind >> (limb * 16)) & 0xFFFF) as u32).into();
            let expected_small: E::F =
                M31::from(((self.input.small_blind >> (limb * 16)) & 0xFFFF) as u32).into();
            eval.add_constraint(is_active.clone() * (input_big_blind[limb].clone() - expected_big));
            eval.add_constraint(
                is_active.clone() * (input_small_blind[limb].clone() - expected_small),
            );
        }
        let zero_big_blind: E::F = M31::from(u32::from(self.input.big_blind == 0)).into();
        let inverted_blinds: E::F =
            M31::from(u32::from(self.input.small_blind > self.input.big_blind)).into();
        eval.add_constraint(is_active.clone() * zero_big_blind);
        eval.add_constraint(is_active.clone() * inverted_blinds);

        // 6. 业务约束 4：output_pot == 0（4 个 limb 都为 0）
        eval.add_constraint(is_active.clone() * output_pot_0.clone());
        eval.add_constraint(is_active.clone() * output_pot_1.clone());
        eval.add_constraint(is_active.clone() * output_pot_2.clone());
        eval.add_constraint(is_active.clone() * output_pot_3.clone());
        for limb in 0..4 {
            eval.add_constraint(is_active.clone() * common.pre_pot[limb].clone());
            eval.add_constraint(is_active.clone() * common.post_pot[limb].clone());
        }

        // 7. 业务约束 5：output_button == 0
        eval.add_constraint(is_active.clone() * output_button.clone());

        // 8. 业务约束 6：output_round_state == ROUND_WAITING (== 0)
        eval.add_constraint(is_active.clone() * output_round_state.clone());

        // 8b. rit_mode 绑定公开输入值；非协议值（∉ {DISABLED, TWICE}）在 active
        // 行上变成非零常量约束，直接不可满足——与 max_players 同一公开输入纪律。
        let expected_rit_mode: E::F = M31::from(u32::from(self.input.rit_mode)).into();
        eval.add_constraint(is_active.clone() * (input_rit_mode.clone() - expected_rit_mode));
        let invalid_rit_mode: E::F =
            M31::from(u32::from(!matches!(
                self.input.rit_mode,
                poker_l1::contracts::texas_poker::constants::RIT_MODE_DISABLED
                    | poker_l1::contracts::texas_poker::constants::RIT_MODE_TWICE
            )))
            .into();
        eval.add_constraint(is_active.clone() * invalid_rit_mode);

        // 9. post_version == pre_version + 1 已由 CommonConstraints 完整约束。

        // 展示名非共识（v34 起出热状态），本 AIR 不再设置名字哈希列/约束；
        // 名字承诺 AIR 消费侧（#22⑤ 约束 10）随 v2 归档机制一并移除。

        // 11. state_root 的 full-width preimage/hash 自洽目前由生产 host verifier
        //     检查并混入 transcript；本 AIR 只约束域分隔 M31 投影，未嵌入 Poseidon AIR。

        eval
    }
}

// ===== trace 生成 =====

/// `create_table` AIR 的 trace 行（含通用 + 业务列）。
#[derive(Debug, Clone)]
pub struct CreateTableRow {
    /// 通用列。
    pub common: CommonRow,
    /// `INPUT_MAX_PLAYERS` 业务列。
    pub input_max_players: M31,
    /// `INPUT_SMALL_BLIND` 业务列（4 个 M31 limb）。
    pub input_small_blind: [M31; 4],
    /// `INPUT_BIG_BLIND` 业务列（4 个 M31 limb）。
    pub input_big_blind: [M31; 4],
    /// `OUTPUT_POT` 业务列（4 个 M31 limb）。
    pub output_pot: [M31; 4],
    /// `OUTPUT_BUTTON` 业务列。
    pub output_button: M31,
    /// `OUTPUT_ROUND_STATE` 业务列。
    pub output_round_state: M31,
    /// `INPUT_RIT_MODE` 业务列。
    pub input_rit_mode: M31,
}

impl CreateTableRow {
    /// 构造 active 行。
    #[must_use]
    pub fn active(
        input: &CreateTableInput,
        pre_state_root: [M31; 4],
        post_state_root: [M31; 4],
        table_id: u64,
        hand_id: u32,
        call_seq: u32,
        pre_version: u64,
        post_version: u64,
    ) -> Self {
        Self {
            common: CommonRow::active(
                MethodKind::CreateTable,
                pre_state_root,
                post_state_root,
                table_id,
                hand_id,
                call_seq,
                pre_version,
                post_version,
                0, // pre_round_state（任意，create 覆写）
                0, // post_round_state = ROUND_WAITING = 0
                0, // pre_pot（任意）
                0, // post_pot = 0
                0, // pre_button
                0, // post_button = 0
            ),
            input_max_players: u8_to_m31(input.max_players),
            input_small_blind: u64_to_m31_limbs(input.small_blind),
            input_big_blind: u64_to_m31_limbs(input.big_blind),
            output_pot: [ZERO; 4],
            output_button: ZERO,
            output_round_state: ZERO, // ROUND_WAITING = 0
            input_rit_mode: u8_to_m31(input.rit_mode),
        }
    }

    /// 构造 padding 行。
    #[must_use]
    pub fn padding() -> Self {
        Self {
            common: CommonRow::padding(),
            input_max_players: ZERO,
            input_small_blind: [ZERO; 4],
            input_big_blind: [ZERO; 4],
            output_pot: [ZERO; 4],
            output_button: ZERO,
            output_round_state: ZERO,
            input_rit_mode: ZERO,
        }
    }

    /// 转为完整列向量（37 通用 + 16 业务 = 53 列）。
    #[must_use]
    pub fn to_vec(&self) -> Vec<M31> {
        let mut v = self.common.to_vec();
        v.push(self.input_max_players);
        v.extend_from_slice(&self.input_small_blind);
        v.extend_from_slice(&self.input_big_blind);
        v.extend_from_slice(&self.output_pot);
        v.push(self.output_button);
        v.push(self.output_round_state);
        v.push(self.input_rit_mode);
        debug_assert_eq!(v.len(), cols::NUM_COLUMNS);
        v
    }
}

/// Project a Starknet field element into the four M31 limbs available in this AIR.
///
/// Four M31 elements cannot losslessly encode a 252-bit field element. The projection is
/// domain-separated and collision resistant rather than a truncation. The full value must also
/// be bound through canonical public inputs.
#[must_use]
pub fn field_to_m31_limbs(f: starknet_crypto::Felt) -> [M31; 4] {
    crate::state_root::state_root_to_air_limbs(crate::state_root::StateRoot::from_field(f))
}

/// Reconstruct the canonical first-call `create_table` transition and its exact AIR row.
///
/// The L1 precompile only permits `create_table` when the shared table object does not yet
/// exist.  It represents that absence with one canonical placeholder table, then overwrites it
/// with `TexasPokerTable::new`, bumps the version, and advances `call_seq`.  Requiring that exact
/// pre/post pair prevents a valid create-table row from being attached to an arbitrary table
/// reinitialisation.
pub fn validate_public_inputs(
    air: &CreateTableAir,
    public_inputs: &TexasPublicInputs,
) -> TexasAirResult<()> {
    use poker_l1::contracts::texas_poker::types::{EMPTY_PLAYER, TexasPokerTable};

    if public_inputs.kind != MethodKind::CreateTable {
        return Err(TexasAirError::SpecViolation(
            "create_table: public-input method kind mismatch".into(),
        ));
    }
    let pre = table_from_state_preimage(&public_inputs.pre_image)?;
    let post = table_from_state_preimage(&public_inputs.post_image)?;
    if pre.id != post.id
        || public_inputs.table_id != pre.id.creation_nonce
        || public_inputs.table_id != post.id.creation_nonce
        || public_inputs.pre_version != u64::from(pre.call_seq)
        || public_inputs.post_version != u64::from(post.call_seq)
        || public_inputs.hand_id != post.hand_id
        || public_inputs.call_seq != post.call_seq
    {
        return Err(TexasAirError::SpecViolation(
            "create_table: public metadata does not match canonical pre/post tables".into(),
        ));
    }

    let canonical_pre = TexasPokerTable::new(pre.id, EMPTY_PLAYER, 2, 1, 1);
    if pre != canonical_pre {
        return Err(TexasAirError::SpecViolation(
            "create_table: canonical first-call placeholder mismatch".into(),
        ));
    }
    if !(2..=9).contains(&air.input.max_players) {
        return Err(TexasAirError::SpecViolation(
            "create_table: max_players must be in [2, 9]".into(),
        ));
    }
    if air.input.big_blind == 0 {
        return Err(TexasAirError::SpecViolation(
            "create_table: big_blind must be non-zero".into(),
        ));
    }
    if air.input.small_blind > air.input.big_blind {
        return Err(TexasAirError::SpecViolation(
            "create_table: small_blind exceeds big_blind".into(),
        ));
    }
    if !matches!(
        air.input.rit_mode,
        poker_l1::contracts::texas_poker::constants::RIT_MODE_DISABLED
            | poker_l1::contracts::texas_poker::constants::RIT_MODE_TWICE
    ) {
        return Err(TexasAirError::SpecViolation(
            "create_table: rit_mode must be RIT_MODE_DISABLED or RIT_MODE_TWICE".into(),
        ));
    }

    let mut expected_post = TexasPokerTable::new(
        pre.id,
        post.creator,
        air.input.max_players,
        air.input.small_blind,
        air.input.big_blind,
    );
    expected_post.rules.rit_mode = air.input.rit_mode;
    expected_post.call_seq = pre.call_seq.checked_add(1).ok_or_else(|| {
        TexasAirError::SpecViolation("create_table: call_seq overflow during replay".into())
    })?;
    expected_post.hand_id = pre.hand_id;
    if post != expected_post {
        return Err(TexasAirError::SpecViolation(
            "create_table: canonical post-table differs from native VM replay".into(),
        ));
    }

    let mut expected_row = CreateTableRow::active(
        &air.input,
        state_root_to_air_limbs(public_inputs.pre_state_root),
        state_root_to_air_limbs(public_inputs.post_state_root),
        public_inputs.table_id,
        public_inputs.hand_id,
        public_inputs.call_seq,
        u64::from(pre.call_seq),
        u64::from(post.call_seq),
    );
    expected_row.common.pre_pot = crate::airs::common::u64_to_m31_limbs(pre.pot);
    expected_row.common.post_pot = crate::airs::common::u64_to_m31_limbs(post.pot);
    let expected_row = expected_row.to_vec();
    let trusted_row = public_inputs.require_expected_trace_row(expected_row.len())?;
    if trusted_row != expected_row {
        return Err(TexasAirError::SpecViolation(
            "create_table: trusted trace row was not reconstructed from canonical public inputs"
                .into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use poker_l1::object_model::ObjectID;
    use poker_l1::contracts::texas_poker::types::{EMPTY_PLAYER, TexasPokerTable};

    fn canonical_transition() -> (
        CreateTableAir,
        TexasPublicInputs,
        TexasPokerTable,
        TexasPokerTable,
    ) {
        let id = ObjectID::new([0xA1; 20], 42);
        let pre = TexasPokerTable::new(id, EMPTY_PLAYER, 2, 1, 1);
        let input = CreateTableInput {
            max_players: 6,
            small_blind: 10,
            big_blind: 20,
            rit_mode: poker_l1::contracts::texas_poker::constants::RIT_MODE_DISABLED,
        };
        let mut post = TexasPokerTable::new(
            id,
            [0xC1; 20],
            input.max_players,
            input.small_blind,
            input.big_blind,
        );
        post.call_seq = 1;
        let mut public_inputs = TexasPublicInputs::from_tables(
            &pre,
            &post,
            MethodKind::CreateTable,
            id.creation_nonce,
            0,
            1,
        )
        .unwrap();
        let row = CreateTableRow::active(
            &input,
            state_root_to_air_limbs(public_inputs.pre_state_root),
            state_root_to_air_limbs(public_inputs.post_state_root),
            id.creation_nonce,
            0,
            1,
            u64::from(pre.call_seq),
            u64::from(post.call_seq),
        );
        public_inputs
            .bind_expected_trace_row(&row.to_vec())
            .unwrap();
        let air = CreateTableAir::new(
            10,
            input,
            state_root_to_air_limbs(public_inputs.pre_state_root),
            state_root_to_air_limbs(public_inputs.post_state_root),
            id.creation_nonce,
            0,
            1,
            u64::from(pre.call_seq),
            u64::from(post.call_seq),
        );
        (air, public_inputs, pre, post)
    }

    #[test]
    fn canonical_public_inputs_reconstruct_first_create() {
        let (air, public_inputs, _, _) = canonical_transition();
        validate_public_inputs(&air, &public_inputs).unwrap();
    }

    #[test]
    fn canonical_public_inputs_reconstruct_rit_enabled_create() {
        use poker_l1::contracts::texas_poker::constants::RIT_MODE_TWICE;

        // rit_mode=TWICE 的建桌必须被原生回放完整绑定：post 镜像
        // rules.rit_mode=TWICE，AIR 列与公开输入同步携带该值。
        let (mut air, public_inputs, pre, post) = canonical_transition();
        air.input.rit_mode = RIT_MODE_TWICE;
        // 故意不修改 post：validate 必须因 post.rules.rit_mode 与输入不一致而拒绝。
        let mismatch = validate_public_inputs(&air, &public_inputs).unwrap_err();
        assert!(mismatch.to_string().contains("native VM replay"));

        // 用带 TWICE 规则的真实 post 重建公开输入，验证必须通过。
        let mut rit_post = post.clone();
        rit_post.rules.rit_mode = RIT_MODE_TWICE;
        let mut rit_inputs = TexasPublicInputs::from_tables(
            &pre,
            &rit_post,
            MethodKind::CreateTable,
            pre.id.creation_nonce,
            0,
            1,
        )
        .unwrap();
        let mut row = CreateTableRow::active(
            &air.input,
            state_root_to_air_limbs(rit_inputs.pre_state_root),
            state_root_to_air_limbs(rit_inputs.post_state_root),
            rit_inputs.table_id,
            rit_inputs.hand_id,
            rit_inputs.call_seq,
            u64::from(rit_inputs.pre_version),
            u64::from(rit_inputs.post_version),
        );
        row.common.pre_pot = crate::airs::common::u64_to_m31_limbs(pre.pot);
        row.common.post_pot = crate::airs::common::u64_to_m31_limbs(rit_post.pot);
        rit_inputs.bind_expected_trace_row(&row.to_vec()).unwrap();
        let rit_air = CreateTableAir::new(
            air.log_size,
            air.input.clone(),
            state_root_to_air_limbs(rit_inputs.pre_state_root),
            state_root_to_air_limbs(rit_inputs.post_state_root),
            rit_inputs.table_id,
            rit_inputs.hand_id,
            rit_inputs.call_seq,
            u64::from(rit_inputs.pre_version),
            u64::from(rit_inputs.post_version),
        );
        validate_public_inputs(&rit_air, &rit_inputs).unwrap();
    }

    #[test]
    fn public_input_validation_rejects_unknown_rit_mode() {
        let (mut air, public_inputs, _, _) = canonical_transition();
        air.input.rit_mode = 7;
        let error = validate_public_inputs(&air, &public_inputs).unwrap_err();
        assert!(error.to_string().contains("rit_mode"));
    }

    #[test]
    fn public_input_validation_rejects_table_reinitialisation() {
        let (air, _, mut pre, post) = canonical_transition();
        pre.creator = [0xA5; 20];
        let mut public_inputs = TexasPublicInputs::from_tables(
            &pre,
            &post,
            MethodKind::CreateTable,
            pre.id.creation_nonce,
            post.hand_id,
            post.call_seq,
        )
        .unwrap();
        let row = CreateTableRow::active(
            &air.input,
            state_root_to_air_limbs(public_inputs.pre_state_root),
            state_root_to_air_limbs(public_inputs.post_state_root),
            public_inputs.table_id,
            public_inputs.hand_id,
            public_inputs.call_seq,
            u64::from(pre.call_seq),
            u64::from(post.call_seq),
        );
        public_inputs
            .bind_expected_trace_row(&row.to_vec())
            .unwrap();

        let error = validate_public_inputs(&air, &public_inputs).unwrap_err();
        assert!(error.to_string().contains("first-call placeholder"));
    }

    #[test]
    fn public_input_validation_rejects_post_state_unrelated_to_air_input() {
        let (air, _, pre, mut post) = canonical_transition();
        // 名字出共识后，post 的业务篡改以 pot 标记（create 后 pot 必须为 0）。
        post.pot = 123;
        let mut public_inputs = TexasPublicInputs::from_tables(
            &pre,
            &post,
            MethodKind::CreateTable,
            pre.id.creation_nonce,
            post.hand_id,
            post.call_seq,
        )
        .unwrap();
        let row = CreateTableRow::active(
            &air.input,
            state_root_to_air_limbs(public_inputs.pre_state_root),
            state_root_to_air_limbs(public_inputs.post_state_root),
            public_inputs.table_id,
            public_inputs.hand_id,
            public_inputs.call_seq,
            u64::from(pre.call_seq),
            u64::from(post.call_seq),
        );
        public_inputs
            .bind_expected_trace_row(&row.to_vec())
            .unwrap();

        let error = validate_public_inputs(&air, &public_inputs).unwrap_err();
        assert!(error.to_string().contains("native VM replay"));
    }

    #[test]
    fn test_create_table_row_active_columns() {
        let input = CreateTableInput {
            max_players: 6,
            small_blind: 10,
            big_blind: 20,
            rit_mode: poker_l1::contracts::texas_poker::constants::RIT_MODE_TWICE,
        };
        let row = CreateTableRow::active(
            &input,
            [M31::from(1u32); 4],
            [M31::from(2u32); 4],
            42,
            1,
            1,
            0,
            1,
        );
        let v = row.to_vec();
        assert_eq!(v.len(), cols::NUM_COLUMNS);
        // 通用列检查
        assert_eq!(v[crate::airs::common::COL_IS_ACTIVE], M31::from(1u32));
        assert_eq!(v[crate::airs::common::COL_METHOD_KIND], M31::from(0u32));
        // 业务列检查
        assert_eq!(v[cols::INPUT_MAX_PLAYERS], M31::from(6u32));
        assert_eq!(v[cols::INPUT_SMALL_BLIND_BASE], M31::from(10u32));
        assert_eq!(v[cols::INPUT_BIG_BLIND_BASE], M31::from(20u32));
        assert_eq!(v[cols::OUTPUT_BUTTON], ZERO);
        assert_eq!(v[cols::OUTPUT_ROUND_STATE], ZERO);
        assert_eq!(v[cols::INPUT_RIT_MODE], M31::from(1u32));
    }

    #[test]
    fn test_create_table_row_padding() {
        let row = CreateTableRow::padding();
        let v = row.to_vec();
        assert_eq!(v.len(), cols::NUM_COLUMNS);
        // padding 行全部为 0（除 IS_PADDING=1）
        assert_eq!(v[crate::airs::common::COL_IS_ACTIVE], ZERO);
        assert_eq!(v[crate::airs::common::COL_IS_PADDING], M31::from(1u32));
        assert_eq!(v[cols::INPUT_MAX_PLAYERS], ZERO);
    }

    #[test]
    fn test_num_columns_consistency() {
        // 通用 37 + 业务 16 = 53
        assert_eq!(cols::NUM_COLUMNS, COMMON_NUM_COLUMNS + 16);
        assert_eq!(CreateTableAir::num_columns(), cols::NUM_COLUMNS);
    }
}
