//! Method AIR 通用列布局与约束宏。
//!
//! 所有 19 个 active method AIR 共享同一组通用列（state_root / method_kind / is_active 等），
//! 业务特定列在每个 AIR 的 `*Air` 结构里定义。
//!
//! ## 列布局策略
//!
//! 每个 method AIR 的 trace 包含：
//! 1. **通用列**（[`COMMON_NUM_COLUMNS`] 个）：所有 AIR 共享
//! 2. **业务列**（每个 AIR 自定义）：业务字段如 max_players, bet_amount 等
//!
//! ## v2.1 Hard Constraint
//!
//! 所有 AIR 约束 degree ≤ 2（gating × binality）。Gating + 业务字段算术约束度 ≤ 3。

use stwo::core::fields::m31::M31;

// ===== 通用列布局（所有 method AIR 共享）=====

/// M31 零元素常量（`M31(pub u32)` 允许直接构造，无需导入 `Zero` trait）。
pub const ZERO: M31 = M31(0);

/// 通用列起始位置（业务列从 `COMMON_NUM_COLUMNS` 开始）。
pub const COL_IS_ACTIVE: usize = 0;
/// `METHOD_KIND` 列索引。
pub const COL_METHOD_KIND: usize = 1;
/// `PRE_STATE_ROOT` 起始列索引（4 个 M31 limb）。
pub const COL_PRE_STATE_ROOT_BASE: usize = 2;
/// `POST_STATE_ROOT` 起始列索引（4 个 M31 limb）。
pub const COL_POST_STATE_ROOT_BASE: usize = 6;
/// `TABLE_ID` 起始列索引（4 个 M31 limb）。
pub const COL_TABLE_ID_BASE: usize = 10;
/// `HAND_ID` 列索引。
pub const COL_HAND_ID: usize = 14;
/// `CALL_SEQ` 列索引。
pub const COL_CALL_SEQ: usize = 15;
/// `PRE_VERSION` 起始列索引（4 个 M31 limb）。
pub const COL_PRE_VERSION_BASE: usize = 16;
/// `POST_VERSION` 起始列索引（4 个 M31 limb）。
pub const COL_POST_VERSION_BASE: usize = 20;
/// `PRE_ROUND_STATE` 列索引。
pub const COL_PRE_ROUND_STATE: usize = 24;
/// `POST_ROUND_STATE` 列索引。
pub const COL_POST_ROUND_STATE: usize = 25;
/// `PRE_POT` 起始列索引（4 个 M31 limb）。
pub const COL_PRE_POT_BASE: usize = 26;
/// `POST_POT` 起始列索引（4 个 M31 limb）。
pub const COL_POST_POT_BASE: usize = 30;
/// `PRE_BUTTON` 列索引。
pub const COL_PRE_BUTTON: usize = 34;
/// `POST_BUTTON` 列索引。
pub const COL_POST_BUTTON: usize = 35;
/// `IS_PADDING` 列索引（padding 行标志位）。
pub const COL_IS_PADDING: usize = 36;

/// 通用列数（state_root 用 4×M31 表示 SecureField）。
pub const COMMON_NUM_COLUMNS: usize = 37;

// ===== 常量辅助 =====

/// MAX_TOTAL_BET = 10^18，全局筹码上界。
/// 对齐 `poker_l1/src/contracts/texas_poker/constants.rs:MAX_TOTAL_BET`。
/// 用于 addon/rebuy/join 的全局上界检查：`chip_pool + amount <= MAX_TOTAL_BET`。
pub const MAX_TOTAL_BET: u64 = 1_000_000_000_000_000_000;

/// MAX_TOTAL_BET 的 4-limb M31 表示（host 端 / AIR 约束用）。
#[must_use]
pub fn max_total_bet_limbs() -> [M31; 4] {
    u64_to_m31_limbs(MAX_TOTAL_BET)
}

/// 把 u64 编码为 4 个 M31（每 limb 16 位）。
#[must_use]
pub fn u64_to_m31_limbs(v: u64) -> [M31; 4] {
    [
        M31::from((v & 0xFFFF) as u32),
        M31::from(((v >> 16) & 0xFFFF) as u32),
        M31::from(((v >> 32) & 0xFFFF) as u32),
        M31::from(((v >> 48) & 0xFFFF) as u32),
    ]
}

/// 把 u8 编码为 M31。
#[must_use]
pub fn u8_to_m31(v: u8) -> M31 {
    M31::from(u32::from(v))
}

/// 把 bool 编码为 M31（0 或 1）。
#[must_use]
pub fn bool_to_m31(b: bool) -> M31 {
    M31::from(u32::from(b))
}

/// 把 4 个 M31 limb 重新组合为 u64（host 端用，AIR 内不需要）。
#[must_use]
pub fn m31_limbs_to_u64(limbs: [M31; 4]) -> u64 {
    // `M31(pub u32)` — 直接访问内部 u32 值（已 mod P，但 limb < 2^16 < P）。
    let l0 = u64::from(limbs[0].0);
    let l1 = u64::from(limbs[1].0);
    let l2 = u64::from(limbs[2].0);
    let l3 = u64::from(limbs[3].0);
    l0 | (l1 << 16) | (l2 << 32) | (l3 << 48)
}

/// 计算规范 4-limb u64 加法 `lhs + rhs = sum` 的 3 个 ripple-carry witness。
///
/// 每个输入/输出 limb 都是 16 bit，因此每级 carry 只能是 0 或 1。调用方需
/// 保证 `lhs.checked_add(rhs)` 成功；u64 溢出不属于可证明的合法状态转换。
#[must_use]
pub fn compute_add_carries(lhs: u64, rhs: u64) -> [M31; 3] {
    let lhs = u64_to_m31_limbs(lhs);
    let rhs = u64_to_m31_limbs(rhs);
    let mut carry = 0u64;
    let mut out = [ZERO; 3];
    for i in 0..3 {
        let limb_sum = u64::from(lhs[i].0) + u64::from(rhs[i].0) + carry;
        carry = limb_sum >> 16;
        debug_assert!(carry <= 1, "two-limb addition carry must be boolean");
        out[i] = M31::from(carry as u32);
    }
    let top_sum = u64::from(lhs[3].0) + u64::from(rhs[3].0) + carry;
    debug_assert!(top_sum < 65536, "u64 addition overflow");
    out
}

/// 计算 4-limb 加法 `cp + am + df = mx` 的进位（host 端用）。
///
/// 返回 `(carry_lo: [M31; 3], carry_hi: [M31; 3])`，其中
/// `carry = lo + 2*hi`（2-bit 分解，carry ∈ {0,1,2,3}）。
///
/// 调用方需保证 `cp + ap + am + df = mx`（u64 意义下成立，无 5th limb 溢出）。
#[must_use]
pub fn compute_bound_carries(chip_pool: u64, amount: u64, diff: u64) -> ([M31; 3], [M31; 3]) {
    let cp = u64_to_m31_limbs(chip_pool);
    let am = u64_to_m31_limbs(amount);
    let df = u64_to_m31_limbs(diff);
    let mx = u64_to_m31_limbs(MAX_TOTAL_BET);

    // Limb 0: cp0 + am0 + df0 = mx0 + c0 * 65536
    let sum0 = u64::from(cp[0].0) + u64::from(am[0].0) + u64::from(df[0].0);
    let c0 = (sum0 - u64::from(mx[0].0)) / 65536;

    // Limb 1: cp1 + ap1 + am1 + df1 + c0 = mx1 + c1 * 65536
    let sum1 = u64::from(cp[1].0) + u64::from(am[1].0) + u64::from(df[1].0) + c0;
    let c1 = (sum1 - u64::from(mx[1].0)) / 65536;

    // Limb 2: cp2 + ap2 + am2 + df2 + c1 = mx2 + c2 * 65536
    let sum2 = u64::from(cp[2].0) + u64::from(am[2].0) + u64::from(df[2].0) + c1;
    let c2 = (sum2 - u64::from(mx[2].0)) / 65536;

    // Limb 3: cp3 + ap3 + am3 + df3 + c2 = mx3 (c3 = 0, no overflow)
    let sum3 = u64::from(cp[3].0) + u64::from(am[3].0) + u64::from(df[3].0) + c2;
    debug_assert_eq!(
        sum3,
        u64::from(mx[3].0),
        "bound check carry overflow: limb3 mismatch"
    );

    let carry_lo = [
        M31::from((c0 % 2) as u32),
        M31::from((c1 % 2) as u32),
        M31::from((c2 % 2) as u32),
    ];
    let carry_hi = [
        M31::from((c0 / 2) as u32),
        M31::from((c1 / 2) as u32),
        M31::from((c2 / 2) as u32),
    ];
    (carry_lo, carry_hi)
}

// ===== 通用约束（AIR evaluate 内调用）=====

/// 通用约束辅助器。
///
/// 在每个 method AIR 的 `evaluate` 函数里调用，验证以下通用约束：
/// 1. `IS_ACTIVE` 与 `IS_PADDING` 互斥且为 boolean
/// 2. `METHOD_KIND` 等于 AIR 声明的 kind（gating）
/// 3. Padding 行：所有通用列为 0（除 IS_PADDING=1）
///
/// 返回 `(is_active, is_padding)` 供业务约束使用。
pub struct CommonConstraints<E: stwo_constraint_framework::EvalAtRow> {
    /// IS_ACTIVE 列。
    pub is_active: E::F,
    /// IS_PADDING 列。
    pub is_padding: E::F,
    /// 方法 kind 列。
    pub method_kind: E::F,
    /// `PRE_ROUND_STATE` 列（业务守卫用，如 bet 的 postflop 校验）。
    pub pre_round_state: E::F,
    /// `POST_ROUND_STATE` 列。
    pub post_round_state: E::F,
    /// `PRE_POT` 全 4 limb（全 limb 资金守恒约束用，如 call/bet/raise 的 PotDelta）。
    pub pre_pot: [E::F; 4],
    /// `POST_POT` 全 4 limb。
    pub post_pot: [E::F; 4],
    /// `PRE_BUTTON` 列（button 不变约束用）。
    pub pre_button: E::F,
    /// `POST_BUTTON` 列。
    pub post_button: E::F,
    /// 是否已经写入通用约束到 eval。
    pub _written: bool,
}

impl<E: stwo_constraint_framework::EvalAtRow> CommonConstraints<E> {
    /// 在 AIR evaluate 中读取通用列并写入通用约束。
    ///
    /// # 参数
    /// - `eval`: Stwo EvalAtRow
    /// - `statement`: verifier independently reconstructed public statement.
    ///
    /// # 返回
    /// `CommonConstraints` 实例，业务约束可用 `is_active` 做 gating。
    pub fn write(eval: &mut E, statement: &crate::airs::AirStatement) -> Self {
        Self::write_with_version_increment(eval, statement, 1)
    }

    /// Same as [`Self::write`], with an explicitly modeled number of native
    /// `bump_version` calls in the transition.
    ///
    /// Most selectors mutate a table exactly once. A final showdown reveal is
    /// the exceptional atomic transition: it records the reveal and then
    /// settles/resets the hand, which performs a second version bump. Callers
    /// must derive this value from the canonical transition rather than from
    /// prover-supplied data.
    pub fn write_with_version_increment(
        eval: &mut E,
        statement: &crate::airs::AirStatement,
        version_increment: u64,
    ) -> Self {
        let one: E::F = M31::from(1u32).into();

        // 读取通用列（顺序必须与 COL_* 常量定义一致）
        let is_active = eval.next_trace_mask();
        let method_kind = eval.next_trace_mask();
        let pre_state_root_0 = eval.next_trace_mask();
        let pre_state_root_1 = eval.next_trace_mask();
        let pre_state_root_2 = eval.next_trace_mask();
        let pre_state_root_3 = eval.next_trace_mask();
        let post_state_root_0 = eval.next_trace_mask();
        let post_state_root_1 = eval.next_trace_mask();
        let post_state_root_2 = eval.next_trace_mask();
        let post_state_root_3 = eval.next_trace_mask();
        let table_id_0 = eval.next_trace_mask();
        let table_id_1 = eval.next_trace_mask();
        let table_id_2 = eval.next_trace_mask();
        let table_id_3 = eval.next_trace_mask();
        let hand_id = eval.next_trace_mask();
        let call_seq = eval.next_trace_mask();
        let pre_version_0 = eval.next_trace_mask();
        let pre_version_1 = eval.next_trace_mask();
        let pre_version_2 = eval.next_trace_mask();
        let pre_version_3 = eval.next_trace_mask();
        let post_version_0 = eval.next_trace_mask();
        let post_version_1 = eval.next_trace_mask();
        let post_version_2 = eval.next_trace_mask();
        let post_version_3 = eval.next_trace_mask();
        let pre_round_state = eval.next_trace_mask();
        let post_round_state = eval.next_trace_mask();
        let pre_pot_0 = eval.next_trace_mask();
        let pre_pot_1 = eval.next_trace_mask();
        let pre_pot_2 = eval.next_trace_mask();
        let pre_pot_3 = eval.next_trace_mask();
        let post_pot_0 = eval.next_trace_mask();
        let post_pot_1 = eval.next_trace_mask();
        let post_pot_2 = eval.next_trace_mask();
        let post_pot_3 = eval.next_trace_mask();
        let pre_button = eval.next_trace_mask();
        let post_button = eval.next_trace_mask();
        let is_padding = eval.next_trace_mask();

        // 通用约束 1：单步 AIR 的每一行都是同一条 active statement 的复制。
        //
        // 单方法低延迟 profile 使用 256 行。此前只把 row 0 标成 active，其余
        // 行 padding，但 AIR 没有可信 first-row selector，导致全 padding trace 可绕过
        // 所有业务约束。这里直接要求每行 active=1、padding=0；重复每个 domain 点虽有
        // 冗余，却不依赖未绑定的边界 witness，彻底关闭 all-padding 绕过。
        let active_minus_one = is_active.clone() - one.clone();
        eval.add_constraint(active_minus_one);
        eval.add_constraint(is_padding.clone());

        // 通用约束 2：所有公共 statement 列逐项绑定到 verifier-trusted AIR。
        let expected: E::F = M31::from(statement.kind as u32).into();
        let kind_diff = method_kind.clone() - expected;
        eval.add_constraint(kind_diff);

        let pre_roots = [
            pre_state_root_0,
            pre_state_root_1,
            pre_state_root_2,
            pre_state_root_3,
        ];
        let post_roots = [
            post_state_root_0,
            post_state_root_1,
            post_state_root_2,
            post_state_root_3,
        ];
        for i in 0..4 {
            eval.add_constraint(pre_roots[i].clone() - statement.pre_state_root[i].into());
            eval.add_constraint(post_roots[i].clone() - statement.post_state_root[i].into());
        }

        let table_cols = [table_id_0, table_id_1, table_id_2, table_id_3];
        let expected_table = u64_to_m31_limbs(statement.table_id);
        for i in 0..4 {
            eval.add_constraint(table_cols[i].clone() - expected_table[i].into());
        }
        eval.add_constraint(hand_id - M31::from(statement.hand_id).into());
        eval.add_constraint(call_seq - M31::from(statement.call_seq).into());

        let pre_version_cols = [pre_version_0, pre_version_1, pre_version_2, pre_version_3];
        let post_version_cols = [
            post_version_0,
            post_version_1,
            post_version_2,
            post_version_3,
        ];
        let expected_pre_version = u64_to_m31_limbs(statement.pre_version);
        let expected_statement_post = u64_to_m31_limbs(statement.post_version);
        for i in 0..4 {
            eval.add_constraint(pre_version_cols[i].clone() - expected_pre_version[i].into());
            eval.add_constraint(post_version_cols[i].clone() - expected_statement_post[i].into());
        }

        // 通用约束 3（审计 C2）：version += 1
        // `post_version = pre_version + 1`（u64）。
        // 期望的 post 各 limb 由 host 已知的 pre_version 在「编译期/host 端」算出，
        // 作为常量注入；AIR 逐 limb 约束 trace 列等于期望值。
        // 这等价于完整的 4-limb ripple-carry 加 1，无需额外 witness 列，且对 u64
        // 任意值（含 limb0 = 0xFFFF 进位情形）均 sound —— 彻底消除「version 不递增」反例。
        // 对齐合约 bump_version 的 saturating_add：u64::MAX 时保持不变（不 wrap 回 0）。
        let expected_post = statement.pre_version.saturating_add(version_increment);
        let expected_post_limbs = u64_to_m31_limbs(expected_post);
        for i in 0..4 {
            eval.add_constraint(post_version_cols[i].clone() - expected_post_limbs[i].into());
        }

        Self {
            is_active,
            is_padding,
            method_kind,
            pre_round_state,
            post_round_state,
            pre_pot: [pre_pot_0, pre_pot_1, pre_pot_2, pre_pot_3],
            post_pot: [post_pot_0, post_pot_1, post_pot_2, post_pot_3],
            pre_button,
            post_button,
            _written: true,
        }
    }

    /// 业务约束的 gating 辅助：`is_active * constraint`。
    pub fn gate(&self, constraint: E::F) -> E::F {
        self.is_active.clone() * constraint
    }

    /// 约束 `pre_round_state == expected`（如 join/leave/start_hand 要求 WAITING=0）。
    ///
    /// degree-2 等式约束。
    pub fn round_state_eq(&self, expected: u8) -> E::F {
        let exp: E::F = M31::from(u32::from(expected)).into();
        self.is_active.clone() * (self.pre_round_state.clone() - exp)
    }

    /// 约束 `pre_round_state ∈ {PREFLOP, FLOP, TURN, RIVER}`（下注轮门控）。
    ///
    /// 用 degree-4 vanishing 多项式 `(rs-2)(rs-3)(rs-4)(rs-5) == 0` 表达
    /// `rs ∈ {2,3,4,5}`。但 4 次多项式（同一列自乘 4 次）总 degree = 4·(2^log_size)
    /// 超过 Stwo 上界 `2^(log_size+1)`，故需调用方提供 witness 列 `q = rs²`，
    /// 把多项式展开为 degree ≤ 2 的项：
    ///   rs⁴ - 14·rs³ + 71·rs² - 154·rs + 120
    ///   = q·q - 14·(rs·q) + 71·q - 154·rs + 120
    /// 其中 `rs·q`、`q·q` 均为两列乘积（degree ~2·2^log_size，在上界内）。
    ///
    /// 调用方需：
    /// 1. 新增 witness 列 `INPUT_PRE_ROUND_STATE_Q`（host 端填 `pre_round_state²`）
    /// 2. 先约束 `q == pre_round_state * pre_round_state`（用 `round_state_q_constraint`）
    /// 3. 再调用本函数传入 `q` 的 trace 值
    ///
    /// 闭合 Lean 审计 Gap 1（RoundStateIsBetting）：阻止恶意 prover 在 `ROUND_WAITING=0`
    /// 状态下构造 fold/check/call/raise/bet/force_fold 的 trace。
    pub fn round_state_is_betting(&self, q: E::F) -> E::F {
        let rs = self.pre_round_state.clone();
        let fourteen: E::F = M31::from(14u32).into();
        let seventy_one: E::F = M31::from(71u32).into();
        let one_hundred_fifty_four: E::F = M31::from(154u32).into();
        let one_hundred_twenty: E::F = M31::from(120u32).into();
        // q² - 14·(rs·q) + 71·q - 154·rs + 120（每项 degree ≤ 2）
        let vp = q.clone() * q.clone() - fourteen * (rs.clone() * q.clone()) + seventy_one * q
            - one_hundred_fifty_four * rs
            + one_hundred_twenty;
        self.is_active.clone() * vp
    }

    /// 约束 `pre_round_state ∈ {FLOP, TURN, RIVER}`，用于只允许 postflop 的 `bet`。
    ///
    /// 三次 vanishing polynomial `(rs-3)(rs-4)(rs-5)` 展开为
    /// `rs³ - 12rs² + 47rs - 60`。复用调用方提供的 `q = rs²` witness 后，
    /// 写成 `rs*q - 12q + 47rs - 60`，约束次数不超过 2。
    pub fn round_state_is_postflop_betting(&self, q: E::F) -> E::F {
        let rs = self.pre_round_state.clone();
        let twelve: E::F = M31::from(12u32).into();
        let forty_seven: E::F = M31::from(47u32).into();
        let sixty: E::F = M31::from(60u32).into();
        self.is_active.clone() * (rs.clone() * q.clone() - twelve * q + forty_seven * rs - sixty)
    }

    /// 约束 `q == pre_round_state²`（Gap 1 witness 一致性，degree-2 两列乘积）。
    /// 配合 `round_state_is_betting(q)` 使用。
    pub fn round_state_q_constraint(&self, q: E::F) -> E::F {
        self.is_active.clone() * (q - self.pre_round_state.clone() * self.pre_round_state.clone())
    }

    /// 约束 `post_round_state == pre_round_state`（round_state 不变）。
    pub fn round_state_unchanged(&self) -> E::F {
        self.is_active.clone() * (self.post_round_state.clone() - self.pre_round_state.clone())
    }

    /// 约束 pot 全 4-limb 不变（`post_pot[i] == pre_pot[i]`，每 limb degree-2）。
    /// 阶段 3 soundness 升级：fold/check 之前仅约束 limb 0，恶意 prover 可在 limb 1-3 造假。
    /// 对齐 Lean 的 pot-unchanged 契约。
    pub fn pot_unchanged_4limb(&self) -> Vec<E::F> {
        // P0-2 修复：逐 limb 独立约束（此前相加成单项可抵消）。
        let mut out = Vec::with_capacity(4);
        for i in 0..4 {
            out.push(self.is_active.clone() * (self.post_pot[i].clone() - self.pre_pot[i].clone()));
        }
        out
    }

    /// 约束 `post_button == pre_button`（button 不变，degree-2）。
    /// 用于 fold/check/call/bet/raise 等 button 不变的方法。
    pub fn button_unchanged(&self) -> E::F {
        self.is_active.clone() * (self.post_button.clone() - self.pre_button.clone())
    }

    /// 约束全局上界 `chip_pool + amount + diff = MAX_TOTAL_BET`，
    /// 其中 `diff = MAX_TOTAL_BET - (chip_pool + amount) ≥ 0`。
    ///
    /// 使用 2-bit carry 分解处理 4 数 limb 加法的进位（carry ∈ {0,1,2,3}）。
    /// 每个 carry 分解为 `lo + 2*hi`，lo/hi 为 boolean（独立 degree-2 约束）。
    ///
    /// # 参数
    /// - `chip_pool`/`amount`/`diff`: 4-limb 输入（每 limb 16-bit）
    /// - `carry_lo`/`carry_hi`: 3 个进位的 2-bit 分解（limb 0→1, 1→2, 2→3 的进位）
    ///
    /// # 约束
    /// 1. 逐 limb: `cp[i] + am[i] + df[i] + carry_in = mx[i] + carry_out * 65536`
    /// 2. 进位 boolean: `lo*(lo-1)=0`, `hi*(hi-1)=0`（6 个 degree-2 约束）
    /// 3. 最终 carry_out = 0（limb 3 方程中 carry_out 项为 0）
    ///
    /// # degree
    /// limb 方程 `is_active * (linear) = degree 2`; boolean `b*(b-1) = degree 2`。
    ///
    /// # Soundness
    /// 由于每 limb < 65536 且 carry ∈ {0,1,2,3}，4 数 limb 之和 < 4×65536 = 262144
    /// < M31_P = 2^31−1，M31 运算无取模，limb 方程等价于 Nat 方程。
    /// 配合 `Limb4Range16` range constraint（diff 全 limb < 65536）可推出
    /// `decodeU64(cp) + decodeU64(am) ≤ MAX_TOTAL_BET`。
    pub fn bound_check_4limb(
        &self,
        chip_pool: &[E::F; 4],
        amount: &[E::F; 4],
        diff: &[E::F; 4],
        carry_lo: &[E::F; 3],
        carry_hi: &[E::F; 3],
    ) -> Vec<E::F> {
        // P0-2 修复：逐 limb 进位关系 + carry booleanity 各自独立约束（此前相加可抵消）。
        let one: E::F = M31::from(1u32).into();
        let two: E::F = M31::from(2u32).into();
        let base: E::F = M31::from(65536u32).into();
        let mx = max_total_bet_limbs();
        let mx_f: [E::F; 4] = [mx[0].into(), mx[1].into(), mx[2].into(), mx[3].into()];

        // carry values: c_i = lo_i + 2 * hi_i
        let c0 = carry_lo[0].clone() + two.clone() * carry_hi[0].clone();
        let c1 = carry_lo[1].clone() + two.clone() * carry_hi[1].clone();
        let c2 = carry_lo[2].clone() + two.clone() * carry_hi[2].clone();

        let mut out = Vec::with_capacity(10);
        // Limb 0: cp0 + ap0 + am0 + df0 - mx0 - c0*65536 = 0 (carry_in = 0)
        out.push(
            self.is_active.clone()
                * (chip_pool[0].clone() + amount[0].clone() + diff[0].clone()
                    - mx_f[0].clone()
                    - c0.clone() * base.clone()),
        );
        // Limb 1: cp1 + ap1 + am1 + df1 + c0 - mx1 - c1*65536 = 0
        out.push(
            self.is_active.clone()
                * (chip_pool[1].clone() + amount[1].clone() + diff[1].clone() + c0.clone()
                    - mx_f[1].clone()
                    - c1.clone() * base.clone()),
        );
        // Limb 2: cp2 + ap2 + am2 + df2 + c1 - mx2 - c2*65536 = 0
        out.push(
            self.is_active.clone()
                * (chip_pool[2].clone() + amount[2].clone() + diff[2].clone() + c1.clone()
                    - mx_f[2].clone()
                    - c2.clone() * base.clone()),
        );
        // Limb 3: cp3 + ap3 + am3 + df3 + c2 - mx3 = 0 (carry_out = 0)
        out.push(
            self.is_active.clone()
                * (chip_pool[3].clone() + amount[3].clone() + diff[3].clone() + c2.clone()
                    - mx_f[3].clone()),
        );
        // carry bit booleanity（6 条独立）
        for i in 0..3 {
            out.push(carry_lo[i].clone() * (carry_lo[i].clone() - one.clone()));
            out.push(carry_hi[i].clone() * (carry_hi[i].clone() - one.clone()));
        }
        out
    }

    /// 约束规范 u64 加法 `post_pot = pre_pot + amt`（4×16-bit limb + ripple carry）。
    pub fn pot_delta_4limb(&self, amt: &[E::F; 4], carry: &[E::F; 3]) -> Vec<E::F> {
        self.limb4_delta(&self.pre_pot, &self.post_pot, amt, carry)
    }

    /// 约束规范 u64 加法 `post = pre + amt`。
    ///
    /// 三个 boolean carry 分别连接 limb 0→1、1→2、2→3；最高 limb 不允许
    /// carry-out，因此该谓词同时表达 Rust `checked_add` 成功。与旧的逐 limb
    /// 无 carry 等式不同，它接受 `0xFFFF + 1 = 0x1_0000` 这类合法转移。
    pub fn limb4_delta(
        &self,
        pre: &[E::F; 4],
        post: &[E::F; 4],
        amt: &[E::F; 4],
        carry: &[E::F; 3],
    ) -> Vec<E::F> {
        let one: E::F = M31::from(1u32).into();
        let base: E::F = M31::from(65536u32).into();
        let zero: E::F = M31::from(0u32).into();
        let carry_in = [
            zero.clone(),
            carry[0].clone(),
            carry[1].clone(),
            carry[2].clone(),
        ];
        let carry_out = [carry[0].clone(), carry[1].clone(), carry[2].clone(), zero];
        let mut out = Vec::with_capacity(7);
        for i in 0..4 {
            out.push(
                self.is_active.clone()
                    * (pre[i].clone() + amt[i].clone() + carry_in[i].clone()
                        - post[i].clone()
                        - base.clone() * carry_out[i].clone()),
            );
        }
        for bit in carry {
            out.push(bit.clone() * (bit.clone() - one.clone()));
        }
        out
    }

    /// 约束规范 u64 减法 `post = pre - amt`，等价写成 `pre = post + amt`。
    ///
    /// 反向使用同一条 ripple-carry 加法链；最高 limb 不允许 carry-out，因此还会
    /// 拒绝下溢后伪造的环绕结果。对齐 Lean `Limb4DeltaRev`。
    pub fn limb4_delta_rev(
        &self,
        pre: &[E::F; 4],
        post: &[E::F; 4],
        amt: &[E::F; 4],
        carry: &[E::F; 3],
    ) -> Vec<E::F> {
        self.limb4_delta(post, pre, amt, carry)
    }

    /// 约束 `a[i] = b[i]`（全 4 limb 相等，每 limb degree-2）。
    /// 对齐 Lean `Limb4Eq`。
    pub fn limb4_eq(&self, a: &[E::F; 4], b: &[E::F; 4]) -> Vec<E::F> {
        // P0-2 修复：逐 limb 独立约束。
        let mut out = Vec::with_capacity(4);
        for i in 0..4 {
            out.push(self.is_active.clone() * (a[i].clone() - b[i].clone()));
        }
        out
    }

    /// 约束 `a ≥ b`（全 4-limb 大于等于，degree-2，阶段 3 新增）。
    ///
    /// 通过 4-limb 减法的借位链实现：`a[i] + 65536·borrow_in[i] - b[i] - diff[i] = 65536·borrow_out[i]`，
    /// 其中 `borrow_in[0]=0`，`borrow_out[i] = borrow_in[i+1]`，且最后一个 `borrow_out[3] = 0`（无下溢）。
    ///
    /// `borrow_in/borrow_out` 序列（4 个 boolean witness）+ `diff`（4 个差值 limb witness）：
    /// - borrow 全为 0/1（booleanity 约束）
    /// - borrow_out[3] = 0 确保减法无下溢 → `decode(a) ≥ decode(b)`（在 Limb4Range16 假设下）
    ///
    /// 对齐 Lean 的 `BuyInGeBigBlind` 约束。
    ///
    /// 参数：`a`（大值，如 buy_in）、`b`（小值，如 big_blind）、`diff`（差值 a-b 的 4 limb witness）、
    /// `borrow`（3 个中间借位 witness，boolean）。
    pub fn ge_4limb(
        &self,
        a: &[E::F; 4],
        b: &[E::F; 4],
        diff: &[E::F; 4],
        borrow: &[E::F; 3],
    ) -> Vec<E::F> {
        // P0-2 修复：逐 limb 借位关系 + 借位 booleanity 各自独立约束（此前相加可抵消）。
        let one: E::F = M31::from(1u32).into();
        let base: E::F = M31::from(65536u32).into();
        let borrow_in = [
            M31::from(0u32).into(),
            borrow[0].clone(),
            borrow[1].clone(),
            borrow[2].clone(),
        ];
        let borrow_out = [
            borrow[0].clone(),
            borrow[1].clone(),
            borrow[2].clone(),
            M31::from(0u32).into(),
        ];
        let mut out = Vec::with_capacity(7);
        // 每 limb 借位关系（4 条独立）
        for i in 0..4 {
            out.push(
                self.is_active.clone()
                    * (a[i].clone() + base.clone() * borrow_out[i].clone()
                        - b[i].clone()
                        - borrow_in[i].clone()
                        - diff[i].clone()),
            );
        }
        // borrow booleanity（3 条独立）
        for i in 0..3 {
            out.push(borrow[i].clone() * (borrow[i].clone() - one.clone()));
        }
        out
    }

    /// 约束单个 M31 值 `x` 落在 [0, 65536)（16-bit range check，阶段 3 新增）。
    ///
    /// 通过 16 个 boolean witness `bits[i]` 做 bit 分解：约束
    /// `x = Σ_{i=0}^{15} bits[i] · 2^i`，且每个 `bits[i] ∈ {0,1}`。
    /// 这让 Lean 的 `LimbRange16` 假设有 AIR 依据（此前是未由 AIR 满足的外部假设）。
    ///
    /// 调用方需为每个要 range-check 的值在 trace 中提供 16 个 boolean witness 列。
    /// padding 行所有 bits=0、x=0，约束平凡满足。
    pub fn range16(&self, x: &E::F, bits: &[E::F; 16]) -> Vec<E::F> {
        // P0-2 修复：重构约束与各 bit booleanity 独立（此前相加可让 bit 翻转抵消）。
        let one: E::F = M31::from(1u32).into();
        let two: E::F = M31::from(2u32).into();
        // x = Σ bits[i] · 2^i（一条独立重构约束）
        let mut recon = bits[0].clone();
        let mut pow2: E::F = two.clone();
        for i in 1..16 {
            recon = recon.clone() + bits[i].clone() * pow2.clone();
            pow2 = pow2.clone() * two.clone();
        }
        let mut out = Vec::with_capacity(17);
        out.push(self.is_active.clone() * (x.clone() - recon));
        // 各 bit booleanity（16 条独立）
        for i in 0..16 {
            out.push(bits[i].clone() * (bits[i].clone() - one.clone()));
        }
        out
    }
}

// ===== trace 生成辅助（host 端）=====

/// 通用 trace 行数据（host 端填充用）。
#[derive(Debug, Clone)]
pub struct CommonRow {
    /// IS_ACTIVE 列（1 = 业务行，0 = padding 行）。
    pub is_active: M31,
    /// METHOD_KIND 列（方法选择器）。
    pub method_kind: M31,
    /// 调用前 state_root（4 个 M31 limb）。
    pub pre_state_root: [M31; 4],
    /// 调用后 state_root（4 个 M31 limb）。
    pub post_state_root: [M31; 4],
    /// 表台 ID（4 个 M31 limb）。
    pub table_id: [M31; 4],
    /// 手牌序号。
    pub hand_id: M31,
    /// 调用序号。
    pub call_seq: M31,
    /// 调用前 version（4 个 M31 limb）。
    pub pre_version: [M31; 4],
    /// 调用后 version（4 个 M31 limb）。
    pub post_version: [M31; 4],
    /// 调用前 round_state。
    pub pre_round_state: M31,
    /// 调用后 round_state。
    pub post_round_state: M31,
    /// 调用前 pot（4 个 M31 limb）。
    pub pre_pot: [M31; 4],
    /// 调用后 pot（4 个 M31 limb）。
    pub post_pot: [M31; 4],
    /// 调用前 button seat index。
    pub pre_button: M31,
    /// 调用后 button seat index。
    pub post_button: M31,
    /// IS_PADDING 列（1 = padding 行，0 = 业务行）。
    pub is_padding: M31,
}

impl CommonRow {
    /// 构造 active 行（业务执行发生）。
    #[must_use]
    pub fn active(
        method_kind: crate::method_kind::MethodKind,
        pre_state_root: [M31; 4],
        post_state_root: [M31; 4],
        table_id: u64,
        hand_id: u32,
        call_seq: u32,
        pre_version: u64,
        post_version: u64,
        pre_round_state: u8,
        post_round_state: u8,
        pre_pot: u64,
        post_pot: u64,
        pre_button: u8,
        post_button: u8,
    ) -> Self {
        Self {
            is_active: M31::from(1u32),
            method_kind: u8_to_m31(method_kind as u8),
            pre_state_root,
            post_state_root,
            table_id: u64_to_m31_limbs(table_id),
            hand_id: M31::from(hand_id),
            call_seq: M31::from(call_seq),
            pre_version: u64_to_m31_limbs(pre_version),
            post_version: u64_to_m31_limbs(post_version),
            pre_round_state: u8_to_m31(pre_round_state),
            post_round_state: u8_to_m31(post_round_state),
            pre_pot: u64_to_m31_limbs(pre_pot),
            post_pot: u64_to_m31_limbs(post_pot),
            pre_button: u8_to_m31(pre_button),
            post_button: u8_to_m31(post_button),
            is_padding: ZERO,
        }
    }

    /// 构造 padding 行（IS_PADDING=1，其他通用列为 0）。
    #[must_use]
    pub fn padding() -> Self {
        Self {
            is_active: ZERO,
            method_kind: ZERO,
            pre_state_root: [ZERO; 4],
            post_state_root: [ZERO; 4],
            table_id: [ZERO; 4],
            hand_id: ZERO,
            call_seq: ZERO,
            pre_version: [ZERO; 4],
            post_version: [ZERO; 4],
            pre_round_state: ZERO,
            post_round_state: ZERO,
            pre_pot: [ZERO; 4],
            post_pot: [ZERO; 4],
            pre_button: ZERO,
            post_button: ZERO,
            is_padding: M31::from(1u32),
        }
    }

    /// 转为列向量（按 COL_* 常量定义顺序）。
    #[must_use]
    pub fn to_vec(&self) -> Vec<M31> {
        let mut v = Vec::with_capacity(COMMON_NUM_COLUMNS);
        v.push(self.is_active);
        v.push(self.method_kind);
        v.extend_from_slice(&self.pre_state_root);
        v.extend_from_slice(&self.post_state_root);
        v.extend_from_slice(&self.table_id);
        v.push(self.hand_id);
        v.push(self.call_seq);
        v.extend_from_slice(&self.pre_version);
        v.extend_from_slice(&self.post_version);
        v.push(self.pre_round_state);
        v.push(self.post_round_state);
        v.extend_from_slice(&self.pre_pot);
        v.extend_from_slice(&self.post_pot);
        v.push(self.pre_button);
        v.push(self.post_button);
        v.push(self.is_padding);
        debug_assert_eq!(v.len(), COMMON_NUM_COLUMNS);
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_u64_m31_roundtrip() {
        for v in [0u64, 1, 255, 65535, 65536, u32::MAX as u64, u64::MAX] {
            let limbs = u64_to_m31_limbs(v);
            assert_eq!(m31_limbs_to_u64(limbs), v, "u64 roundtrip failed: {v}");
        }
    }

    #[test]
    fn test_common_row_padding() {
        let row = CommonRow::padding();
        let v = row.to_vec();
        assert_eq!(v.len(), COMMON_NUM_COLUMNS);
        assert_eq!(v[COL_IS_ACTIVE], ZERO);
        assert_eq!(v[COL_IS_PADDING], M31::from(1u32));
    }

    #[test]
    fn test_common_row_active() {
        let row = CommonRow::active(
            crate::method_kind::MethodKind::CreateTable,
            [M31::from(1u32); 4],
            [M31::from(2u32); 4],
            42,
            7,
            3,
            0,
            1,
            0,
            0,
            0,
            0,
            0,
            0,
        );
        let v = row.to_vec();
        assert_eq!(v[COL_IS_ACTIVE], M31::from(1u32));
        assert_eq!(v[COL_METHOD_KIND], M31::from(0u32)); // CreateTable = 0
        assert_eq!(v[COL_IS_PADDING], ZERO);
        assert_eq!(v[COL_TABLE_ID_BASE], M31::from(42u32));
        assert_eq!(v[COL_HAND_ID], M31::from(7u32));
        assert_eq!(v[COL_CALL_SEQ], M31::from(3u32));
    }
}
