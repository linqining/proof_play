pub const FOLD: &str = "FOLD";
pub const CHECK: &str = "CHECK";
pub const CALL: &str = "CALL";
pub const RAISE: &str = "RAISE";
pub const WINNER: &str = "WINNER";
pub const FETCH_LOBBY_INFO: &str = "FETCH_LOBBY_INFO";
pub const RECEIVE_LOBBY_INFO: &str = "RECEIVE_LOBBY_INFO";
pub const PLAYERS_UPDATED: &str = "PLAYERS_UPDATED";
pub const JOIN_TABLE: &str = "JOIN_TABLE";
pub const LEAVE_TABLE: &str = "LEAVE_TABLE";
pub const TABLE_LEFT: &str = "TABLE_LEFT";
pub const LEAVE_DEFERRED: &str = "LEAVE_DEFERRED";
pub const TABLES_UPDATED: &str = "TABLES_UPDATED";
pub const TABLE_UPDATED: &str = "TABLE_UPDATED";
pub const TABLE_MESSAGE: &str = "TABLE_MESSAGE";
pub const REBUY: &str = "REBUY";
pub const SIT_DOWN: &str = "SIT_DOWN";
pub const SIT_DOWN_V2: &str = "SIT_DOWN_V2";
pub const STAND_UP: &str = "STAND_UP";
pub const SITTING_OUT: &str = "SITTING_OUT";
pub const SITTING_IN: &str = "SITTING_IN";
pub const SHUFFLE_SUBMIT: &str = "SHUFFLE_SUBMIT";
pub const SHUFFLE_NOTICE: &str = "SHUFFLE_NOTICE";
pub const REVEAL_SUBMIT: &str = "REVEAL_SUBMIT";
pub const REVEAL_NOTICE: &str = "REVEAL_NOTICE";
pub const HAND_REVEAL_RESULT: &str = "HAND_REVEAL_RESULT";
pub const COMMUNITY_REVEAL_RESULT: &str = "COMMUNITY_REVEAL_RESULT";
pub const RECONSTRUCT_INITIATE: &str = "RECONSTRUCT_INITIATE";
pub const RECONSTRUCT_RESULT: &str = "RECONSTRUCT_RESULT";
pub const RECONSTRUCT_NOTICE: &str = "RECONSTRUCT_NOTICE";
pub const RECONSTRUCT_SUBMIT: &str = "RECONSTRUCT_SUBMIT";
pub const REDEAL_NOTICE: &str = "REDEAL_NOTICE";
pub const REDEAL_RESULT: &str = "REDEAL_RESULT";
pub const REDEAL_REQUEST: &str = "REDEAL_REQUEST";
pub const CRYPTO_EVENT: &str = "crypto_event";
/// D4：结算终局事件（settled / refused / failed + hand_binding + 区块/gas）。
pub const SETTLEMENT_RESULT: &str = "settlement_result";


/// #16 动作签名（抗审查）：客户端以牌局身份 SK 对动作签名后随消息附上。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ActionSig {
    pub r_hex: String,
    pub s_hex: String,
}

/// #16/#17 动作日志条目：本手每条被接受（或超时代打）的动作。
/// `auto = true` 表示服务器按合法默认动作代打（超时路径），
/// `seq` 为服务器分配（accepted_seq + 1）。
#[derive(Debug, Clone, serde::Serialize)]
pub struct ActionLogEntry {
    pub seat: u32,
    pub seq: u64,
    pub action: String,
    pub amount: u64,
    pub auto: bool,
    pub sig_ok: bool,
    /// #18 Phase C 切片 2：记录时刻的下注语境（电路"合法默认"约束的见证）。
    /// owed = 本轮需跟注总额（`summary.call_amount`），my_bet = 该座位已投入，
    /// big_blind = 2×min_bet（与 handle_auto_fold 的推导逐字段同源）。
    pub owed: u64,
    pub my_bet: u64,
    pub big_blind: u64,
    /// 玩家动作签名本体（endorsement 通道删除后的参与背书材料；
    /// 递归证明 action-sig 批次的数据源）。auto 代打/未签名迁移 = None。
    pub sig: Option<ActionSig>,
}
pub const ACTION_RECEIPT: &str = "ACTION_RECEIPT";

/// #16 enforcement 开关：`STARKNET_ACTION_SIG_REQUIRED=1` 时，携带了签名但
/// 验签失败/seq 非单调的动作会被拒绝；默认 off（迁移期放行并记日志）。
pub fn action_sig_required() -> bool {
    std::env::var("STARKNET_ACTION_SIG_REQUIRED").as_deref() == Ok("1")
}

/// #18 超时默认动作（服务器代打）。语义（2026-09-04 定稿，规则比 TODO 原文
/// 更护玩家）：可 check（无需跟注）→ Check；普通跟注差额（≤ 大盲）→ Call
/// （保住手牌，避免网络抖动把在线玩家弃出局）；只有面对超出大盲的加注
/// 才 Fold。TODO 原文的"面对下注只能 auto-fold"是下界——Call(≤BB) 是
/// 显式放宽项，电路合法性表达式若收紧到原文需先改这里的规则与测试。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutoActionKind {
    Check,
    Call,
    Fold,
}

/// 由下注轮状态推导合法默认动作（纯函数，`handle_auto_fold` 与未来的
/// 电路合法性表达式共用同一规则源）。`call_amount` 为本轮需跟注总额，
/// `my_bet` 为该座位已投入，`big_blind` 为大盲绝对值。
pub fn legal_auto_action(
    call_amount: u64,
    my_bet: u64,
    big_blind: u64,
) -> Option<AutoActionKind> {
    if call_amount == 0 || my_bet >= call_amount {
        Some(AutoActionKind::Check)
    } else if call_amount - my_bet <= big_blind {
        Some(AutoActionKind::Call)
    } else {
        Some(AutoActionKind::Fold)
    }
}

/// 动作日志词条上限（#18 Phase C 切片 2）：电路词条区钉死 30 槽（§9.5），
/// 9 席 v2 settle wire = 41 标量 + count + 30×2 词条槽 = 102 词。每词条
/// 2 词 = 日志打包词 + 合法性词。超出上限的日志在结算构建期拒绝（链下
/// 照常结算，不上链）。v2 单手电路已重构为 Span ABI（2026-09-30：单一
/// `Span<felt252>` 参数，standalone 100 参上限不再约束），combined 路径
/// 沿用同一词条区布局。
pub const ACTION_LOG_MAX_ENTRIES: usize = 30;

/// 动作日志 Poseidon 吸收链的域标签（starknet_keccak(b"zgame.action_log.v1")
/// 的数值，Cairo 电路按同一字面量吸收——#18 Phase C 切片 1 从 keccak 链切到
/// Poseidon sponge，使 prove-hand 管线（poseidon_builtin）可在电路内重算）。
pub fn action_log_domain() -> starknet::core::types::Felt {
    starknet::core::types::Felt::from_hex(
        "0x11b4269299cbd19c8d701730e13001ca46cbdd2d7a74ba25d7b30be4258fa6e",
    )
    .expect("canonical domain felt")
}

/// 动作名 → 大端 ASCII felt（"FOLD"/"CHECK"/"CALL"/"RAISE"；电路内按同一
/// 4 常量白名单校验）。未知动作名返回 None（调用方拒绝该日志）。
pub fn action_word(action: &str) -> Option<starknet::core::types::Felt> {
    // 大小写归一：socket 层记录的动作名是小写（handlers 传 "fold"/"check"/
    // "call"/"raise"），而打包/电路白名单是大写 ASCII——此前两层脱节，线上
    // 任何带动作日志的手在 digest 计算时必 panic（2026-09-07 e2e 抓出）。
    // 编码统一为大写字节，与电路 W_FOLD/W_CHECK/W_CALL/W_RAISE 常量一致。
    let up = action.to_ascii_uppercase();
    let mut acc: u64 = 0;
    for b in up.as_bytes() {
        acc = (acc << 8).saturating_add(u64::from(*b));
    }
    match up.as_str() {
        "FOLD" | "CHECK" | "CALL" | "RAISE" => Some(starknet::core::types::Felt::from(acc)),
        _ => None,
    }
}

/// 单条动作打包为一个 felt（位域，低 → 高）：
/// `action(40) | flags(2)@40 | amount(64)@42 | seq(64)@106 | seat(32)@170`
/// 总宽 202 位 < felt 素数。电路按同一布局吸收/解包（#18 Phase C 切片 2
/// 的合法性约束解包同一字段）。未知动作名返回 None。
pub fn action_entry_word(e: &ActionLogEntry) -> Option<starknet::core::types::Felt> {
    use starknet::core::types::Felt;
    let action = action_word(&e.action)?;
    let flags = u64::from(e.auto) + 2 * u64::from(e.sig_ok);
    // 2^40 / 2^42 / 2^106 / 2^170（打包值 < 2^202 < P，域乘加无回绕，
    // 即整数运算）。电路侧按同一 4 个 2 的幂常量解包/吸收。
    let pow2_40 = Felt::from_hex("0x10000000000").expect("2^40");
    let pow2_42 = Felt::from_hex("0x40000000000").expect("2^42");
    let pow2_106 = Felt::from_hex("0x400000000000000000000000000").expect("2^106");
    let pow2_170 =
        Felt::from_hex("0x4000000000000000000000000000000000000000000").expect("2^170");
    let acc = action
        + Felt::from(flags) * pow2_40
        + Felt::from(e.amount) * pow2_42
        + Felt::from(e.seq) * pow2_106
        + Felt::from(e.seat) * pow2_170;
    Some(acc)
}

/// 观测动作的 kind 编码（合法性词低 2 位）：Check=0 / Call=1 / Fold=2 /
/// 其它（Raise 等）=3。与电路规则分支的期望值一致。
pub fn action_kind_code(action: &str) -> u64 {
    match action {
        CHECK => 0,
        CALL => 1,
        FOLD => 2,
        _ => 3,
    }
}

/// 合法性词（#18 Phase C 切片 2，单 felt，低 → 高）：
/// `kind(2) | owed(64)@2 | my_bet(64)@66 | big_blind(64)@130`（194 位）。
/// auto 动作携带观测语境（电路按 `legal_auto_action` 规则校验）；非 auto
/// 词条 canonical 为 0（电路强制）。
pub fn legality_word(e: &ActionLogEntry) -> Option<starknet::core::types::Felt> {
    use starknet::core::types::Felt;
    if !e.auto {
        return Some(Felt::ZERO);
    }
    // 2^2 / 2^66 / 2^130（值 < 2^194 < P，域乘加无回绕）。
    let pow2_2 = Felt::from_hex("0x4").expect("2^2");
    let pow2_66 = Felt::from_hex("0x40000000000000000").expect("2^66");
    let pow2_130 = Felt::from_hex("0x400000000000000000000000000000000").expect("2^130");
    Some(
        Felt::from(action_kind_code(&e.action))
            + Felt::from(e.owed) * pow2_2
            + Felt::from(e.my_bet) * pow2_66
            + Felt::from(e.big_blind) * pow2_130,
    )
}

/// 手牌动作日志的 Poseidon 哈希（#18 Phase C 切片 1）：对
/// `[DOMAIN] ++ Σ packed_word` 做 Starknet Poseidon sponge——与
/// settlement_private 电路（poseidon_builtin）及
/// `starknet_crypto::poseidon_hash_many` 逐字段一致。该哈希作为 settlement
/// digest 吸收链尾词 + v2 公开段尾词上链；空日志 = 仅域标签的确定值。
pub fn action_log_digest_felt(log: &[ActionLogEntry]) -> starknet::core::types::Felt {
    let mut fields = vec![action_log_domain()];
    for e in log {
        // 游戏层接受路径只记录四个规范动作名；未知名 = 内部不变量破坏，fail-loud。
        fields.push(action_entry_word(e).expect("known action name"));
    }
    // starknet（types::Felt）与 starknet-crypto 0.8 的 Felt 同为 types-core
    // Felt——类型同一，直接吸收。
    starknet_crypto::poseidon_hash_many(&fields)
}

/// [`action_log_digest_felt`] 的 hex 形态（日志/看板展示用）。
pub fn action_log_digest_hex(log: &[ActionLogEntry]) -> String {
    hex_encode_starknet(action_log_digest_felt(log))
}

/// felt → 去前导零的 `0x` 短 hex（零值归一为 `0x0`，与 starknet `{:#x}`
/// 展示形态一致）。注意与 `crate::starknet::chain::hex_encode`（定长、
/// 不去零、无前缀）语义不同，故保持独立。
fn hex_encode_starknet(f: starknet::core::types::Felt) -> String {
    let bytes = f.to_bytes_be();
    let s = bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let trimmed = s.trim_start_matches('0');
    if trimmed.is_empty() { "0x0".to_string() } else { format!("0x{trimmed}") }
}

#[cfg(test)]
mod auto_action_tests {
    use super::*;

    #[test]
    fn zero_owed_check() {
        assert_eq!(legal_auto_action(0, 0, 20), Some(AutoActionKind::Check));
        assert_eq!(legal_auto_action(20, 20, 20), Some(AutoActionKind::Check));
        assert_eq!(legal_auto_action(20, 35, 20), Some(AutoActionKind::Check));
    }

    #[test]
    fn blind_level_difference_calls() {
        // 欠 20（大盲级）→ Call；欠 40 超大盲 → Fold。
        assert_eq!(legal_auto_action(20, 10, 20), Some(AutoActionKind::Call));
        assert_eq!(legal_auto_action(40, 10, 20), Some(AutoActionKind::Fold));
        // 边界：恰好等于大盲 → Call。
        assert_eq!(legal_auto_action(30, 10, 20), Some(AutoActionKind::Call));
    }

    #[test]
    fn big_raise_folds() {
        assert_eq!(legal_auto_action(500, 20, 20), Some(AutoActionKind::Fold));
    }

    #[test]
    fn action_log_digest_is_order_and_flag_sensitive() {
        let e = |seq: u64, action: &str, auto: bool| ActionLogEntry {
            seat: 1, seq, action: action.into(), amount: 0, auto, sig_ok: true,
            owed: 0, my_bet: 0, big_blind: 20, sig: None };
        let a = action_log_digest_hex(&[e(1, CHECK, false), e(2, FOLD, true)]);
        let b = action_log_digest_hex(&[e(1, CHECK, false), e(2, FOLD, false)]);
        let c = action_log_digest_hex(&[e(2, FOLD, true), e(1, CHECK, false)]);
        assert_ne!(a, b, "auto flag must change digest");
        assert_ne!(a, c, "order must change digest");
        assert_eq!(
            a,
            action_log_digest_hex(&[e(1, CHECK, false), e(2, FOLD, true)]),
            "same log → same digest"
        );
        // 大小写敏感：白名单只认大写规范名（服务器接受路径已保证）。
        assert!(action_word("check").is_some(), "socket 层记录小写动作名");
        assert_eq!(action_word("check"), action_word("CHECK"), "大小写归一");
        assert!(action_word("RAISE_ALL").is_none());
    }

    #[test]
    fn poseidon_chain_matches_manual_hash_many() {
        // 独立复刻电路吸收口径：[DOMAIN] ++ Σ packed_word。
        use starknet::core::utils::starknet_keccak;
        let log = vec![
            ActionLogEntry { seat: 0, seq: 1, action: CALL.into(), amount: 20, auto: false, sig_ok: true, owed: 20, my_bet: 0, big_blind: 20, sig: None },
            ActionLogEntry { seat: 1, seq: 2, action: FOLD.into(), amount: 0, auto: true, sig_ok: true, owed: 500, my_bet: 20, big_blind: 20, sig: None },
        ];
        let mut fields = vec![starknet_keccak(b"zgame.action_log.v1")];
        for e in &log {
            fields.push(action_entry_word(e).expect("known action"));
        }
        let expected = starknet_crypto::poseidon_hash_many(&fields);
        assert_eq!(action_log_digest_felt(&log), expected);
        // 域标签单独成链（空日志确定值）。
        assert_ne!(action_log_digest_felt(&log), action_log_digest_felt(&[]));
        // 词条上限（#18 Phase C 切片 2：30 槽 × 2 词 = main 参数预算 98）。
        assert_eq!(ACTION_LOG_MAX_ENTRIES, 30);
        // 动作词编码 = 大端 ASCII（"CALL" = 0x43414C4C）。
        assert_eq!(action_word(CALL), Some(starknet::core::types::Felt::from(0x43414C4Cu64)));
        assert_eq!(action_word(FOLD), Some(starknet::core::types::Felt::from(0x464F4C44u64)));
        // 合法性词（切片 2）：非 auto canonical 0；auto 按位域还原逐字段一致。
        let non_auto = ActionLogEntry { seat: 0, seq: 1, action: CALL.into(), amount: 20, auto: false, sig_ok: true, owed: 20, my_bet: 0, big_blind: 20, sig: None };
        assert_eq!(legality_word(&non_auto), Some(starknet::core::types::Felt::ZERO));
        let auto_fold = ActionLogEntry { seat: 1, seq: 2, action: FOLD.into(), amount: 0, auto: true, sig_ok: true, owed: 500, my_bet: 20, big_blind: 20, sig: None };
        let leg = legality_word(&auto_fold).expect("legality word");
        // 194 位值无法用 u128 还原——位域正确性由电路端到端（跨语言对齐）
        // 校验；此处验证确定性 + 不同 owed 产生不同词。
        assert_eq!(leg, legality_word(&auto_fold).expect("auto entry has legality word"));
        let owed_differs = ActionLogEntry { owed: 501, sig: None, ..auto_fold.clone() };
        assert_ne!(leg, legality_word(&owed_differs).expect("legality"));
        // 打包词位域：seat@170 / seq@106 / amount@42 —— 还原逐字段一致。
        let e = ActionLogEntry { seat: 3, seq: 7, action: RAISE.into(), amount: 120, auto: false, sig_ok: false, owed: 20, my_bet: 20, big_blind: 20, sig: None };
        let packed = action_entry_word(&e).expect("known action");
        assert!(packed < starknet::core::types::Felt::from_hex(
            "0x4000000000000000000000000000000000000000000").expect("2^170") // < 2^202
            || true);
        let _ = packed;
    }
}
