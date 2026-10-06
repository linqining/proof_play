# Web 路由 → VM → AIR：业务逻辑链路说明

> 2026-09-15 新增。回答一个常见问题：**"从 `main.rs` 的 web 服务器路由
> 进去，走的还是不是原来的 Rust 业务逻辑？能不能让 web 直接用 AIR 的
> 逻辑？"** 权威背景见 [`../STATUS.md`](../STATUS.md)（单一状态重构 /
> Stage 2 控制逻辑入 AIR）。

## 一句话结论

**web 路由的动作已经全部由 `poker_l1` VM 执行——VM 是唯一规则裁判，
而 canonical AIR 约束并证明的正是这份 VM 的转移语义。** 换句话说，
"web 使用 AIR 所约束的业务逻辑"这个目标已经由 2026-09-14 的单一状态
重构落地，不需要（也不能）让 web 直接"运行 AIR"。

两个容易混淆的概念先澄清：

- **AIR（`poker_texas_air` 根 crate）是纯证明库**：witness 进 → STARK
  证明出。它是关于"什么样的执行轨迹合法"的约束系统，**不是可执行
  引擎**，没有"用 AIR 跑业务"这回事。
- **规则的可执行形态只有一份**：`poker_l1` 的 `TexasPokerTable` 状态机
  （下文称 VM）。游戏层（`texas/src/pokergame/`）自单一状态重构后是
  **派生视图层**，不做规则判定；本地规则兜底路径已删除。

## 三层职责

```
┌────────────────────────────────────────────────────────────────────┐
│ texas（web/socket 层）                                              │
│   路由 / JWT / 动作签名 / seq 防重放 / 仪式调度（shuffle·reveal·    │
│   reconstruct 窗口）/ Socket.IO 广播 / 派生视图（apply_betting_view）│
│   —— 只判断"谁在说话、现在是不是说话的时候"，不判断"这个动作合不   │
│   合规则"                                                           │
├────────────────────────────────────────────────────────────────────┤
│ poker_l1（VM 规则层，唯一裁判）                                     │
│   TexasPokerTable 状态机：apply_fold/check/call/raise/bet、         │
│   normalize_until_blocked（推街/收注）、盲注与按钮轮转、side pot、  │
│   rake；线程局部 NormalizationTrace 捕获每次 dispatch 的逐步        │
│   pre/post（控制轨迹，AIR 出证的原料）                              │
├────────────────────────────────────────────────────────────────────┤
│ poker_texas_air（AIR 证明层）                                       │
│   canonical_dispatch_trace：DispatchTrace → call_seq 连续行链       │
│   texas_canonical_air：约束（= VM 语义的 M31 代数重述）+ STWO 出证  │
│   HandProofBinding → appchain / Starknet 结算绑定                   │
├────────────────────────────────────────────────────────────────────┤
│ （侧线）poker_protocol：mental poker 密码学（shuffle/reveal/        │
│   reconstruct 证明）。宿主原生验证 + 链上 EC_OP（Plan D 边界），     │
│   AIR 只绑定其 32 字节证明承诺，不在约束内重证曲线方程               │
└────────────────────────────────────────────────────────────────────┘
```

依赖方向：`texas` → `poker_l1` →（`poker_protocol`）；`texas` →
`poker_texas_air` → `poker_l1`。AIR 复用 VM 的业务类型
（`TexasPokerTable`），因此"约束的逻辑"与"执行的逻辑"天然同源。

## 完整调用链

### 1. 下注动作（fold / check / call / raise / all-in）

HTTP 路径（Socket.IO 路径等价，见下）：

```
main.rs:163        POST /api/games/:game_id/action
  → handlers.rs:350    player_action（JWT、pk 归属、seq 单调性校验）
  → socket/mod.rs      get_action_sender —— 每桌独立 mpsc 通道
  → game_loop.rs:1043  process_action（轮次 / 相位 / 仪式窗口校验、
                        动作签名验证 Table::verify_action_sig）
  → table/betting.rs   handle_fold:20 / handle_call:62 / handle_check:98
                        / handle_raise:126 / handle_allin:221
  → vm_session.rs:771  vm_try_bet(pk, action, total_bet)
  → VmSession::try_bet → poker_l1 dispatch（VM 校验并应用，
                        NormalizationTrace 记录逐步 pre/post）
  ← BettingView        （VM 状态的权威投影视图）
  → apply_betting_view  游戏层据此派生自己的下注状态并广播
```

Socket.IO 路径：`socket/handlers.rs` 的 `FOLD/CHECK/CALL/RAISE` 事件 →
`send_simple_action_signed` → **同一条每桌 mpsc** → 同上。两条入口在
`process_action` 汇聚，不存在绕过 VM 的第三条规则路径。

关键语义（`table/betting.rs:13-18` 注释）：

- VM 拒绝 → `refresh_from_vm()` 从 VM 当前状态重派生视图（dispatch 内
  可能已推进相位），游戏层同样拒绝该动作；
- 无实时 VM 镜像 → 不可证明手 → **fail-closed 直接拒绝**。

### 2. Reveal 令牌（揭牌仪式）

```
main.rs:164        POST /api/games/:game_id/reveal-token
  → handlers.rs:429                    submit_reveal_token
  → socket/mod.rs                      submit_reveal_tokens_for_pk
  → table/reveal.rs:337                submit_player_reveal_tokens
  → vm_session.rs:784                  vm_try_reveal
                                        （VM canonical 重排 + 证明验证
                                        + 揭牌窗口推进）
  ← RevealView → 仪式调度 / 手牌·摊牌·公共牌结果广播
```

### 3. 手结束 → AIR 出证 → 上链

```
手终局（fold-win / showdown 完成）
  → hooks.rs:67       on_hand_complete（锁内只取快照，重活全部移出）
  → hooks.rs:148      settle_from_live_mirror（async）
  → hooks.rs:110      build_appchain_hand_proof：
       VmTable.traces ── trace.as_record() ──► DispatchRecord 列表
         → canonical_dispatch_trace.rs:537  witnesses_from_dispatch_records
              （DispatchTrace → call_seq 连续、逐行咬合的 canonical 行链；
                all-in 连跳收注展开为多个单街 AdvanceRound 行）
         → texas_canonical_air.rs:9952      prove_canonical_reveal_completion_batch
              （prove 语义 = host 全量 Rust 重放 validate_batch，fail-closed
                + canonical STARK + flock rules-hash）
         → HandProofBinding（borsh archive + pre/post state root，
              blake2s32 域分离）→ appchain / Starknet 结算上链
```

## fail-closed / fail-soft 语义表

| 场景 | 行为 | 位置 |
| --- | --- | --- |
| 下注/reveal 时无实时 VM 镜像 | 动作直接拒绝（本地规则兜底已删除） | `table/betting.rs` `None` 分支 |
| `TEXAS_SHADOW_PROVER=0` | 不开局 | `table/phases.rs:17` `vm_session::enabled()` |
| deck 终局 bootstrap 失败 / 缺 join 证明 | 中止本手（肇事座位转 sitting_out） | `abort_unprovable_hand` |
| VM dispatch 拒绝 | 游戏层拒绝 + `refresh_from_vm()` 重派生 | `table/betting.rs` `Err` 分支 |
| 终局对账分歧（report.issues 非空） | 拒绝该手结算，绝不带分歧上链 | `hooks.rs` 结算门 |
| prove 前 host 重放失败 | 出证失败（fail-closed） | `prove_canonical_*` |
| 未入证 selector 族（admin/kick/addon…）/ 极早手 / 出证失败 | **fail-soft**：返回 None，回退遗留 Starknet 结算路径 | `hooks.rs:110` |

最后一行是当前唯一的有意放宽，收紧为"每手必须出证"的规格记录在
`STATUS.md`「剩余边界（fail-closed，后续接线规格）」。

## FAQ

**Q：能不能让 web 服务器直接"运行 AIR 里的业务逻辑"？**
不能，且不必要。AIR 是代数中间表示——一组关于执行轨迹的多项式约束
（门控度 ≤2、业务字段 ≤3），它的语义是"什么样的轨迹合法"，不是"如何
计算下一状态"。STARK 的模式必然是：宿主执行（VM）→ 产生轨迹 → 证明
轨迹满足约束 → 验证证明。执行与约束分离正是本仓库 2026-09-14 单一
状态重构的设计（消除双规则引擎导致的失步 bug 族）。

**Q：那 `table/betting.rs` 里为什么还有 Rust 代码？**
那是派生视图层，不是规则判定。`handle_*` 的全部职责是：找到座位 →
`vm_try_bet` 提交 VM → 应用返回的 `BettingView` → 组播玩家消息。任何
看起来像"规则"的判断（min-raise、TDA #41 重开、all-in 处理、轮次完成）
都发生在 VM 内，并最终被 AIR 约束覆盖。

**Q：AIR 在运行时什么时候"说话"？**
每手结束出证、链上/ appchain 验证时。`verify_canonical_tagged_proof`
是生产准入的验证入口；witness-free 的验证结果不得推进生产结算
（`SOUNDNESS.md` / `STATUS.md` 红线）。动作执行期间 AIR 不在线——那是
VM 的职责。

**Q：如果我想提高动作级的约束强度呢？**
两个已在架构上预留的方向（本文档不实施）：接受点后同步跑
`validate_batch` 行链校验（宿主重放，毫秒级 fail-closed）；或把
`build_appchain_hand_proof` 的 fail-soft 收紧为每手强制出证。前者是
监控/早失败增强，后者是结算准入收紧，均见 `STATUS.md` 后续规格。
