> ⚠️ **历史存档(2026-09-05 归档)**:"链交易重放"信任模型已随仓库模型变更失效——
> 现模型 = Starknet 链下 stwo 证明程序,不存在链交易重放概念;poker_l1 链机制
> (state kernel/coordinator/authenticate_receipt_l1)已于 Phase 1 删除。
> 现行信任边界见 `README.md` 信任模型章节与 `strk20.json` proof_policy。

# 不依赖交易回放的信任模型

本文针对本项目当前 STARK proving 流程，说明如何把“host
回放交易后才接受证明”的信任边界，改成“不回放交易，但仍能验证状态迁移”的边界。
这里的“不回放”是指服务端不再重新执行交易 payload 来推导 post-state；它不等于
不验证交易的共识包含性，也不等于信任 RPC 返回的任意 mapping。

**状态：分层迁移已落地，完整业务 AIR 仍未完成。** 独立 workspace 现在提供
`TexasTransitionReceipt`、历史 mapping inclusion proof 和不可构造的
`AuthenticatedTexasReceipt`。它们可以把直接 tagged proof 绑定到 finalized
state root，而不执行交易回放。旧 `ProveTask`/VM replay 路径仍保留给兼容和审计；
由于 tagged AIR 尚未覆盖完整 `TexasPokerTable`、结算和密码协议，当前入口仍不能
宣称已经证明完整 VM 共识迁移。

## 当前边界

### `poker_texas_air` 直接路径的新增边界

`texas_tagged::verify_tagged_texas_proof` 和
`texas_canonical_air::verify_canonical_tagged_proof` 现在可以只使用归档中的公开
scope 和 Stwo proof 完成验证，不再读取 `ProveTask`、交易 payload 或执行 native VM
replay。前者只证明 betting/funding/leave 的投影关系；后者证明 26-kind canonical
trace 的形状、selector、序号、表作用域和相邻 state-image commitment 链接，并证明
下注完成后所有 seat `bet` 被精确收集进 pot；它还在 AIR 内约束 permissionless/actor
authority、settlement commitment 不变，以及 transition/nullifier 非零。canonical
trace builder 仍调用 `validate_batch` 做 prover-side witness hygiene，但 verifier 不调用它，
也不能把它当作 admission 语义；mutation tests 会在构造 trace 后绕过该检查，直接验证
AIR 自身是否拒绝伪造。固定宽度 ABI guards（例如 crypto commitment、AdvanceRound
opening/padding）同样只负责尽早报错；
`CanonicalTransitionWitness::validate_shape` 仍是可选结构检查，不应被当作完整
VM 语义证明。未列入 AIR 的 selector relation 仍必须在生产 admission 中 fail-closed。
这只消除了 verifier 的回放依赖；它没有把 prover 提供的
`TexasStateImage` 变成链上事实。当前 AIR 已为 betting 与可寻址 lifecycle
actions 打开全部九个 seat 的 mutable image（状态、stack、bet、total_bet、pending
addon、time bank），并约束 Create/Start 的 seat 不变性、目标 lifecycle
action 的非目标 seat 不变性、StartHand 的非零 deadline，以及
`SetLeaveAfterHand` 的精确九位掩码写入。`AdvanceDeadline` 还以 64-bit limb/
carry/range relation 证明 action height 不早于 pre deadline。`flag = true` 的
shuffle-timeout 微步骤也已进入同一 AIR：它绑定最低 pending active seat、`auxiliary = 2`、
`shuffle_timeout_ms` deadline、`stack + pending_addon` refund、pot/chip-pool 守恒、Out 状态、
key/hole 清零、total/time-bank 历史、非目标 seat 不变，以及至少两人的新 pending mask 和非零
deck commitment。该关系只证明固定宽度的非零 deck-rebuild statement，不重算洗牌密码学；其它
timeout 分支和 crypto-state commitment 仍需专用关系，也未在同一 AIR 内重算 state image 的
Blake2b digest/state root。

`FoldWithProof`、`SubmitShuffle`、`SubmitReveal` 和 `SubmitReconstruct` 的 ABI 字段仍然
保留，但 canonical direct AIR 当前对这四类 selector 统一 fail-closed：独立的 crypto AIR
尚未与 canonical state-image relation 组合，因此非零 proof commitment、pending mask 和
completion opening 都不能单独构成可接纳的密码学迁移证明。只有完成组合后，才应开启下述
细粒度约束。canonical ABI v5 已增加固定九位 `protocol_pending_mask`：shuffle /
reconstruct 直接投影 VM pending mask，reveal 投影所有 assignment pending mask 的并集。
AIR 将 pre/post mask 分解成 boolean bits，要求 action seat 的 pre bit 为一、每次只清除该
seat bit，并用 inverse 证明 post mask 仍非空；`StartHand` 与 `AdvanceRound` 打开的新
protocol mask 还从完整九 seat lifecycle image 推导。因此非最后一次协议提交的进度不再由
host 决定。ABI v5 同时打开 shuffle/reveal/betting/reconstruct/showdown 五项 `u32`
timeout 配置；AIR 对十个 16-bit limb 做 range decomposition，要求 transition 前后保持不变，
并以打开的 `betting_timeout_ms` 推导 time-bank extension 与 `AutoFold` 新 deadline，不再信任
固定部署默认值。final `SubmitReconstruct` 现已增加 canonical completion opening：AIR 从
`pre.protocol_pending_mask == action seat bit` 推导完成条件，不信任 `action.flag`；opening
绑定 authenticated consensus timestamp、`timestamp + shuffle_timeout_ms` 的 checked deadline、
`0..=52` 的 pre deck cursor 与 post cursor reset、按完整 seat lifecycle 重建的 shuffle pending
mask、清零 completed mask，以及 suspended reveal、pre/post deck 和 pre/post reconstruction
commitment。该行精确约束 `Reconstructing/1 -> Shuffling/2` normalization，并保持筹码、座位、
street、custody、rules/governance 等普通状态不变。最后一次 shuffle 与 reveal submit 所需的
reveal schedule、blind/ante 等 opening 仍未完成，因此 `shuffle -> reveal` 和
`reveal -> betting` 继续明确 fail-closed。上述 reconstruct completion 也仍只是
transition/commitment statement：它**不**验证 DLEQ、shuffle、reveal 或 reconstruction 的
Ristretto 方程，也不重算 deck/reveal commitment。

尤其 `zchain` 的 `advance_deadline_in_place` 不是一个单一的“过期后不变”
转换：它先运行有限次 normalization，随后按 reconstruct、shuffle、reveal、betting
或 showdown deadline 分支；betting 还要区分消耗 time bank / 延长 deadline 与
自动 fold，其他分支会 kick、refund/reset、reconstruct 或结算。当前 canonical
`AdvanceDeadline` 行没有 reconstruct/reveal/showdown 级联的完整输入状态或确定性输出约束；
只有上面列出的 betting extension、AutoFold suffix 和 shuffle-timeout 微步骤可以直接验证。
因此其它分支作为 finalized-head 更新的入口都必须 fail-closed，不能把
`deadline_height >= pre.deadline` 当成完整 VM timeout 证明。

### Deadline / terminal direct-AIR 覆盖矩阵

下表是针对 `poker_l1::...::advance_deadline_in_place` 的逐分支审计，区分“当前能直接约束
的独立微步骤”与“仍会把 VM 语义留给 host 的级联”。它是新增 selector/固定宽度 opening 的
最低工作清单，不是把 native `normalize_until_blocked` 作为 verifier 依赖。

| VM 分支 | VM 的原子结果 | 当前 direct AIR | 解除 fail-closed 所需的固定宽度关系 |
| --- | --- | --- | --- |
| deadline 前 / `NoDeadline` | 仅报告，不改变 table | 不应生成 head-changing row | 不需要证明；admission 必须拒绝把它编码为 state transition |
| reconstruct timeout | kick 所有 reconstruct pending；按活跃数 reset、单人 award/reset，或以 accumulator 完成 reconstruct-shuffle | 仅覆盖窄 reset 子集：恰有一个 pending active seat、总 active 数为 1 或 2、零 wager/addon。`kick_player_internal` 的低人数 cascade 在外层读取 accumulator 前完成 reset；AIR 约束 pending bit、active-count、refund、seat vacate 和 reset endpoint | 多 pending kick schedule、单人 award/settlement，以及三名以上 active 时的 accumulator→reconstruct-shuffle continuation |
| shuffle timeout | kick 当前 shuffler；按活跃数 reset/award，否则 rebuild deck 并继续 shuffle | 已覆盖固定、非级联微步骤：最低 pending seat、refund/pot/chip-pool、Out/key/hole 清零、至少两人 pending mask、非零新 deck commitment | 若要覆盖 VM 的 reset/award cascade、完整 52-card rebuild schedule 与密码学 commitment 重算，仍需额外 bounded rows/AIR |
| reveal timeout | kick 全部 reveal pending；0/1 active 时 reset/award；preflop reset，其他 street start reconstruct | 已覆盖 preflop reset、非 preflop reconstruct 与 sole-survivor award 三个终局：单一 pending reset、固定宽度、升序的多 pending `RevealTimeoutKick…Kick→RevealTimeoutReset`（reset endpoint 允许任意数量的 retained active seats，AIR 约束每一 kick 的 custody/lifecycle delta、终局 `Out` 保留、refund/deadline，并由 ZR4 固定宽度 assignment opening 认证 pending union/reveal commitment）；`RevealTimeoutKick…Kick→RevealTimeoutReconstruct`（kick 行按 3-bit 分解约束 street ∈ {1..=5} 且 `subtag == street`；terminal 行约束 `Revealing→Reconstructing/Collecting` 头、`height + reconstruct_timeout` 武装的 deadline、板/牌组/suspended reveal/run-it-twice 不变、非零且变化的 reconstruction commitment（平方和乘积逆证明）、终局 kick 的 stack/bet/addon 清零与 total/time-bank 保留、`amount = stack + addon`、`pot += bet`、`chip_pool −= refund`、acted/leave 掩码按 `pre × (1 − selector)` 清位、post pending mask 由完整 post 座位像推导，并以 `live_count × (live_count − 1)` 的逆证明至少两名 live 玩家）；以及 `RevealTimeoutKick…Kick→RevealTimeoutAward` 零抽水单人 award（VM 侧 `on_reveal_timeout` 改用 raw kick，使 kick 级联不再于循环中提前 reset 偷走 pot——与 VM 自身对 betting 轮同一漏洞的修复注释一致；AIR 约束 `Revealing→Waiting` reset 头、`live == 2` 与 credit/selector 对 live 集的划分、winner stack 精确 `+= pre_pot`（pot 非零逆证明）、被踢与既有 `Out` 座位以 vacated 指示清空、retained 座位 Active 化、time-bank cap、identity/key 保留与 hole 清零、`amount = stack + addon`、`chip_pool −= refund`，以及全部 reset 掩码/承诺清零）。sidecar AIR 还约束完整 assignment 字段、typed/连续 padding、canonical target order、card `<52`/唯一性、pending/submitted mask 的 bit/range/disjoint/union 关系，以及按 seat mask 的确定性 kick schedule。真实 VM fixture 锁定 union→kick→reset/reconstruct/award 语义 | 0-survivor 且 pot > 0 的终点在 VM 内清空 pot 后违反 canonical custody 守恒（筹码滞留 vault 无归属），需要 VM 先决定退款/运营者提取政策才能给出 AIR 关系，保持 fail-closed；rake > 0 的单人 award 已由 `RevealTimeoutRakedAward` 覆盖：新增 `canonical_rake_opening` 以共享 lookup-backed Blake2b STARK 证明完整 `Borsh(TableRules)` 预像哈希到 pre `rules_commitment`（域分隔 `zchain.texas.rules.v1`），公开三元组（mode/bps/cap）进入 Fiat--Shamir scope 与 6 列预处理公共 scope；AIR 以加权场恒等式与 16-bit 肢范围分解精确证明 `rake = min(floor(pot × bps / 10_000), cap, pot)`（pot 截断 32 位，除法余数 14-bit 分解，cap 比较用借位链），winner 精确记 `pot − rake`、`chip_pool −= refund + rake`，缺少/不匹配规则证明均 fail-closed；真实 VM fixture 锁定 rake 公式；完整 deck commitment derivation 与更一般的 reset/assignment ledger 组合仍需专用关系 |
| betting, time bank > 0 | 消耗 `min(time_bank, betting_timeout)`，延长 deadline | `AdvanceDeadline` 已覆盖 | 已有，保持为单一非级联 row |
| betting, time bank = 0 | auto fold，再由 normalization 收池、round advance、single-winner award/reset 或下一 reveal | 只覆盖非终局 `AutoFold` suffix | 将 fold 与后续 bounded normalization 分成显式 `Collect/Advance/Award/Reset` 微步骤；不得让 AutoFold 隐含它们 |
| showdown display timeout | derive side pots/rake/runout/winners，award，reset | 部分覆盖（`src/canonical_settlement_air.rs`：结算代数 AIR——守恒/层平铺、runout 对半拆分、odd-chip 线性分解、winner⊆eligible、无争议层免抽水，四 VM fixture 全链路 prove/verify + 篡改拒绝 10/10；层切片推导/rake 公式链/hand-rank 派生已闭环：7 张评估器电路（直方图/顺子含轮子/同花/kicker 多重集排序/category 优先级/派生↔承诺 24 位绑定）全部在 AIR 内约束，空座位哨兵手按真实分类承诺；层切片由 bet 向量推导（eligible/gross 借位链），总 rake 公式链（school-mul/除法/min 借位链 + mode 门控），rank↔winner 一致性（运行最大值选择链 + 双向借位链等式，runout-1 槽按 two_runouts∧contested 门控）；settlement 套件 21/21 含四场景全链路 prove/verify 与牌面/底牌/rake/层级篡改拒绝） | 9-seat/≤9-side-pot/≤2-runout settlement plan、hand-rank、odd-chip、rake、custody 和 reset 关系 |

每个 deadline branch 都会先运行最多 `MAX_NORMALIZATION_STEPS` 次 pre-normalization；该循环可被
展开为有界 selector batch，但每一个 `CompleteReconstruct`、`AdvanceShuffle`、
`CompleteReveal`、`EndWithoutShowdown` 和 `AdvanceBettingRound` 都必须是单独约束的 state
relation。特别是 `settlement_commitment` 目前被 canonical AIR 锁定为不变；在拥有完整
settlement opening 和 award/reset AIR 前，绝不能仅放宽这个 gate。

canonical archive 中的 batch digest、首尾 transition kind、state-image commitment，以及 state、lifecycle、
overlay、settlement、custody 五个域的首尾根都已进入 Fiat--Shamir transcript、公开
scope、trace 连续性约束和 canonical receipt binding，因此不能再把有效 proof 与另一组
根/receipt 拼接。AIR 仍未重算这些 Blake2b 值，也不能单独作为 admission 的语义来源。

因此当前入口的安全结论是“证明了当前编码的 AIR 关系”，而不是“证明了完整
`TexasPokerTable` 的共识迁移”。只有 `authenticate_receipt` 成功产生
`AuthenticatedTexasReceipt` 后，生产 admission 才能绑定该 archive；单独调用
`verify_tagged_texas_proof` 仍必须 fail-closed，不能更新 confirmed head。

当前 receipt ABI 还要求 mapping 中的 `receipt_value` 等于包含完整 statement 的规范 digest，
并要求 statement 的 transition、pre/post state、lifecycle、overlay roots、固定宽度
`state_object_key` 与 `state_opening_epoch` 分别等于 receipt 字段；只有这些等式和历史
state-root path 同时成立，才允许构造不可伪造的 authenticated wrapper。新的
`canonical_state_opening` 组合器再验证同一 object key 在 pre/post roots 下的两条 257-
compression Blake2b AIR opening，并把 opening value 绑定到 canonical pre/post image
commitment。它消除了 root-opening splice，但不宣称已经在 AIR 内重算完整
`CanonicalStateImage::commitment()`；固定宽度 state-leaf epoch 仍必须由 L1 manifest/receipt
注册。

`canonical_state_hash` 现已能用同一套 lookup Blake2b proof 认证精确的
`"zchain.texas.canonical-state.v2" || Borsh(CanonicalStateImage)` 预像；
`prove_canonical_batch_with_state_image_openings` 将此 byte→commitment proof 与
pre/post SMT opening 组合，得到 byte→commitment→root 链。canonical transition
AIR 已将 ABI/header、table、phase、资金、五类 root、九个 seat 的完整公开 image
（含 identity/key/hole-card commitment），以及 board/deck/reveal/reconstruction/
run-it-twice 五个 commitment、protocol pending mask 和完整 timeout config（共 852 个 endpoint limb）回绑到这些 Borsh bytes；
对下注、funding、join/leave、force/kick、SetLeaveAfterHand 与 AdvanceRound，
已知不变的 commitment 字段也被约束为不变。完整 bytes 也进入 Fiat--Shamir scope。
未组合前，Shuffle/reveal/reconstruct 的 phase/seat/proof-presence shape、final reconstruct 的
`Reconstructing/1 -> Shuffling/2` normalization opening，以及非终局 `FoldWithProof` 的
betting/state-preservation shape 仅作为 ABI 设计和独立测试保留，canonical direct AIR 会拒绝
这些 selector；reconstruction 密码学、deck/reveal
commitment 重算、final shuffle/reveal、reconstruct/reveal/showdown timeout cascade、完整 settlement
与其余 normalization 关系仍未
组合，故这个新组合仍不是 host-zero admission 证据，
`verify_canonical_proof` 仅供结构审计；`admit_canonical_proof` 与
`admit_canonical_proof_with_state_openings` 都会明确 fail-closed。

`canonical_reconstruction_binding` 进一步定义了 Ristretto-only、table-wide fixed-width
reconstruction opening，而不是按 action seat 改变含义的 host projection。opening 固定包含
epoch、pending mask、aggregate key、九个 seat 的 owner key/两张 owner-readable hole card，
以及可选 52-card accumulator。一个共享 lookup-backed Blake2b batch 同时认证 pre
`reconstruction_commitment`、canonical Ristretto context digest、selected-seat prior-state
digest、完整 encoded request digest、pre/post state-image commitment 与 request-free crypto
scope；call-context 由这些已经认证的 digest 重建，避免对这七条关系做原生 hash，并消除循环 commitment。
当前它关闭 state-to-statement 的 hash/key/readable-card detachment，并把 request card vector
固定为有序的 Ristretto `hash_to_curve("texas_poker/card/{i}")` 结果；这些是迁移协议常量，
不是当前 48-byte BLS VM state 的原地等价编码。contribution 的 slot-OR/cross-key/shuffle
关系、post/final deck commitment 仍须由 Ristretto program AIR 组合。新增的
`ristretto_reconstruction_accumulator_air` 已将 canonical 32-byte
left/right decode、projective Edwards addition 和 canonical projective encode 固定为一个
equal-shape row；52 张牌的 `c1/c2` 共 104 条 `post = prior + contribution` 关系按
`card0.c1, card0.c2, ..., card51.c2` 顺序进入一个 batch STARK。有效 row count 与顺序都受
公开 statement/transcript 绑定，verifier 会拒绝 prior/contribution/post splice、c1/c2 或 card
row swap、非 canonical point、错误 addition row 和 padding relabel。该 archive 还能把非首轮
prior accumulator 绑定到上述 pre-state opening，把 52 个 contribution 精确绑定到 encoded
request，并要求 proven post accumulator 等于 post opening 中的完整 deck。相同 Blake2b lookup
batch 认证该 post opening 到 `post.reconstruction_commitment`；post pending mask 只能清除提交
seat，epoch/key/seat/readable-card 数据必须与 pre opening 完全一致。当前 generic Fp batch 的完整
fixture 仍需 723.78s，必须继续把乘法/范围 witness lookup 化才能达到 production 性能。首轮
canonical base deck 现在由一个固定 156-row batch 证明：先以 compressed identity 为起点递推
`1G..52G` 和 `1PK..52PK`，再逐槽证明 `card_i + (i+1)PK`，从而得到
`c1_i=(i+1)G, c2_i=card_i+(i+1)PK`。初始 opening 必须为 absent/zero accumulator 并携带该
base-deck archive；非初始 opening 则禁止携带，避免 optional proof 被跳过。156-row 真实 STARK
尚未在当前 generic Fp backend 上完成性能基准。最终提交继续拒绝，直到 post accumulator 到
encrypted deck commitment 及 reconstruct shuffle 的关系完成。
因此这些 archive 仍不是 production admission 证据。

为继续关闭 slot-OR/cross-key 所需的 DLEQ 关系，Ristretto backend 新增 compressed
fixed-window scalar multiplication：15 行递推 `1P..15P`，再用 320 行完成 64 个四比特 Horner
窗口，总计 335 个等形状 point-addition row。单 statement 和多 statement 版本都由一个 batch
STARK 绑定完整行序；多 statement 版本把若干 335-row slice 拼入同一 proof，并拒绝
scalar/base/output、slice 交换和 padding relabel。旧的 5,760-op monolithic generic program
仍因资源上限 fail-closed。新 backend 已使标量乘法可证明。`ristretto_scalar_add_air`
专门证明 challenge share 的 `mod l` 相加，避免将 Ristretto scalar 错当 `mod p`
field element；`ristretto_reconstruction_slot_or_air` 已把每槽 OR 的两个分支方程
组合成八个标量乘法、五个点加法和一条 share-sum AIR，并将 slot/card/contribution/proof
顺序绑定到 `ZR3P` request envelope。它仍不能替代 transcript：global challenge 只能作为
未来 Poseidon transcript AIR 的认证输出，最终 V3 archive 与 shuffle 仍不可用。

Ristretto `ReconstructionV3VerifyRequest.proof` 已从任意非空字节串收紧为
`ZR3P/v1` canonical envelope：固定 1 个 shuffle、2 个 cross-key、52 个 slot-OR
component，并对完整（不含 proof 自身）请求 statement 和 component 序列分别做域分隔
digest。这样 request/epoch/key/ciphertext/card/call-scope 或 component 交换都会在 archive
进入 accumulator 前拒绝。该 digest 是防 splice 的公开 statement binding，**不是**
Poseidon Fiat--Shamir transcript 或任何 native success receipt 的替代。两条 cross-key
线性关系和每槽 slot-OR 方程现在都有 request/envelope-bound 的 AIR archive，但 challenge
仍只能来自未来 Poseidon transcript AIR 的认证输出；在 transcript 与 shuffle AIR 全部合成前，
production admission 仍保持 fail-closed。

当前 state-image composition 的 verifier 已将 endpoint commitment 的职责明确分层：
standalone state-opening verifier 仍是 audit/building block；完整
`Borsh(image) -> Blake2b(image commitment) -> SMT root` composition 会调用不重算
Blake2b 的 canonical verifier，并由独立 lookup-backed state-image hash AIR 认证两个
endpoint digest。这样不会把 host 端 `CanonicalStateImage::commitment()` 重算误当成
host-zero 证明；VM cascade、settlement、deck/reveal 和 Ristretto 关系仍未因此完成，
production admission 继续 fail-closed。

为避免未来 transcript AIR 在字段编码或 challenge 顺序上另起一套未认证的 host 规范，
`ristretto_reconstruction_transcript` 已固定 Poseidon252/v1 的协议输入：domain、完整 request
的每个字节字段（带 label/长度、每 16-byte little-endian chunk 一域元素）、cross-key 的
负贡献与三项 commitment、shuffle wire，以及 52 个 slot-OR 的 slot 序号与四项 commitment。
挑战输出顺序严格为两个 cross-key 后、shuffle wire 后的 52 个 slot-OR；每个输出还保留
nonzero retry counter 作为将来 sponge AIR 的 witness。`ZR3P` Blake2b digest 仅作额外 splice
binding，不能替代完整 bytes 的吸收，也不是挑战。此模块尚未实现 Poseidon permutation、
scalar reduction 或 retry AIR，故不可用 host 计算结果解除 fail-closed admission。
该规范进一步导出 rate-two `absorb / permute / squeeze` 操作序列，并固定每次 squeeze 的
Starknet `+1` padding lane，避免将来 AIR/prover 在 full-block 或 final-block 边界各自解释。
在任何 relation archive 消费该 typed boundary 前，现有实现会拒绝 statement-digest splice、
零或非 canonical 的 `mod l` challenge，以及超过固定上界的 retry counter；这些只是格式和
范围约束，绝不将 host 给出的字节提升为 transcript 认证输出。

`ristretto_reconstruction_composition` 现在把已实现的 state binding、52-card accumulator、
两条 cross-key 和 52 条 slot-OR 归入一份固定的 request-scoped bundle，并在运行子 AIR 前
拒绝 statement/envelope/transcript/slot-order splice。该 bundle 的 audit verifier 只表示
这些已实现关系均成立；其 admission-shaped API 在验证后仍返回
`HostZeroAdmissionIncomplete`，直到 Poseidon permutation/retry 与 Bayer--Groth shuffle AIR
完成，不能据此推进生产 head。

另外，canonical action ABI 的保留字段已按 VM 参数形状收口：普通 selector 不能携带伪造
proof commitment，`auxiliary` 仅由 `AdvanceDeadline` 消费，`flag` 仅由
`SetLeaveAfterHand` 消费，`deadline_height` 仅由 permissionless timeout 行消费，
seatless `CreateTable/StartHand/AdvanceRound` 必须使用 no-seat sentinel。native shape 和
direct AIR 同时约束这些字段，并有 trace mutation 攻击测试。

独立项目还提供 `authenticate_receipt_l1`。生产适配器必须使用
`TexasL1ReceiptInclusionProof`，它直接调用
`poker_l1::object_model::SparseMerkleTree::verify`：固定 256 层、
`H(0x00 || key || value)` 叶哈希、`H(0x01 || left || right)` 内部哈希，且
mapping value 固定为 statement-bound `receipt_value` 的 32 字节编码。旧的
`TexasReceiptInclusionProof` 只保留作通用 ABI/测试，不足以证明真实 L1 state root。

当前实现已经把几个边界分开，但生产路径仍有以下事实：

| 组件 | 当前信任内容 | 证明能否独立排除伪造 |
| --- | --- | --- |
| `poker_texas_air` STARK/AIR | 固定 AIR、VK、manifest，以及 prover 提供的 witness | 只能证明 AIR 约束；不能证明 witness 对应某笔 L1 交易 |
| L1 state kernel | `table_head` CAS、seq/hand、nullifier、authority、deadline、链上 proof 验证 | 能约束已提交 effect；不认证 host 传入的外部交易来源 |
| coordinator | job、tentative/confirmed head、exact signed transaction sidecar | 负责持久化和顺序，不是共识证明 |
| runtime finality observer | 交易所在 canonical block、执行状态、同高度 `table_head` 写入 | 目前还检查 transaction/function/transition body；这属于 replay/transaction-shape 依赖 |
| native witness builder | 从游戏状态生成 opening、plan digest 和 public inputs | 如果 AIR 没有重算对应算法，builder 仍是信任边界 |

因此，当前的“proof verified”不能直接解释为“这笔链上交易按预期改变了状态”。

## 目标边界

目标流程应是：

```text
固定部署 manifest/VK
  -> STARK proof 约束完整 pre/post transition
  -> 链上 settlement program 在最终确认时验证 proof 并写 authenticated receipt
  -> 共识最终确认 block + state root + receipt mapping
  -> runtime 只验证 receipt 的包含性和字段等式
```

安全性依赖 L1 共识正确执行已认证的 program，而不依赖服务端重新解释交易参数。
服务端仍然必须验证 canonical block、确认深度和历史 state root；移除的是业务语义 replay，
不是共识 finality 验证。

## 必须修改的部分

### 1. 链上 state kernel：写入不可变 transition receipt

新增 `transition_receipt_v1` 及按唯一 key 存储的 mapping。receipt 至少应包含：

- `table_id`、`hand_id`、`pre_seq`、`post_seq`
- pre/post `state_root`、`lifecycle_root`、`overlay_root`
- `rules_commitment`、`fee_config_hash`
- `circuit_id`、`manifest_digest`、`effect_kind`、`authority_kind`
- `authority`、`transition_commitment`、`nullifier`、`deadline_height`
- terminal/next-hand 所需的 settlement、custody、opening commitment

每个 `commit_*_v1` 必须在同一个 finalize 原子地：

1. 检查旧 `table_head` 精确匹配；
2. 检查 relation binding、manifest、authority 和 `snark.verify`；
3. 检查 nullifier/receipt key 未使用；
4. 写入新 `table_head`、`spent_nullifier` 和完整 receipt。

receipt 不能由第二笔“登记交易”补写，否则会重新引入竞态和跨交易信任假设。terminal、
showdown、next-hand 的经济 receipt 也必须由同一个已验证 transition 写入，不能由 host
根据事件再拼接。

### 2. Public statement：把原来依赖 replay 的字段放进证明

每个 relation 的 public input 必须显式绑定：

```text
table/hand/seq + pre/post full state roots
rules/fee/overlay commitments
actor/authority statement
canonical action or timeout statement
transition commitment + nullifier
manifest digest + circuit id
```

`transition_plan_digest`、`trusted_row`、仅由 host 生成的 settlement summary 不能继续作为
“已验证事实”。如果字段仍然是 opaque digest，就必须有同一 relation 的约束证明其生成规则；
否则应从 public ABI 删除。

### 3. AIR/R1CS：接管 replay 曾经提供的业务约束

删除生产路径对 `validate_*`/`replay_tasks` 的依赖之前，必须把这些语义移入可验证关系：

- action legality、turn/round/phase gating；
- amount、stack、bet、pot 的全 limb 加减、非负和范围检查；
- round advance、timeout 与 deadline 的互斥；
- terminal 的 side-pot、rake、odd-chip、winner payout 和 custody conservation；
- deck/runout/hand-rank 的 transcript commitment；
- pre/post state opening 和 state-root 计算（或者一个已审计的递归 state-transition SNARK）。

对 `texas_canonical_air`，20 个 selector family relation 已有 canonical AIR
dispatch；其中 `AdvanceRound` 还在 AIR 中选择固定的 preflop/flop/turn（含
run-it-twice）board-reveal schedule，并约束 card cursor、board position、pending
mask、submitted mask 和 padding。archive 已将 admission 所需的 pre/post state、
lifecycle、overlay、settlement、custody root 公开绑定到 trace；下一步仍需将它们及
board/deck/reveal assignment inclusion 同完整 state opening / Blake2b root relation
绑定。否则恶意 prover 可以生成满足当前结构 AIR 的 trace，而经济或密码语义仍只能由
host 断言。

`AdvanceRound` 的 deck cursor 本身已在 AIR 中作 6-bit/`<=52` 约束；这只消除了
field-range 伪造，**不**证明 cursor 或 assignment 是 L1 加密 deck 的成员。生产 L1
当前将 poker table 分为一个可变长度 hot-state object 和 metadata/rules/governance
三个 context objects；host-zero 的 Blake2b opening component 必须认证这些实际对象的
key、value、leaf hash 和 256 层路径，或在新 table epoch 中部署等价的固定宽度 state
object。仅将 host 计算的 object digest/root 写入 public input 不满足该要求。

特别是 Poseidon state root 不能只在 host 端重算后塞进 public input。若暂时做不到，必须把
该路径明确标为“host-attested”，不能宣称 no-replay trustless。

### 4. Finality observer：从 transaction replay 改为 receipt inclusion proof

runtime 应停止把 `validate_execution_target`、transition body shape 或重新解析
交易参数当成业务认证来源。新的 `L1FinalityObservation` 应返回并校验：

- transaction ID、canonical block hash/height、确认深度、历史 state root；
- `transition_receipt` 的历史 mapping value；
- receipt key 和 value 的 Merkle/state-root inclusion proof；
- receipt 与 job public statement 的逐字段相等；
- receipt 对应的 program/manifest registry 已在共识状态中固定。

不能从“当前 mapping 查询结果”证明历史交易结果；必须读取与 finalized block 同高度的状态。
如果使用 explorer/RPC，必须改成能验证 block/state-root/receipt inclusion 的 light-client
接口；否则 RPC 仍是隐藏信任点。

transaction ID 在此模型中只用于定位和幂等 outbox，不再承担“交易参数语义正确”的证明。
exact signed bytes、broadcast retry、unknown 状态回查和冻结逻辑仍必须保留。

### 5. Coordinator admission：只接受 authenticated receipt

新增不可构造的 `AuthenticatedTransitionReceipt`（只能由 finality verifier 生成），admit
时检查：

- receipt table/hand/seq 与 tentative/confirmed head 严格连续；
- pre/post roots、manifest、circuit、authority、overlay 与 proof artifact 完全一致；
- receipt block/state-root 已 finalized，且包含证明通过；
- nullifier、job id、transaction id 不能跨桌/跨手重用。

`ProveTask` 可以继续作为 prover 的输入/缓存，但不能再作为 receipt provenance。生产 admission
不能从 task 自己构造 pre/post snapshot，也不能用 replay 后的本地状态替代链上 receipt。

### 6. 授权与部署

- actor signature 必须绑定到 proof statement；outer L1 transaction signer 只负责执行/付费，
  不能被当成玩家 authority；
- relation registry、VK、program digest、manifest digest 必须 immutable 且版本化；
- authority policy（actor/operator/permissionless）必须由 state kernel 按 effect 固定检查；
- timeout 必须同时由 proof statement 和 `block.height > deadline_height` 约束；
- old/new program、VK、manifest 不能混用，升级必须产生新的 manifest/circuit domain。

## 迁移顺序

1. 先实现 receipt struct/mapping 和历史 state-root inclusion proof，保留现有 replay 作为双重校验；
2. 让每个 relation 的 proof public ABI 覆盖完整 pre/post、authority、economic commitment；
3. coordinator 改为“receipt + proof”双绑定，replay 仅作为 audit/debug；
4. runtime 默认走 receipt-only，保留显式 `audit_replay` 工具，不让其进入生产 admission；
5. 补 adversarial tests：伪造 receipt、拼接不同 job、乱序、旧 receipt 重放、RPC 最新状态替换历史状态、
   manifest/VK 替换、authority 替换、terminal/next-hand 跨手替换；
6. 只有在所有经济关系和 state-root relation 已在 proof/链上约束后，才移除 replay 代码。

## 不能接受的“简化”

以下做法不是 no-replay trust model：

- 仅删除 host replay，继续信任 task 携带的 post-state/settlement plan；
- 仅检查 transaction 已 finalized，不检查 receipt 字段和历史 state inclusion；
- 仅读取最新 `table_head`，不绑定交易所在 block height；
- 把 explorer 返回的 function/transition JSON 当成共识证明；
- 用一个通用 circuit/VK 接受多个 effect，再由 host 选择解释方式。

这些改动会把原来的“信任 canonical replay”降级成“信任 prover、服务或 RPC”，而不是减少
信任假设。
