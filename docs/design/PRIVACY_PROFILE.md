# 隐私分档与资金隐私边界(PRIVACY_PROFILE)

- 日期:2026-10-01
- 状态:定稿。M2 依 §5 开工配置骨架;M5 依 §4 做语句面电路项;M9 门位引用 §2 档位。
- 关联:`docs/design/SETTLEMENT_PRIVACY_PLAN.md`(P2-M1..M4 的后续)、
  `out/rollup-realchain-schedule.md`(§2.2 / §2.5 / §3)、`docs/SOUNDNESS.md`
  (声明改窄待办,见 §4)。
- **命名纪律**:本文件定义的配置面一律**链中立**——不含 starknet、monad
  等任何链名;链身份只属于「结算后端」轴(§5)。理由:隐私分档是资金与
  语句的语义选择,与部署在哪条链无关;链名混入隐私配置会让后续接入新链
  时产生「每条链一套隐私档」的假分叉。现状 `STARKNET_*` 环境名为历史名,
  兼容读取;新增面一律中立名(§5 别名表)。

---

## 1. 背景与事实基础(泄露面审计,2026-10-01)

结算金额隐私的五条泄露通道(逐条有代码锚点,审计口径):

| # | 通道 | 泄露内容 | 锚点 | 可修复性 |
|---|---|---|---|---|
| L1 | legacy 结算 calldata 携带明文 players/signs/magnitudes(合约重算 digest 比对) | 单手逐人输赢,**零爆破** | `texas/src/starknet/submit.rs:183-184` | 结构性(该模式定义如此) |
| L2 | `registered_digest` 无盐:`poseidon([hand_id, p,s,m×9, action_log_digest])` | 小定义域(chip=小整数,`WEI_PER_CHIP` 公开)爆破,结果唯一且可公开复验(无可否认性) | `submit.rs:217-227` | 电路加盐可治(仅 v2 语句面) |
| L3 | 公开段 `total_winnings` = pot(wei) | 每手 pot 大小 | `settlement_prover.rs:312-334` | **结构性,明示放弃**:合约托管记账承重字段 |
| L4 | cm 基座公开:`cm = poseidon(payout_commitment(链上公开可读), binding, amount)` | 赢家金额可无秘密爆破 | `settlement_prover.rs:165-190`;`settlement_payout_anonymizer.cairo:6` | 电路换 blind 可治 |
| L5 | 资金腿:claim 自曝 amount(重算 cm 所需);v1 vault deposit/unshield 1:1 | 会话 bankroll 流水 | `settlement_payout_anonymizer.cairo:170-177`;vault anonymizer | claim 时刻**明示放弃**;出入金走匿名腿可治 |

守住的隐私:**牌/动作内容**(亮牌在链下 mental-poker 协议完成,动作上链
仅为哈希与三个计数)。由此得出两条审计推论:

1. 「单手级金额隐私」在 L1–L5 面前对决心观察者**不成立**;任何高于此的
   隐私叙事必须按 §2 档位收窄表述。
2. 资金隐私的真实战场是**出入金腿(L5)**,不是结算语句;匿名化合约
   (STRK20 池 / vault anonymizer / payout anonymizer)已在
   poker_contracts 落地(`SETTLEMENT_PRIVACY_PLAN.md`:买入
   `privacy_invoke`、出金 `privacy_withdraw` 均已存在),缺的是**强制
   启用与档位化**,不是新建。

## 2. 隐私分档(Profiles)

两个具名档 + 一个有时限的过渡态;**组合封闭,不做自由矩阵**(§6 纪律 2)。

### transparent(透明档)
- 语句面 = plaintext(L1 模式);资金腿 = direct(1:1 托管);
  balance_root 叶子 = 明文。
- 承诺:牌/动作私密;金额、流水、负债树全公开。
- 适用:dev、测试网、审计对账期、监管要求可读性的场景。

### shielded(隐匿档)
- 语句面 = committed(v2 语句,§4 电路项落地后含盐/blind);资金腿 =
  shielded(池/note 匿名腿强制);balance_root 叶子 = 承诺。
- 承诺:牌/动作私密;语句面抗爆破;出入金流水隐藏(池内 note)。
- 残留(明示):每手 pot 公开(L3);claim 时刻 amount 公开一次(L5′)。

**shielded-v0(过渡态,时限 = M5 完成)**:现状 dual 语句(L2/L4 未修)+
出入金腿未强制。只允许存在于测试网;**真链 REAL 流量不得以 v0 名义开跑**。

**shielded-v1**:§4 两项电路项落地 + 资金腿强制之后,才有资格作为 REAL
桌与主网门位的隐私档。

### 封闭性规则
- 配置只接受上述具名档;非法组合(声明 shielded 但资金腿 direct 等)在
  配置校验期 fail-closed 拒启。
- balance_root 叶子格式**不设独立键**,由档位决定。

## 3. 三层选择面

| 层 | transparent | shielded | 现状代码载体 |
|---|---|---|---|
| 语句面 | plaintext(legacy calldata) | committed(v2 语句;M5 后含盐/blind) | `SettleRoute{Legacy,Dual}`(texas config.rs:136-149) |
| 资金腿 | direct(vault 1:1) | shielded(privacy_invoke / privacy_withdraw / payout anonymizer) | 现散在客户端(privacyBuyIn Plan B)——收编为服务端 venue 政策 |
| balance_root 叶子 | `poseidon(player, balance, nonce)`(明文余额) | 承诺叶子 | M2 新建 |

叶子格式说明:transparent 档明文叶子无额外泄露面(金额在 L1–L5 下本已
可推导),且逃生验证面最小、哨兵监控与托管储备对账可直接审计负债;
shielded 档必须承诺叶子——否则余额树自己把资金面卖了。

**规格约定(2026-10-02 定稿,推荐形态)**:哈希**各自原生**——Cairo/
STARK 里 Poseidon 是 builtin(全树 <fold 批 1% 噪声)、SHA-256 为外来
苦役(全树 ~3–12M steps,fold 批 431k steps 的 10–30×);EVM/Groth16
里正相反。故:**poker 侧负债树保持 Poseidon(权威结算负债面,M5 电路
回填轻)**;账本面树 = 边界转换器(纯计算,零证明成本)按
`EscapeHatch.sol` 冻结规格出每批增量根(SHA-256/bytes20/u64 LE/
补齐索引式——balance-rollup::ledger 规格镜像,信任分阶段 authority +
DA);**要收敛的是余额主体与登记语义(felt→address 映射、每批增量
根),不是哈希函数**。转换器已落地(balance-rollup::ledger + poster
批伴随 `<batch_key>.ledger-root.json`);登记调用方(M4)与审计(M5)
照旧。

## 4. 修复路线(谁在哪治哪条)

- **M2**:`PRIVACY_PROFILE` 配置骨架(§5,兼容读旧 env 名)+
  balance_root 叶子随档(§3)。✅ 2026-10-01 代码落地:`privacy-profile`
  crate(档位/三层/别名/fail-closed)、`balance-rollup` crate(双叶格式/
  链式/checkpoint 语料/创世种子)、settle-queue 条目携带
  `balance_entry`、batch-poster 回执入树 + 批 Receipted 根随批(批记录
  `balance_root` + spool 伴随 `<batch_key>.balance.json`,不动 Monad
  信封跨仓契约)、status 增 `balance_root_head`/`balance_applied_hands`、
  texas 入队携带语料 + `validate` 档位校验。**M2 边界(诚实声明)**:
  树=结算负债面(买入/出金腿后置——真链启用前以 vault 快照
  `seed_balances` 播种);shielded 叶 blind 为 v0 占位派生(不构成隐藏);
  链上登记腿=伴随工件,合约入口随 M4/M5。
- **M4**:shielded-v0 测试网真链跑,采集成本/延迟(喂 zchain 角色决策
  与 §7 电路项参数)。
- **M5(合约/电路窗口,审计对象同批带走)**:
  - **L2 加盐**:盐为服务端每手秘密,进电路 witness;digest 公式追加
    一域。仅 v2 语句面(legacy 本就公开,不白花约束)。
  - **L4 blind**:cm 基座由公开的 `payout_commitment` 链上读数换成赢家
    私有盲化因子;claim 校验公式同步改,claim 时需携带 blind
    (claim 自曝残留不变,§2 明示)。
  - `SOUNDNESS.md` 隐私声明按 §2 档位改窄(「金额隐私」改述为
    「牌/动作隐私 + 档位化语句面」),避免 M9 审计叙事说不圆。
- **M9**:主网门位前置之一——REAL 桌若宣称隐私,必须跑在 shielded-v1;
  若跑 transparent,则营销与文档口径同步降档。

## 5. 配置面(链中立命名)

**命名规则**:隐私/语句/资金腿的配置键不得包含任何链名;链身份唯一入口
是 `SETTLEMENT_BACKEND`(后端适配器注册处)。现状 `STARKNET_*` 环境名为
历史名,兼容读取;新增面一律中立名。

| 逻辑键 | 值 | 说明 | 现名别名(兼容读) |
|---|---|---|---|
| `PRIVACY_PROFILE` | `transparent` / `shielded` | venue 层主键,一次选定 §3 三层 | (新) |
| `SETTLEMENT_STATEMENT_MODE` | `plaintext` / `committed` | 语句面轴(随 profile,不单独开放) | `STARKNET_SETTLEMENT_MODE`(Legacy→plaintext,Dual→committed) |
| `CUSTODY_FLOW_MODE` | `direct` / `shielded` | 资金腿轴(随 profile;REAL 桌强制 shielded = venue 政策) | (散在客户端,收编) |
| `SETTLEMENT_BACKEND` | 后端适配器注册名 | **链身份唯一入口**:现有后端与未来其他链各自注册适配器 | `STARKNET_SETTLEMENT_EXIT`(appchain/starknet 属 venue 运行时轴,另行归位) |

**正交性断言**:换后端不得改变隐私档语义;换隐私档不得要求改后端。
任何一轴的实现不得 import 另一轴的链类型。此断言进验收(§7)。

## 6. 工程纪律

1. **证明脊一份**:ProveTask / fact / batch_key / settle-queue / fold 批
   管线不因档位 fork;档位只差语句公开面与资金腿。
2. **具名组合封闭**:两个具名档 + shielded-v0 过渡态;无 per-axis 自由
   覆盖(dev 实验除外,不入生产配置面)。e2e 发现 5/11 已演示模式乘积的
   运维痛,新增一轴必须先删一个旧轴。
3. **fail-closed**:非法组合 / 未知档 / 缺失档在 config 校验期拒绝启动,
   不落缺省。
4. **档位语义进验收**(§7),「隐私」一词不得无档位漂移。

## 7. 各档验收

- **transparent**:牌/动作不可见断言(链上无牌面/动作明文)、金额可读
  断言(审计友好性即特性)、明文叶成员证明逃生演练。
- **shielded-v0**:L2/L4 爆破面**记录在案**(已知残留)、匿名腿出入金
  流水隐藏断言、balance_root 承诺叶逃生演练。
- **shielded-v1**:加盐后 digest 爆破不可行(定义域 × 盐熵论证)、blind
  后 cm 不可爆破断言、pot/claim 残留明示于文档、承诺叶逃生演练通过。
- **正交性**:PRIVACY_PROFILE × SETTLEMENT_BACKEND 任意组合可启动,
  语义不变。

## 8. 与 zchain 的关系(正交声明)

匿名化合约(STRK20 池 / vault / payout anonymizer)在 poker_contracts,
zchain 是消费方(wallet-app)与结算基础设施仓(monad settlement、
settlement-adapter、FactQueue)。隐私档的落地**不需要**引入 zchain;
zchain 角色决策(venue 层保留 vs 降级)维持排期 §3 触发点(M4 成本/
延迟数据)。若未来角色决策 = 降级,shielded 档的匿名腿仍在
poker_contracts 原地可用。
