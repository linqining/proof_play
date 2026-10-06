# FAQ 必答 8 问 v0.1

> 按 §6.6 原文收录。回答如需更新，必须与 zchain 仓库的 docs/plan-appchain-v1.md 与路线图页同步。

**这是公链还是中心化服务器？**
v1 是单 Sequencer 的托管式 Appchain，逐步增加 BFT。

**PLAY 和 REAL 有什么区别？**
PLAY 是测试/娱乐筹码；REAL 是运营方托管的真实资产映射。

**软确认是不是最终确认？**
不是；最终性要看 BFT、proof 和 checkpoint 状态。

**运营方能否修改牌局或 rake？**
协议会拒绝不满足签名、守恒、费率和 proof 绑定的记录，但 v1 的活性和提现仍依赖运营方，风险必须明示。

**如何验证一手牌？**
使用 explorer 的 proof portal 或独立 verifier 命令。

**Sequencer 审查交易怎么办？**
通过 relay SeenReceipt、ForceInclude 和后续 DA/退出协议处理。（注：ForceInclude 与 relay 属 v1.5 路线，当前未上线——回答时说明这是设计路径而非现状。）

**出金是否无需许可？**
v1 不是；permissionless claim 需等 Vault verifier 上线。

**是否发行代币或承诺收益？**
v1 不以收益或代币升值为产品承诺，任何经济设计另行治理和合规评审。
