# 90 秒演示视频脚本 v0.1

> 按 §6.6 分镜表。全片带水印 `PLAY / devnet / v1.3`；画面中出现的任何数字必须与当期 fact-sheet 一致。

| 时间 | 画面 | 口播/字幕 |
|---|---|---|
| 0–15s | 玩家连接 PLAY 钱包并进入牌桌。 | "PLAY 环境，一条专用扑克 Appchain。"（字幕标注 devnet / custodial v1） |
| 15–35s | 下注操作获得 soft accepted，屏幕展示 frame index 与状态根。 | "每次下注：软确认帧签名入链——注意，这是运营方承诺，不是最终确认。" |
| 35–55s | 手牌结束，展示 SettlementPlan、rake 与 payout root。 | "结算计划单一事实源：pot、rake、赔付结构全部进根，签名覆盖精确赔付。" |
| 55–70s | 浏览器本地验证 proof，显示 verifier 版本和结果。 | "本地验证：verifier 版本 texas-air-v2（占位），结果 PASS，耗时可见。" |
| 70–82s | 展示 explorer、status、docs 和代码仓库入口。 | "区块浏览器、状态页、版本化文档、公开仓库——所有入口互相链接。" |
| 82–90s | 明示当前是 v1 托管网络，REAL 提现和后续 BFT/退出协议按路线图开放。 | "v1 是托管网络。REAL、BFT checkpoint、无信任提现——按公开路线图逐阶段启用。" |

## 制作纪律

1. 82–90s 的限定句不得剪掉；投放平台若限制时长，改用 60s 版本时保留托管声明。
2. 演示环境必须真实 devnet 录屏；不得用 mock 数据冒充链上响应。
3. 协议升级后本视频归档（旧 API/费率/最终性画面失效即下架）。
4. 如展示 explorer/status 数据，画面必须含 "SAMPLE DATA / devnet" 标注（在 portal 服务上线前）。
