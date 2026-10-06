---
title: 版本说明：latest 与 next
lang: zh-CN
section: changelog
description: 文档版本化机制：latest 指向已发布 release，next 承载草案。
lead: 草案进入 next，不覆盖已部署网络的规范。
---

## 机制

| 通道 | 指向 | 规则 |
|---|---|---|
| `latest` | 最近一次<strong>已发布</strong> release 对应的 docs tag | 只在 release 发布时前进；与 ABI 版本、genesis/config hash 一一对应 |
| `next` | 草案（未发布变更） | 可随时变动；页面带 draft 水印；不覆盖 latest |
| 历史版本 | 按 release tag 归档 | 永不修改 |

## 与 release 的对应（WEB-ACC-5）

每个代码 release 自动同步：docs tag、ABI 版本、genesis hash、changelog、SBOM 与签名。当前状态：版本号在 `website/build.py` 集中定义（人工同步），自动同步流水线<strong>待发布基础设施</strong>——在自动流水线上线前，本站的版本字符串以仓库内 ABI.md 为准人工核对。

## 当前指向

- `latest`：docs v1.3.0-alpha（ABI v1.2.3）——devnet 阶段文档，尚无已部署网络，latest 即唯一通道。
- `next`：空（无未发布草案）。
