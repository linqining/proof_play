---
title: API 参考
lang: zh-CN
section: api-reference
description: OpenAPI/RPC/ABI 参考的生成计划与当前手工参考层。
lead: 目标是从源码 schema 自动生成，含正例、负例、错误码、幂等和重试语义；当前为手工参考层。
---

## 当前状态（如实）

| 资产 | 状态 |
|---|---|
| RPC 手工参考 | <a href="/docs/developers/rpc/">/docs/developers/rpc/</a> |
| ABI 规范 | <a href="/docs/protocol/abi/">/docs/protocol/abi/</a>（源：poker-appchain/docs/ABI.md） |
| 错误码 | <a href="/docs/developers/errors/">/docs/developers/errors/</a> |
| 自动生成流水线 | <strong>待接入</strong>（WEB-ACC-5 的一部分） |

## 自动生成要求（发布前达标）

- 从源码 schema / borsh 定义生成，人工不得改写生成的 wire 字段。
- 每个方法附正例与负例（请求/响应对）。
- 错误码全覆盖，含幂等与重试语义。
- 生成物带版本（与 release 对齐）与内容哈希。

生成流水线接入后，本页变为生成物索引（按版本列目录），并附"生成时间 / 源 commit / 内容哈希"。
