#!/usr/bin/env bash
# missing_docs 棘轮门禁：只拦"新增"，存量预算渐进消化。
#
# 预算存在 scripts/missing_docs_budget.txt。为公开 API 新增条目而未补文档
# 会使计数超过预算 → CI 失败；补文档后应同步调低预算（棘轮只紧不松）。
#
# 用法: ./scripts/missing_docs_ratchet.sh
set -euo pipefail
cd "$(dirname "$0")/.."

BUDGET_FILE="scripts/missing_docs_budget.txt"
BUDGET=$(cat "$BUDGET_FILE")

COUNT=$(cargo check --workspace --lib --bins 2>&1 | grep -c "missing documentation" || true)

echo "missing_docs: ${COUNT} (budget ${BUDGET})"
if [ "$COUNT" -gt "$BUDGET" ]; then
    echo "::error::missing_docs 新增 $((COUNT - BUDGET)) 条（预算 ${BUDGET}）。"
    echo "       请为新公开项补文档，然后同步调低 ${BUDGET_FILE}。"
    exit 1
fi
