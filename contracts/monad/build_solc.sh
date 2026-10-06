#!/usr/bin/env bash
# =============================================================================
# build_solc.sh — 无 foundry 环境下的合约编译（solc 直编）。
#
# 用途：CI/本机无 forge 时对 contracts/monad/src 做真实编译验收（bin + ABI）；
# script/test 需要 forge-std，不在本脚本范围（`forge test` 另行覆盖）。
#
# 用法：
#   SOLC=${SOLC:-../../tools_external/solc/solc-macos} ./build_solc.sh
#   # 或 PATH 里有 solc 时直接 ./build_solc.sh
# 产物：out/solc/<Contract>.bin / .abi（工具件，不入库口径同 foundry out/）。
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"

SOLC_BIN="${SOLC:-../../tools_external/solc/solc-macos}"
if ! command -v "$SOLC_BIN" >/dev/null 2>&1 && [[ ! -x "$SOLC_BIN" ]]; then
  echo "error: solc not found at $SOLC_BIN (set SOLC=/path/to/solc)" >&2
  exit 1
fi

OUT=out/solc
mkdir -p "$OUT"

"$SOLC_BIN" --version
"$SOLC_BIN" --bin --abi --optimize \
  --evm-version cancun \
  -o "$OUT" --overwrite \
  src/L1Bridge.sol src/L1Outbox.sol src/L1Inbox.sol \
  src/Groth16Verifier.sol src/SettleWrap.sol \
  src/Groth16VerifierBatch.sol src/SettleBatch.sol \
  src/FastExit.sol

echo "---- artifacts ----"
ls -la "$OUT"
echo "build_solc: OK"
