#!/usr/bin/env bash
# Ready 实机端到端交易核对（docs/design/SETTLEMENT_PRIVACY_PLAN.md「实机端到端剩余一步」）
# 用法: ./scripts/verify_e2e_txs.sh <你的Ready钱包地址>
# 功能: 1) vault v2 筹码余额  2) payout commitment 注册状态
#       3) 最近 settle/claim 相关日志要点（需 /tmp/texas_server.log）
set -euo pipefail
ADDR_RAW="${1:?用法: verify_e2e_txs.sh <Ready钱包地址>}"
# 规范化为 64 位十六进制（RPC felt 编码要求偶长度）
ADDR="0x$(printf '%064s' "${ADDR_RAW#0x}" | tr ' ' '0')"
URL="${URL:-https://starknet-sepolia-rpc.publicnode.com}"
V2="0x3e73e675e5738e64f3fa54a921426eeb48aa72dec56745198f7a869ee0de25f"   # PokerVault v2
D2="0x283008305b515ead456b621d41f232d1c650c882c550d465b3fc5c83eee98e4"   # PokerDualSettlement v2
CHIP_BAL_SEL="0x19924a03080ce6052c19197f7a89c3f2ff2a7260c79410f273d07dd6802aa4a"   # chip_balance
PCOMMIT_SEL="0x5cd65940e6b3edea8b5cf1ea5fef37c1ac1e0d0fdc7131e6c7f45a9dbee45e21"   # payout_commitment

# vault 读取走 snops（publicnode 对长 calldata felt 的解析不稳定）；
# snops = 本仓库 cargo build -p texas --bin snops 的产物，可用 SNOPS= 覆盖
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
S="${SNOPS:-$ROOT/target/debug/snops}"

echo "== 1. vault v2 筹码余额 =="
CHIPS_HEX=$("$S" --url "$URL" call --contract "$V2" --fn chip_balance --calldata "$ADDR" 2>/dev/null | grep -oE "OUT=0x[0-9a-f]+" | head -1 | cut -d= -f2 || true)
python3 -c "
v=int('$CHIPS_HEX' or '0',16)
print(f'  {v/1e14:.2f} chips ({v} wei)')"

echo "== 2. payout commitment 注册状态 =="
PC_HEX=$("$S" --url "$URL" call --contract "$V2" --fn payout_commitment --calldata "$ADDR" 2>/dev/null | grep -oE "OUT=0x[0-9a-f]+" | head -1 | cut -d= -f2 || true)
python3 -c "
v=int('$PC_HEX' or '0',16)
print('  已注册 ✓ commitment=0x%x' % v if v else '  未注册（在游戏页打开领取弹窗一键注册）')"

echo "== 3. 服务器最近结算（/tmp/texas_server.log）=="
grep -a "dapv on-chain\|private" /tmp/texas_server.log 2>/dev/null | tail -3 | sed 's/\x1b\[[0-9;]*m//g' | cut -c1-160 || echo "  （无日志）"

echo "== 4. 最近私有结算核对（selector=verify_and_settle_dapv_stark_private）=="
echo "  提示: 从第 3 步的 settle=<tx> 取哈希后执行:"
echo "  curl -s -X POST $URL -H 'Content-Type: application/json' -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"starknet_getTransactionByHash\",\"params\":[\"<tx>\"]}' | python3 -m json.tool | grep -E 'selector|entry_point'"
echo "  private selector = 0x166064fd46f02b4fd81b3293579757be9e3ba738c3f15c4bb8d36b33f6f19a7"
