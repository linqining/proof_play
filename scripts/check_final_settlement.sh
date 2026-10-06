#!/usr/bin/env bash
# =============================================================================
# check_final_settlement.sh — 断言「本地出证 → zchain appchain → SNARK 包裹 →
# Monad 测试网结算」全链路的链上证据真实成立。
#
# 读 /tmp/monad-final-settlement.json（由 e2e 演练产出），逐项核对：
#   1. settle 交易回执 status == 0x1 且 to == SettleWrap；
#   2. 回执 log == WrapSettled(programHash, handBinding, fact)，三值与
#      proofPath 包裹证明 JSON 的语句逐字段一致；
#   3. cast call Groth16Verifier.verifyProof(a, b_evm, c, pub) == true
#      （calldata 由 proofPath 现场重建，b_evm = EIP-197 Fp2 虚部在前）；
#   4. cast call SettleWrap.settledFact(handBinding) == fact；
#   5. anchor 交易回执 status == 0x1 且 to == L1Inbox，BatchAnchored 事件的
#      index/root 与明细一致（批次根续接上锚证据）。
#
# gas 口径：Monad 按 gas_limit × price 计费（不是 used）——同时核对
# receipt.gasUsed == 明细 gasLimit，佐证账单口径。
#
# 用法：scripts/check_final_settlement.sh [detail.json]
#   默认明细：/tmp/monad-final-settlement.json
# =============================================================================
set -euo pipefail

DETAIL="${1:-/tmp/monad-final-settlement.json}"
RPC="${MONAD_TESTNET_RPC_URL:-https://testnet-rpc.monad.xyz}"
CAST=/Users/mac/.foundry/bin/cast

command -v python3 >/dev/null 2>&1 || { echo "error: python3 不存在" >&2; exit 1; }
[[ -x "$CAST" ]] || { echo "error: cast 不存在 $CAST" >&2; exit 1; }
[[ -f "$DETAIL" ]] || { echo "error: 明细不存在 $DETAIL" >&2; exit 1; }

j() { python3 -c "import json,sys; print(json.load(open('$DETAIL'))$1)"; }
SETTLE_WRAP="$(j "['stack']['settleWrap']")"
VERIFIER="$(j "['stack']['groth16Verifier']")"
INBOX="$(j "['stack']['l1Inbox']")"
SETTLE_TX="$(j "['settle']['tx']")"
ANCHOR_TX="$(j "['anchor']['tx']")"
PROOF_PATH="$(j "['wrap']['proofPath']")"
SETTLE_LIMIT="$(j "['settle']['gasLimit']")"
ANCHOR_LIMIT="$(j "['anchor']['gasLimit']")"
[[ -f "$PROOF_PATH" ]] || { echo "error: 包裹证明不存在 $PROOF_PATH" >&2; exit 1; }

# 带重试的 RPC（公共测试网偶发超时）
rpc() {
  local out="" i
  for i in 1 2 3 4 5 6; do
    out=$("$@" --rpc-url "$RPC" 2>/dev/null || true)
    [ -n "$out" ] && { echo "$out"; return 0; }
    sleep 4
  done
  echo "error: RPC 连续失败: $*" >&2
  return 1
}

echo "==> 明细 $DETAIL"
echo "    settleWrap = $SETTLE_WRAP"
echo "    settleTx   = $SETTLE_TX"
echo "    anchorTx   = $ANCHOR_TX"

# ---------- 1. settle 交易回执 ----------
R="$(rpc "$CAST" receipt "$SETTLE_TX" --json)"
python3 - "$R" "$SETTLE_LIMIT" "$SETTLE_WRAP" <<'EOF'
import json, sys
r = json.loads(sys.argv[1]); limit = int(sys.argv[2]); to = sys.argv[3].lower()
assert r.get('status') == '0x1', f"settle 回执未成功: status={r.get('status')}"
assert (r.get('to') or '').lower() == to, f"回执 to={r.get('to')} != SettleWrap {to}"
gu = int(r['gasUsed'], 16)
print(f"[1/5] settleTx status=0x1, to=SettleWrap, gasUsed={gu}, block={int(r['blockNumber'],16)}")
print(f"      gasUsed == gasLimit({limit})：{gu == limit}（Monad 按 limit×price 计费口径佐证）")
EOF

# ---------- 2. WrapSettled 事件逐字段核对 ----------
TOPIC0="$("$CAST" keccak "WrapSettled(uint256,uint256,uint256)")"
python3 - "$R" "$TOPIC0" "$SETTLE_WRAP" "$PROOF_PATH" <<'EOF'
import json, sys
r, topic0, settle, path = json.loads(sys.argv[1]), sys.argv[2].lower(), sys.argv[3].lower(), sys.argv[4]
p = json.load(open(path))
def pad(x): return x.lower().removeprefix('0x').rjust(64, '0')
want = [pad(p['program_hash']), pad(p['hand_binding'])]
want_data = pad(p['fact'])
hits = [lg for lg in r.get('logs', [])
        if lg['address'].lower() == settle and lg['topics'][0].lower() == topic0]
assert hits, "回执中无 WrapSettled 事件"
lg = hits[0]
assert lg['topics'][1].lower() == '0x' + want[0], "事件 programHash 不符"
assert lg['topics'][2].lower() == '0x' + want[1], "事件 handBinding 不符"
assert lg['data'].lower().removeprefix('0x') == want_data, "事件 fact 不符"
print(f"[2/5] WrapSettled 事件匹配（{settle}）")
print(f"      programHash={p['program_hash']} handBinding={p['hand_binding']} fact={p['fact']}")
EOF

# ---------- 3. cast call verifyProof == true（b_evm，现场重建 calldata） ----------
CD="$(python3 - "$PROOF_PATH" <<'EOF'
import json, subprocess, sys
CAST = "/Users/mac/.foundry/bin/cast"
p = json.load(open(sys.argv[1]))
h = lambda s: int(s, 16)
w = lambda v: v.to_bytes(32, 'big')
sel = subprocess.run([CAST, 'sig', 'verifyProof(uint256[2],uint256[2][2],uint256[2],uint256[3])'],
                     capture_output=True, text=True).stdout.strip()
assert sel.startswith('0x') and len(sel) == 10, sel
body = b''.join(w(h(x)) for x in p['proof']['a'])
for row in p['proof']['b_evm']:
    body += b''.join(w(h(x)) for x in row)
body += b''.join(w(h(x)) for x in p['proof']['c'])
body += b''.join(w(h(x)) for x in [p['program_hash'], p['hand_binding'], p['fact']])
print('0x' + bytes.fromhex(sel[2:]).hex() + body.hex())
EOF
)"
OUT="$(rpc "$CAST" call "$VERIFIER" "$CD")"
python3 -c "
out = '$OUT'.strip('\"')
assert out == '0x' + '00'*31 + '01', f'verifyProof 返回非 true: {out}'
print('[3/5] cast call Groth16Verifier.verifyProof(...) == true')"
echo "      selector: $("$CAST" sig 'verifyProof(uint256[2],uint256[2][2],uint256[2],uint256[3])')  calldata $((${#CD}/2-1)) bytes"

# ---------- 4. settledFact(handBinding) == fact ----------
HB="$(python3 -c "import json;print(json.load(open('$PROOF_PATH'))['hand_binding'])")"
FACT="$(python3 -c "import json;print(json.load(open('$PROOF_PATH'))['fact'])")"
SF="$(rpc "$CAST" call "$SETTLE_WRAP" "settledFact(uint256)" "$HB")"
python3 -c "
sf, fact = '$SF', '$FACT'
assert sf == fact or int(sf, 16) == int(fact, 16), f'settledFact 不符: {sf} != {fact}'
print(f'[4/5] settledFact({\"$HB\"}) == {fact}')"

# ---------- 5. anchor 交易回执 + BatchAnchored 事件 ----------
A="$(rpc "$CAST" receipt "$ANCHOR_TX" --json)"
ATOPIC0="$("$CAST" keccak "BatchAnchored(uint64,bytes32,uint64)")"
python3 - "$A" "$ATOPIC0" "$INBOX" "$ANCHOR_LIMIT" "$DETAIL" <<'EOF'
import json, sys
r, topic0, inbox, limit, detail_path = json.loads(sys.argv[1]), sys.argv[2].lower(), sys.argv[3].lower(), int(sys.argv[4]), sys.argv[5]
d = json.load(open(detail_path))
assert r.get('status') == '0x1', f"anchor 回执未成功: status={r.get('status')}"
assert (r.get('to') or '').lower() == inbox, f"anchor to={r.get('to')} != L1Inbox {inbox}"
assert int(r['gasUsed'], 16) == limit, f"anchor gasUsed != gasLimit({limit})"
idx = int(d['anchor']['index'])
root = d['anchor']['batch_root'].lower().removeprefix('0x').rjust(64, '0')
hits = [lg for lg in r.get('logs', [])
        if lg['address'].lower() == inbox and lg['topics'][0].lower() == topic0]
assert hits, "anchor 回执中无 BatchAnchored 事件"
lg = hits[0]
assert int(lg['topics'][1], 16) == idx, f"事件 index 不符: {lg['topics'][1]} != {idx}"
data = lg['data'].lower().removeprefix('0x')
assert data[:64] == root, "事件 batch root 不符"
print(f"[5/5] anchorTx status=0x1, to=L1Inbox, BatchAnchored(index={idx}, root=0x{root[:8]}…) 匹配")
EOF

echo ""
echo "check_final_settlement: OK — 全链路链上证据成立 [$RPC]"
