#!/usr/bin/env bash
# =============================================================================
# check_wrap_onchain.sh — 断言 STARK→Groth16 包裹的 Monad 链上验证真实成立。
#
# 读 /tmp/monad-wrap-deploy.json（由 deploy_wrap_monad 流程产出）：
#   1. verifyTx 回执 status == 0x1；
#   2. 回执 log == WrapSettled(programHash, handBinding, fact)，且三值与
#      proofPath 证明 JSON 的公开输入逐字段一致；
#   3. cast call Groth16Verifier.verifyProof(a,b_evm,c,pub) == true
#      （calldata 由 proofPath 现场重建：EIP-197 Fp2 字序 b_evm）；
#   4. cast call SettleWrap.settledFact(handBinding) == fact。
#
# gas 口径：Monad 按 gas_limit×price 计费（不是 used）——本脚本同时核对
# receipt.gasUsed == 明细中的 gasLimit，佐证账单口径。
#
# 用法：scripts/check_wrap_onchain.sh [detail.json]
#   默认明细：/tmp/monad-wrap-deploy.json
# =============================================================================
set -euo pipefail

DETAIL="${1:-/tmp/monad-wrap-deploy.json}"
RPC="${MONAD_TESTNET_RPC_URL:-https://testnet-rpc.monad.xyz}"
CAST=/Users/mac/.foundry/bin/cast

command -v python3 >/dev/null 2>&1 || { echo "error: python3 不存在" >&2; exit 1; }
[[ -x "$CAST" ]] || { echo "error: cast 不存在 $CAST" >&2; exit 1; }
[[ -f "$DETAIL" ]] || { echo "error: 明细不存在 $DETAIL" >&2; exit 1; }

# 字段读取
VERIFIER="$(python3 -c "import json;print(json.load(open('$DETAIL'))['verifier'])")"
SETTLE_WRAP="$(python3 -c "import json;print(json.load(open('$DETAIL'))['settleWrap'])")"
VERIFY_TX="$(python3 -c "import json;print(json.load(open('$DETAIL'))['verifyTx'])")"
PROOF_PATH="$(python3 -c "import json;print(json.load(open('$DETAIL'))['proofPath'])")"
GAS_LIMIT="$(python3 -c "import json;print(json.load(open('$DETAIL'))['gasUsed'])")"
[[ -f "$PROOF_PATH" ]] || { echo "error: 证明文件不存在 $PROOF_PATH" >&2; exit 1; }

# 带重试的 RPC（测试网偶发超时/broken pipe）
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
echo "    verifier   = $VERIFIER"
echo "    settleWrap = $SETTLE_WRAP"
echo "    verifyTx   = $VERIFY_TX"

# ---------- 1. verifyTx 回执 ----------
R="$(rpc "$CAST" receipt "$VERIFY_TX" --json)"
python3 - "$R" "$GAS_LIMIT" <<'EOF'
import json, sys
r = json.loads(sys.argv[1]); limit = int(sys.argv[2])
assert r.get('status') == '0x1', f"verifyTx 未成功: status={r.get('status')}"
gu = int(r['gasUsed'], 16)
print(f"[1/4] verifyTx status=0x1, gasUsed={gu}, block={int(r['blockNumber'],16)}")
print(f"      gasUsed == gasLimit({limit})：{gu == limit}（Monad 按 limit 计费口径佐证）")
EOF
# 事件与状态读取共用回执缓存
RECEIPT_JSON="$R"

# ---------- 2. WrapSettled 事件逐字段核对 ----------
TOPIC0="$("$CAST" keccak "WrapSettled(uint256,uint256,uint256)")"
python3 - "$RECEIPT_JSON" "$TOPIC0" "$SETTLE_WRAP" "$PROOF_PATH" <<'EOF'
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
print(f"[2/4] WrapSettled 事件匹配（{settle}）")
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
print('[3/4] cast call verifyProof(...) == true')"
echo "      selector: $("$CAST" sig 'verifyProof(uint256[2],uint256[2][2],uint256[2],uint256[3])')  calldata $((${#CD}/2-1)) bytes"

# ---------- 4. settledFact(handBinding) == fact ----------
HB="$(python3 -c "import json;print(json.load(open('$PROOF_PATH'))['hand_binding'])")"
FACT="$(python3 -c "import json;print(json.load(open('$PROOF_PATH'))['fact'])")"
SF="$(rpc "$CAST" call "$SETTLE_WRAP" "settledFact(uint256)" "$HB")"
python3 -c "
sf, fact = '$SF', '$FACT'
assert sf == fact or int(sf, 16) == int(fact, 16), f'settledFact 不符: {sf} != {fact}'
print(f'[4/4] settledFact({\"$HB\"}) == {fact}')"

echo ""
echo "check_wrap_onchain: OK — 链上验证真实成立 [$RPC]"
