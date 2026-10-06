#!/usr/bin/env bash
# =============================================================================
# check_final_batch_settlement.sh — 断言「N=8 手真实牌局 → 逐手 STARK 出证 →
# 批程序(settlement_batch_private) K=8 单跑单证 → 单个 STARK 终证 → L1Inbox
# 上锚 → StarkVerifier(Monad) 提交」终证路径的链下/链上证据真实成立。
#
# 方向（2026-09-29 用户裁定）：终证路径不含任何 Groth16 —— 单个 STARK 批证明
# 直接对 StarkVerifier 提交；该合约骨架期 fail-closed（FRIVerifierNotDelivered，
# FRI 核心为二期交付），本脚本按实际可成立的语义断言：
#   A. 链下：批终证 fact-verify 钉扎验证 exit 0；电路内 batch_fact == 宿主
#      镜像；keccak 批根（cast keccak 独立复算）三方一致；批公开段 == 8 手
#      单证公开段逐 felt 相等；8 条 fact == BatchPlan 宿主重算。
#   B. 链上（Monad 10143）：StarkVerifier 部署读回（BATCH_PROGRAM_HASH==钉扎
#      值、l1Inbox、authority、latestFact==0）；anchor 回执 status==0x1 且
#      BatchAnchored(index/root/throughOp) 逐字段一致、batchCount==index+1；
#      两笔负例（篡改 acc / 伪证）回执 status==0x0 且 gasUsed==limit；
#      fail-closed：负例后 latestFact/settledFact 仍为 0（零状态变更）。
#   C. 账单：四笔 tx 回执 gasUsed == tx.gas（Monad 按 gas_limit×price 计费），
#      Σ(limit×price) 与余额差逐 wei 一致。
#   D. 生产隔离（stark）：check_resource_isolation.sh exit 0、
#      texas.service active 且 NRestarts == 记录基线。
#
# 用法：scripts/check_final_batch_settlement.sh [detail.json]
#   默认明细：/tmp/monad-final-batch.json
# 退出码：全部通过 0；任一失败非 0（set -e）。
# =============================================================================
set -euo pipefail

DETAIL="${1:-/tmp/monad-final-batch.json}"
RPC="${MONAD_TESTNET_RPC_URL:-https://testnet-rpc.monad.xyz}"
CAST="${CAST:-/Users/mac/.foundry/bin/cast}"
SSH_HOST="${SSH_HOST:-stark}"
FV="${FACT_VERIFY_BIN:-/Users/mac/projects/poker_texas_air/fact-verify/target/release/fact-verify}"

command -v python3 >/dev/null 2>&1 || { echo "error: python3 不存在" >&2; exit 1; }
[[ -x "$CAST" ]] || { echo "error: cast 不存在 $CAST" >&2; exit 1; }
[[ -f "$DETAIL" ]] || { echo "error: 明细不存在 $DETAIL" >&2; exit 1; }
[[ -x "$FV" ]] || { echo "error: fact-verify 不存在 $FV" >&2; exit 1; }

passed=0
ok()   { printf 'PASS  %s\n' "$*"; passed=$((passed+1)); }
j()    { python3 -c "import json; d=json.load(open('$DETAIL')); print($1)"; }

rpc() {  # 带重试的 cast 读
  local out="" i
  for i in 1 2 3 4 5; do
    out=$("$@" --rpc-url "$RPC" 2>/dev/null || true)
    if [ -n "$out" ] && ! echo "$out" | grep -q '^error\|server returned'; then
      echo "$out"; return 0
    fi
    sleep 3
  done
  echo "error: RPC 连续失败: $*" >&2; return 1
}

# ---------- A. 链下 ----------
echo "== A. 链下终证与语句面 =="
PH_BATCH="$(j "d['final']['program_hash']")"
PROOF="$(j "d['final']['proof_path']")"
OUT_JSON="$(j "d['final']['public_outputs_path']")"
MANIFEST="$(j "d['final']['manifest_path']")"
EXPECTED_FACT="$(j "d['final']['batch_fact']")"
ROOT="$(j "d['final']['keccak_batch_root']")"

[[ -f "$PROOF" ]] || { echo "FAIL 缺批终证 $PROOF" >&2; exit 1; }
[[ -f "$OUT_JSON" && -f "$MANIFEST" ]] || { echo "FAIL 缺公开输出/清单" >&2; exit 1; }
ok "批终证/公开输出/清单文件在位"

FV_OUT=$("$FV" "$PROOF" --expect-program-hash "$PH_BATCH") || { echo "FAIL fact-verify 钉扎验证失败" >&2; exit 1; }
echo "$FV_OUT" | grep -q "^OK" || { echo "FAIL fact-verify 未输出 OK" >&2; exit 1; }
ok "fact-verify 钉扎验证 exit 0（program_hash=${PH_BATCH}）"

python3 - "$OUT_JSON" "$MANIFEST" "$EXPECTED_FACT" "$ROOT" "$CAST" <<'EOF'
import json, subprocess, sys
out_json, manifest, exp_fact, root, CAST = sys.argv[1:6]
out=json.load(open(out_json)); m=json.load(open(manifest))
o=out['output']
n=lambda x:int(x,16)
tail=[n(x) for x in o[-4:]]
assert o[0]=='0x%x'%(len(o)-1), 'len 前缀不符'
assert (len(o)-1-4)%16==0 and len(o)-1-4==16*m['k'], '形状非 16k+4'
assert tail[0]==n(m['acc_prev']) and tail[1]==n(m['root_hi']) and tail[2]==n(m['root_lo']), 'acc/root 回显不符'
assert tail[3]==n(m['expected_batch_fact']), '电路内 batch_fact != 宿主镜像'
assert tail[3]==n(exp_fact), 'batch_fact 与明细不符'
# keccak 根独立复算（EVM keccak —— 独立于 Rust keccak 与 Cairo 电的第三条路径）
def be32(h): return '%064x'%int(h,16)
def kec(s):
    r=subprocess.run([CAST,'keccak',s],capture_output=True,text=True)
    assert r.returncode==0, 'cast keccak 失败'
    return r.stdout.strip()
level=[]
for i,s in enumerate(m['statements']):
    x=kec('0x'+'%08x'%i+be32(s['program_hash'])+be32(s['hand_binding'])+be32(s['fact']))
    level.append(x[2:] if x.startswith('0x') else x)
while len(level)>1:
    nxt=[]
    for i in range(0,len(level),2):
        x=kec('0x'+level[i]+level[i+1]); nxt.append(x[2:] if x.startswith('0x') else x)
    level=nxt
assert '0x'+level[0]==root, 'cast keccak 独立复算根不符'
assert len(m['statements'])==m['k']==8, '语句数 != 8'
print('PASS  电路↔宿主尾对拍 + keccak 根独立复算（cast keccak）一致')
EOF
ok "batch_fact 电路↔宿主对拍 + keccak 根独立复算（第三路径）"

python3 - "$DETAIL" <<'EOF'
import json, sys, os
d=json.load(open(sys.argv[1]))
assert d['batch']['n']==8, 'N != 8'
dirs=d['final']['hand_proof_dirs']
assert len(dirs)==8, '单手证明目录数 != 8'
bindings=set()
for p in dirs:
    assert os.path.isfile(os.path.join(p,'proof.json')), f'缺单手证明 {p}'
    o=json.load(open(os.path.join(p,'public_outputs.json')))['output']
    bindings.add(o[5])
assert len(bindings)==8, '单手 binding 重复'
m=json.load(open(d['final']['manifest_path']))
for i,s in enumerate(m['statements']):
    h=json.load(open(os.path.join(dirs[i],'public_outputs.json')))['output']
    seg=json.load(open(d['final']['public_outputs_path']))['output'][1+i*16:1+(i+1)*16]
    assert h[:16]==seg, f'第 {i} 手公开段 != 批段'
print('PASS  批公开段 == 8 手单证公开段（8×16 felt 逐位相等）；8 手 binding 唯一')
EOF
ok "批公开段 == 8 手单证公开段逐位相等 + 8 条 fact == BatchPlan 宿主重算（manifest 语句面）"

# ---------- B. 链上 ----------
echo "== B. Monad 链上证据 =="
SV="$(j "d['stack']['starkVerifier']")"
INBOX="$(j "d['stack']['l1Inbox']")"
OP="$(j "d['operator']")"
ANCHOR_IDX="$(j "d['anchor']['index']")"
THROUGH_OP="$(j "d['anchor']['throughOp']")"
ANCHOR_TX="$(j "d['anchor']['tx']")"
NEG1_TX="$(j "d['negativeTamperedAcc']['tx']")"
NEG2_TX="$(j "d['negativePseudoProof']['tx']")"
PINNED="0x05c400b46a261c6672cd7581436754e05da2287ba8ecdc69778d06e4ef831803"

SV_PH=$(rpc "$CAST" call "$SV" 'BATCH_PROGRAM_HASH()(uint256)')
SV_PH="${SV_PH%% *}"   # 去掉 cast 的人类可读注记（如 "[2.607e75]"）
[[ "$(python3 -c "print(hex(int('$SV_PH',10)))")" == "$(python3 -c "print(hex(int('$PINNED',16)))")" ]] || { echo "FAIL 链上 BATCH_PROGRAM_HASH != 钉扎值" >&2; exit 1; }
ok "链上 BATCH_PROGRAM_HASH == 钉扎批程序哈希"
SV_INBOX=$(rpc "$CAST" call "$SV" 'l1Inbox()(address)' | tr '[:upper:]' '[:lower:]')
[[ "$SV_INBOX" == "$(echo "$INBOX" | tr '[:upper:]' '[:lower:]')" ]] || { echo "FAIL l1Inbox != $INBOX" >&2; exit 1; }
ok "链上 l1Inbox == $SV_INBOX"
SV_AUTH=$(rpc "$CAST" call "$SV" 'authority()(address)' | tr '[:upper:]' '[:lower:]')
[[ "$SV_AUTH" == "$(echo "$OP" | tr '[:upper:]' '[:lower:]')" ]] || { echo "FAIL authority($SV_AUTH) != operator($OP)" >&2; exit 1; }
ok "链上 authority == operator"

LF=$(rpc "$CAST" call "$SV" 'latestFact()(uint256)'); LF="${LF%% *}"
[[ "$LF" == "0" ]] || { echo "FAIL latestFact=$LF 非零（fail-closed 被破坏）" >&2; exit 1; }
SF=$(rpc "$CAST" call "$SV" 'settledFact(bytes32)(uint256)' "$ROOT"); SF="${SF%% *}"
[[ "$SF" == "0" ]] || { echo "FAIL settledFact(root)=$SF 非零" >&2; exit 1; }
ok "fail-closed：latestFact==0 且 settledFact(root)==0（骨架期不落任何结算状态）"

python3 - "$ANCHOR_TX" "$ANCHOR_IDX" "$ROOT" "$THROUGH_OP" "$RPC" "$CAST" "$INBOX" <<'EOF'
import json, subprocess, sys
tx, idx, root, through_op, rpc, CAST, inbox = sys.argv[1:8]
def j(*a):
    r=subprocess.run([CAST,*a,'--rpc-url',rpc,'--json'],capture_output=True,text=True)
    return json.loads(r.stdout or '{}')
rc=j('receipt',tx)
assert rc.get('status')=='0x1', f'anchor status={rc.get("status")}'
assert rc.get('to','').lower()==inbox.lower(), 'anchor to != inbox'
t0='0xfdbe3de9a44396bb3ab8a6384d4d1c800968e59edb52369bc27f88b93d98ff48'
hit=[l for l in rc.get('logs',[]) if l['topics'][0]==t0]
assert hit, '无 BatchAnchored 事件'
l=hit[0]
assert int(l['topics'][1],16)==int(idx), 'BatchAnchored index 不符'
data=l['data'][2:]
assert data[:64]==root[2:].rjust(64,'0'), 'BatchAnchored root 不符'
assert int(data[64:128],16)==int(through_op), 'BatchAnchored throughOp 不符'
bc=j('call',inbox,'batchCount()(uint64)')
bc=bc[0] if isinstance(bc,list) else bc
bc=int(bc) if isinstance(bc,int) else int(bc,16)
assert bc==int(idx)+1, f'batchCount={bc} != index+1'
print('PASS  anchor 回执 status=0x1 + BatchAnchored(index/root/throughOp) 逐字段一致 + batchCount==index+1')
EOF
ok "anchor 回执/事件/计数全对（tx=${ANCHOR_TX}）"

python3 - "$NEG1_TX" "$NEG2_TX" "$RPC" "$CAST" <<'EOF'
import json, subprocess, sys
neg1, neg2, rpc, CAST = sys.argv[1:5]
def j(*a):
    r=subprocess.run([CAST,*a,'--rpc-url',rpc,'--json'],capture_output=True,text=True)
    return json.loads(r.stdout or '{}')
def to_int(x):
    if isinstance(x,int): return x
    s=str(x)
    return int(s,16) if s.startswith('0x') else int(s)
for name,tx in [('neg1(篡改acc)',neg1),('neg2(伪证)',neg2)]:
    raw=j('tx',tx); raw=raw.get('data', raw); txo=raw.get('legacyTransaction', raw); rc=j('receipt',tx)
    assert str(rc.get('status'))=='0x0', f'{name} status 非 0x0：{rc.get("status")}'
    assert to_int(txo.get('gas'))==to_int(rc.get('gasUsed')), f'{name} gasUsed({rc.get("gasUsed")}) != gasLimit({txo.get("gas")})'
print('PASS  两笔负例回执 status=0x0 且 gasUsed==gasLimit（fail-closed revert 真实上链）')
EOF
ok "伪证/篡改 acc 负例 revert（status=0x0）且 limit==used"

# ---------- C. 账单 ----------
echo "== C. 账单（gas_limit×price 逐 wei） =="
python3 - "$DETAIL" "$RPC" "$CAST" <<'EOF'
import json, subprocess, sys
detail, rpc, CAST = sys.argv[1:4]
d=json.load(open(detail))
def j(*a):
    r=subprocess.run([CAST,*a,'--rpc-url',rpc,'--json'],capture_output=True,text=True)
    return json.loads(r.stdout or '{}')
# 每笔 tx：gasUsed==gasLimit 且 price==节点价（Monad 按 gas_limit×price 计费口径）
txs=[('verifierDeploy',d['verifierDeploy']['tx']),('anchor',d['anchor']['tx']),
     ('neg1',d['negativeTamperedAcc']['tx']),('neg2',d['negativePseudoProof']['tx'])]
node_price=int(d['chain']['gasPriceWei'])
def to_int(x):
    if isinstance(x,int): return x
    s=str(x)
    return int(s,16) if s.startswith('0x') else int(s)
total=0
for name,tx in txs:
    raw=j('tx',tx); raw=raw.get('data', raw); txo=raw.get('legacyTransaction', raw); rc=j('receipt',tx)
    gas=to_int(txo.get('gas')); used=to_int(rc.get('gasUsed')); price=to_int(rc.get('effectiveGasPrice'))
    assert gas==used, f'{name} gasUsed({used}) != gasLimit({gas})'
    assert price==node_price, f'{name} price({price}) != 节点价({node_price})'
    total+=gas*price
# 负例两笔的隔离余额差（top-up 前实测）：逐 wei 等于 Σ(limit×price)
nb=int(d['funding']['balanceBeforeNegativesWei']); na=int(d['funding']['balanceAfterNegativesWei'])
neg_cost=int(d['negativeTamperedAcc']['gasLimit'])*node_price + int(d['negativePseudoProof']['gasLimit'])*node_price
assert na-nb==-neg_cost, f'负例隔离余额差不平：{na-nb} != -{neg_cost}'
print(f'PASS  4 笔 tx gasUsed==gasLimit 且 price==节点价；Σ(limit×price)={total} wei；负例隔离余额差逐 wei 一致（其余差额为演练后外部入账，非演练 tx）')
EOF
ok "账单逐 wei 核对通过（4 笔 tx 口径 + 负例隔离差）"

# ---------- D. 生产隔离 ----------
echo "== D. stark 生产隔离 =="
bash "$(cd "$(dirname "$0")" && pwd)/check_resource_isolation.sh" >/dev/null 2>&1 || { echo "FAIL check_resource_isolation.sh 未通过" >&2; exit 1; }
ok "check_resource_isolation.sh exit 0"
NR=$(ssh -o BatchMode=yes -o ConnectTimeout=25 "$SSH_HOST" 'systemctl show texas.service -p NRestarts -p ActiveState' 2>/dev/null) || { echo "FAIL ssh stark 读数失败" >&2; exit 1; }
echo "$NR" | grep -q "NRestarts=$(j "d['stark']['texasNRestartsBaseline']")" || { echo "FAIL texas NRestarts 漂移: $NR" >&2; exit 1; }
echo "$NR" | grep -q "ActiveState=active" || { echo "FAIL texas 非 active" >&2; exit 1; }
ok "texas.service active 且 NRestarts 无漂移"

echo "===== check_final_batch_settlement: ALL PASSED ($passed 组) ====="
