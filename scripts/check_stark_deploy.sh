#!/usr/bin/env bash
# check_stark_deploy.sh — stark 服务器 -monad 独立实例部署探活（逐项，set -e）。
#
# 门禁口径（2026-09-29 服务器运维决策）：
#   - 硬门禁 = texas-monad(:1544) + explorer-gateway-monad(:18950) +
#     monad-settlementd-monad 三单元健康 + settlementd 轮询正常
#     （batchCount/aggregateCount 校准一致）+ 现网单元未受影响；
#   - zchain-monad-node@0..3 四节点停止为决策授权的例外（磁盘水位自救：
#     链数据以 ~150MB/min 净增、仅 8.7G 起始余量无法承载；节点曾真实出块
#     至 height 2695+，数据已归档 chain-archive-20260928.tar.zst，扩盘后
#     可按 500ms+ 间隔恢复）；节点相关检查降级为信息项（NODE-*），不计入门禁；
#   - 磁盘检查按 95% 危险线判定（82% 当前值仅报告）。
#
# 连接策略：先建立 ssh ControlMaster（该服务器对高频新建连接敏感），
# 之后全部检查经同一 mux 连接多路复用。
#
# 用法: bash scripts/check_stark_deploy.sh
# 退出码: 0 = 门禁通过；1 = 门禁有 FAIL 项（逐项打印，不中断）。
set -euo pipefail

CM_SOCK=/tmp/cm-stark-deploy
SSH_OPTS=(-o BatchMode=yes -o ControlMaster=auto -o ControlPath=$CM_SOCK -o ControlPersist=300 -o ConnectTimeout=20 -o ServerAliveInterval=15)
HOST=stark
RPC_BASE=18645
GW_PORT=18950
TEXAS_PORT=1544

fails=0

# ===== 0. 建立 ControlMaster（最多 10 次，每次间隔 3 分钟）=====
rm -f "$CM_SOCK" 2>/dev/null || true
master_ok=0
for attempt in 1 2 3 4 5 6 7 8 9 10; do
  if ssh "${SSH_OPTS[@]}" "$HOST" 'echo MASTER_UP' >/dev/null 2>&1; then
    echo "MASTER_UP (attempt $attempt)"
    master_ok=1
    break
  fi
  echo "master attempt $attempt failed, waiting 180s..."
  sleep 180
done
[ "$master_ok" = 1 ] || { echo "FATAL: 无法建立 ssh master 连接"; exit 1; }

# run_check <名称> <远端命令...>：经 mux 逐项执行；PASS/FAIL 打印摘要。
run_check() {
  local name="$1"; shift
  local out rc
  if out=$(ssh "${SSH_OPTS[@]}" "$HOST" "$@" 2>&1); then
    echo "PASS  $name :: $(echo "$out" | tail -2 | tr '\n' ' ' | cut -c1-160)"
  else
    rc=$?
    echo "FAIL  $name :: $(echo "$out" | tail -3 | tr '\n' ' ' | cut -c1-220) (rc=$rc)"
    fails=$((fails + 1))
  fi
}

# run_info <名称> <远端命令...>：信息项（授权例外），结果不计入门禁。
run_info() {
  local name="$1"; shift
  local out
  if out=$(ssh "${SSH_OPTS[@]}" "$HOST" "$@" 2>&1); then
    echo "INFO  $name :: $(echo "$out" | tail -2 | tr '\n' ' ' | cut -c1-160)"
  else
    echo "INFO  $name :: 例外状态（见头部注释）: $(echo "$out" | tail -1 | cut -c1-160)"
  fi
}

echo "== check_stark_deploy: $(date '+%F %T') =="

# 0. SSH 连通
run_check "ssh-连通" "echo ok"

# ===== 硬门禁 1：三单元 + 现网单元状态 =====
run_check "单元 texas-monad active" "systemctl is-active texas-monad.service"
run_check "单元 explorer-gateway-monad active" "systemctl is-active explorer-gateway-monad.service"
run_check "单元 monad-settlementd-monad active" "systemctl is-active monad-settlementd-monad.service"
run_check "现网 texas.service 未受影响（仍 active）" "systemctl is-active texas.service"
run_check "现网 texas-test-guard.service 未受影响" "systemctl is-active texas-test-guard.service"
run_check "现网 nginx 未受影响" "systemctl is-active nginx.service"

# ===== 硬门禁 2：服务面探活 =====
run_check "texas-monad :$TEXAS_PORT HTTP 200" \
  "curl -s -o /dev/null -w '%{http_code}' -m 5 http://127.0.0.1:$TEXAS_PORT/ | grep -q 200 && echo http-ok"
run_check "explorer-gateway :$GW_PORT /api/v1/status" \
  "curl -s -m 5 http://127.0.0.1:$GW_PORT/api/v1/status | grep -q '{' && echo status-ok"
# settlementd journal：adapter connected 且无 fatal
# （先整体捕获再 grep：pipefail 下 `journalctl | grep -q` 会因 SIGPIPE 误判）
run_check "settlementd journal: adapter connected" \
  "out=\$(journalctl -u monad-settlementd-monad.service --no-pager -n 200 || true); printf '%s' \"\$out\" | grep -q 'adapter connected' && echo journal-ok"
run_check "settlementd journal: 无 fatal" \
  "out=\$(journalctl -u monad-settlementd-monad.service --no-pager -n 200 || true); ! printf '%s' \"\$out\" | grep -q 'fatal:'"

# ===== 硬门禁 3：settlementd 链面校准（state 预置锚数 = 链上计数，续接不重放）=====
run_check "settlement state 校准 = 链上 batchCount/aggregateCount" \
  "python3 -c \"
import json, urllib.request
s = json.load(open('/opt/texas-monad/run/settlement-state.json'))
def call(method, params):
    req = urllib.request.Request('https://testnet-rpc.monad.xyz',
        data=json.dumps({'jsonrpc':'2.0','id':1,'method':method,'params':params}).encode(),
        headers={'content-type':'application/json'})
    return int(json.load(urllib.request.urlopen(req, timeout=15))['result'], 16)
bc = call('eth_call', [{'to':'0x60ecddd1359356a43a69de84a1cf235a69a30e71','data':'0x06f13056'},'latest'])
ac = call('eth_call', [{'to':'0x60ecddd1359356a43a69de84a1cf235a69a30e71','data':'0x2c3f6cc8'},'latest'])
batch_keys = [k for k in s['anchors'] if k.startswith('batch:')]
agg_keys = [k for k in s['anchors'] if k.startswith('aggregate:')]
print('chain batchCount=%d aggregateCount=%d; state batch=%d aggregate=%d' % (bc, ac, len(batch_keys), len(agg_keys)))
assert len(batch_keys) == bc and len(agg_keys) == ac, 'calibration mismatch'
\""

# ===== 硬门禁 4：磁盘 95% 危险线 =====
run_check "磁盘已用 < 95% 危险线" \
  "python3 -c \"
import subprocess
out = subprocess.run(['df','--output=pcent','/'], capture_output=True, text=True).stdout
pct = int(out.split()[1].rstrip('%'))
print('disk_used=%d%%' % pct)
assert pct < 95, 'disk at/above 95%% danger line'
\""

# ===== 信息项（决策授权例外）：四节点停止、链 RPC 不监听、链数据已归档 =====
for i in 0 1 2 3; do
  run_info "NODE-单元 zchain-monad-node@${i}（授权停止）" \
    "systemctl is-active zchain-monad-node@${i}.service"
done
run_info "NODE-链数据归档在位（恢复用）" \
  "ls -lh /opt/zchain-monad/chain-archive-20260928.tar.zst | awk '{print \$5, \$9}' && ls /opt/zchain-monad/chain/genesis_validators.json /opt/zchain-monad/chain/validator_0.key >/dev/null && echo genesis-keys-kept"

echo
if [ "$fails" -eq 0 ]; then
  echo "ALL_GATE_CHECKS_PASSED"
else
  echo "FAILED_CHECKS=$fails"
  exit 1
fi
