#!/usr/bin/env bash
# ============================================================================
# deploy_client_zchain_test.sh — ZChain 测试前端一键部署（stark 服务器）
#
# 部署内容：client 生产构建（vite build）→ https://zchain.secretpokers.com
# 后端：/opt/texas-test/texas 测试实例（:1443，appchain→zchain 结算）
# 隔离：只写 /var/www/zchain-test/ 与 /etc/nginx/conf.d/zchain-test.conf，
#       不触碰生产 /var/www/poker、poker.conf、:9001、strk.secretpokers.com。
#
# 用法：scripts/deploy_client_zchain_test.sh [--skip-build]
#   --skip-build  复用 client/dist 现有产物（只做上传与生效）
#
# 前置：
#   1. client/.env.production.local 已设 VITE_SERVER_URI=https://zchain.secretpokers.com/
#      （socket.io 同源走 nginx /socket.io/ 反代；.local 已被 .gitignore 忽略）
#   2. stark 可免密 ssh（~/.ssh/config Host stark）
#   3. 首次部署需先手工安装 nginx conf 与证书：
#      scp deploy/zchain-test-nginx.conf stark:/etc/nginx/conf.d/zchain-test.conf
#      certbot certonly --nginx -d zchain.secretpokers.com
#
# E2E 回归：部署后用 zchain/scripts/poker_air_browser_supervisor.sh 以
#   POKER_URL/GAME_API=https://zchain.secretpokers.com 跑 5 手（扩展真实签名）
#   即可验收（详见 zchain docs/test-records/2026-09-22-* 第 4 节）。
# ============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLIENT="$ROOT/client"
STARK_HOST="${STARK_HOST:-stark}"
REMOTE_DIR="${REMOTE_DIR:-/var/www/zchain-test/dist}"
SKIP_BUILD=0
[[ "${1:-}" == "--skip-build" ]] && SKIP_BUILD=1

# 1) 构建（tsc -b 类型检查 + vite build；产物 client/dist）
if [[ "$SKIP_BUILD" != 1 ]]; then
  echo "[deploy] 构建前端（tsc -b && vite build）…"
  (cd "$CLIENT" && npm run build)
else
  echo "[deploy] 跳过构建，复用现有 dist"
fi
[[ -f "$CLIENT/dist/index.html" ]] || { echo "缺少 $CLIENT/dist/index.html"; exit 1; }

# 2) 上传（stark 无 rsync，用 tar 管道；原子切换 dist.new → dist）
echo "[deploy] 上传到 $STARK_HOST:$REMOTE_DIR …"
ssh "$STARK_HOST" "rm -rf ${REMOTE_DIR}.new && mkdir -p ${REMOTE_DIR}.new"
tar -C "$CLIENT/dist" -cf - . | ssh "$STARK_HOST" "tar -C ${REMOTE_DIR}.new -xf - 2>/dev/null"
ssh "$STARK_HOST" "rm -rf ${REMOTE_DIR}.old && \
  mv $REMOTE_DIR ${REMOTE_DIR}.old && mv ${REMOTE_DIR}.new $REMOTE_DIR && \
  nginx -t && systemctl reload nginx"

# 3) 冒烟：本域首页 200、API 反代到测试后端（/api/auth 未带 token 应 401）
sleep 1
CODE_HOME=$(curl -s -o /dev/null -w '%{http_code}' https://zchain.secretpokers.com/)
CODE_API=$(curl -s -o /dev/null -w '%{http_code}' https://zchain.secretpokers.com/api/auth)
echo "[deploy] 首页=$CODE_HOME /api/auth=$CODE_API（预期 200 / 401）"
[[ "$CODE_HOME" == "200" && "$CODE_API" == "401" ]] && echo "[deploy] 完成 ✓" || {
  echo "[deploy] 冒烟失败，检查 nginx conf 与 :1443 后端"; exit 1; }
