#!/usr/bin/env bash
# zchain-monad-disk-guard.sh —— zchain-monad 隔离盘水位守卫（stark）
#
# 用法:
#   zchain-monad-disk-guard.sh            # 真实模式（由 zchain-monad-disk-guard.timer 周期调用）
#   zchain-monad-disk-guard.sh --dry-run  # 只读评估：打印将采取的动作，健康系统下恒 exit 0
#
# 职责:
#   /opt/zchain-monad/chain-data（回环镜像 ext4）用量 >= 90% 时，
#   停止白名单内的 zchain-monad 隔离域 unit 并 logger 告警，保护系统盘与 texas.service。
#
# 纪律:
#   - 白名单来自 /opt/zchain-monad/guard-units.conf（每行一个 unit 通配名）。
#   - 硬性保护：通配展开后若命中 texas.service 则 FATAL 拒绝执行
#     （注意 texas-prover-monad.service 含 "texas" 字样但不是生产单元，允许进白名单）。
#   - 对系统盘只读；只 stop，不 start、不删任何文件。
#
# 退出码: 0=正常（未超线/已处置/dry-run 评估完成）; 1=评估失败(挂载缺失等); 2=处置动作失败
set -u

MOUNT="/opt/zchain-monad/chain-data"
CONF="/opt/zchain-monad/guard-units.conf"
THRESHOLD=90
TAG="zchain-monad-disk-guard"
DRY_RUN=0
[ "${1:-}" = "--dry-run" ] && DRY_RUN=1

log() { logger -t "$TAG" "$*"; }

# ---- 评估：挂载点必须存在且可读用量 ----
if ! findmnt -rn -o TARGET --target "$MOUNT" | grep -qx "$MOUNT"; then
  log "ERROR: $MOUNT 未挂载，守卫无法评估（人工检查 losetup/fstab）"
  exit 1
fi
usage=$(df -P --output=pcent "$MOUNT" | tail -1 | tr -dc '0-9')
case "$usage" in ''|*[!0-9]*) log "ERROR: 无法解析 $MOUNT 使用率"; exit 1 ;; esac

avail_mb=$(df -Pm --output=avail "$MOUNT" | tail -1 | tr -dc '0-9')
if [ "$DRY_RUN" = 1 ]; then
  echo "[dry-run] $MOUNT usage=${usage}% threshold=${THRESHOLD}% avail=${avail_mb}MB"
else
  log "水位 ${usage}%（阈值 ${THRESHOLD}%，余 ${avail_mb}MB）"
fi

if [ "$usage" -lt "$THRESHOLD" ]; then
  [ "$DRY_RUN" = 1 ] && echo "[dry-run] 低于阈值，不采取动作"
  exit 0
fi

# ---- 超线：构造白名单内“当前 active”的实例清单 ----
[ -r "$CONF" ] || { log "ERROR: 白名单 $CONF 不可读"; exit 1; }
targets=()
while IFS= read -r pat; do
  [ -z "$pat" ] && continue
  case "$pat" in \#*) continue ;; esac
  while IFS= read -r u; do
    [ -n "$u" ] || continue
    # 硬性纪律：展开结果逐个精确比对，生产单元绝不允许出现在停止清单
    if [ "$u" = "texas.service" ]; then
      log "FATAL: 白名单 '$pat' 展开命中生产单元 texas.service，拒绝执行"
      exit 2
    fi
    [ "$(systemctl is-active "$u" 2>/dev/null || true)" = "active" ] && targets+=("$u")
  done < <(systemctl list-units --all --no-legend --plain "$pat" 2>/dev/null | awk '{print $1}')
done < "$CONF"

if [ "${#targets[@]}" -eq 0 ]; then
  log "ALERT: $MOUNT 使用率 ${usage}% >= ${THRESHOLD}%，白名单内无 active 单元可停（磁盘满风险自担于镜像内）"
  exit 0
fi

for u in "${targets[@]}"; do
  if [ "$DRY_RUN" = 1 ]; then
    echo "[dry-run] 将执行: systemctl stop $u"
  else
    log "ALERT: $MOUNT 使用率 ${usage}% >= ${THRESHOLD}%，停止 $u"
    if systemctl stop "$u"; then
      log "已停止 $u"
    else
      log "ERROR: systemctl stop $u 失败"
      exit 2
    fi
  fi
done
exit 0
