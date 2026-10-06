#!/usr/bin/env bash
# install_resource_isolation.sh —— 在 stark 上安装 zchain-monad 资源隔离（CASE B: 服务器空白时用）
# 由本地执行: ssh stark 'bash -s' < install_resource_isolation.sh （先 cd 到本目录，模板文件通过第二个 tar 流进入）
# 纪律: 只增不删；幂等（已存在的配置一律不动）；texas.service 全程只读观测。
# 前置: 本脚本与模板文件同目录，先打包推送到远端 /root/.zmonad-tmp/ 再执行本文件。
set -euo pipefail

TMP=/root/.zmonad-tmp
SYS=/etc/systemd/system
SBIN=/usr/local/sbin
OPT=/opt/zchain-monad
MP=$OPT/chain-data
IMG=$OPT/chain-data.img

echo "== 0. 前置事实 =="
NPROC=$(nproc)
CPU_QUOTA=$(( NPROC / 2 * 100 ))    # systemd 单核百分比语义: 整机一半核
echo "nproc=$NPROC -> CPUQuota=${CPU_QUOTA}%"
ROOT_AVAIL_KB=$(df -Pk / | awk 'NR==2{print $4}')
echo "root avail = $((ROOT_AVAIL_KB/1024)) MiB"
if [ "$ROOT_AVAIL_KB" -lt $((3*1024*1024 + 2*1024*1024)) ]; then
  echo "FATAL: 系统盘余量不足以安置隔离镜像（需 ≥5G: 3G 安全线 + 镜像），终止" >&2
  exit 3
fi

echo "== 1. slice =="
if [ ! -f "$SYS/zchain-recursion.slice" ]; then
  sed "s/__CPU_QUOTA__/$CPU_QUOTA/" "$TMP/zchain-recursion.slice" > "$SYS/zchain-recursion.slice"
  echo "created $SYS/zchain-recursion.slice (CPUQuota=${CPU_QUOTA}%)"
else
  echo "exists, keep: $SYS/zchain-recursion.slice"
fi

echo "== 2. prover 单元与包装 =="
[ -f "$SYS/texas-prover-monad.service" ] || install -m 644 "$TMP/texas-prover-monad.service" "$SYS/texas-prover-monad.service"
mkdir -p "$OPT/bin"
[ -f "$OPT/bin/run-prover-monad.sh" ] || install -m 755 "$TMP/run-prover-monad.sh" "$OPT/bin/run-prover-monad.sh"
# 保持 disabled：绝不 enable/start prover
systemctl disable texas-prover-monad.service >/dev/null 2>&1 || true

echo "== 3. 隔离镜像 =="
IMG_BYTES=$(stat -c %s "$IMG" 2>/dev/null || echo 0)
if [ "$IMG_BYTES" -eq 0 ]; then
  # 容量 = min(6G, 余量-3G安全线)，向下取整 GiB
  CAP_KB=$(( ROOT_AVAIL_KB - 3*1024*1024 ))
  [ "$CAP_KB" -gt $((6*1024*1024)) ] && CAP_KB=$((6*1024*1024))
  CAP_KB=$(( CAP_KB / (1024*1024) * 1024 * 1024 ))   # 向下取整 GiB
  if [ "$CAP_KB" -lt $((2*1024*1024)) ]; then
    echo "FATAL: 可用容量不足 2G，无法建立有意义上限的镜像，终止（如实上报）" >&2
    exit 3
  fi
  CAP_BYTES=$(( CAP_KB * 1024 ))
  echo "image cap = $((CAP_BYTES/1024/1024/1024)) GiB ($CAP_BYTES bytes)"
  fallocate -l "$CAP_BYTES" "$IMG"
  mkfs.ext4 -q -F -L zchain-monad "$IMG"
else
  CAP_BYTES=$IMG_BYTES
  echo "image exists: $IMG ($CAP_BYTES bytes)"
fi

echo "== 4. 挂载 =="
if ! findmnt -rn -o TARGET --target "$MP" 2>/dev/null | grep -qx "$MP"; then
  mkdir -p "$MP"
  LOOP=$(losetup --find --show "$IMG")
  mount -o nodev,nosuid,noexec "$LOOP" "$MP"
  echo "mounted $LOOP -> $MP"
else
  echo "already mounted: $(findmnt -no SOURCE --target "$MP")"
fi

echo "== 5. fstab 持久化 =="
if ! grep -q "chain-data.img" /etc/fstab; then
  cp /etc/fstab /etc/fstab.zmonad-bak   # 只增：备份原 fstab
  echo "$IMG $MP ext4 loop,nosuid,nodev,noexec,nofail,x-systemd.device-timeout=10s 0 2" >> /etc/fstab
  echo "fstab entry appended (备份: /etc/fstab.zmonad-bak)"
else
  echo "fstab already has entry"
fi

echo "== 6. 守卫 + timer =="
[ -f "$SBIN/zchain-monad-disk-guard.sh" ] || install -m 755 "$TMP/zchain-monad-disk-guard.sh" "$SBIN/zchain-monad-disk-guard.sh"
[ -f "$SYS/zchain-monad-disk-guard.service" ] || install -m 644 "$TMP/zchain-monad-disk-guard.service" "$SYS/zchain-monad-disk-guard.service"
[ -f "$SYS/zchain-monad-disk-guard.timer" ] || install -m 644 "$TMP/zchain-monad-disk-guard.timer" "$SYS/zchain-monad-disk-guard.timer"
[ -f "$OPT/MIGRATION.md" ] || install -m 644 "$TMP/MIGRATION.md" "$OPT/MIGRATION.md"
# 白名单: prover 单元 + 勘察发现的节点单元（本脚本只放 prover；节点名由 survey 后人工补）
if [ ! -f "$OPT/guard-units.conf" ]; then
  printf '# zchain-monad 隔离域白名单（每行一个通配；texas.service 受硬保护绝不入列）\ntexas-prover-monad.service\n' > "$OPT/guard-units.conf"
fi

echo "== 7. 启用 =="
systemctl daemon-reload
systemctl enable --now zchain-recursion.slice
systemctl enable --now zchain-monad-disk-guard.timer
mkdir -p "$MP/prover-work" "$MP/nodes"

echo "== 8. 部署状态落盘（check 脚本的期望值来源；从部署后实况采集，已存在则不覆盖） =="
if [ ! -f "$OPT/deploy-state.env" ]; then
  {
    echo "IMG_BYTES=$(stat -c %s "$IMG")"
    echo "CPU_QUOTA=$CPU_QUOTA"
    echo "SLICE_MEMMAX_BYTES=$(systemctl show zchain-recursion.slice -p MemoryMax --value)"
    echo "SLICE_MEMHIGH_BYTES=$(systemctl show zchain-recursion.slice -p MemoryHigh --value)"
    echo "SLICE_SWAPMAX_BYTES=$(systemctl show zchain-recursion.slice -p MemorySwapMax --value)"
    echo "IO_WEIGHT=$(systemctl show zchain-recursion.slice -p IOWeight --value)"
    echo "CPU_WEIGHT=$(systemctl show zchain-recursion.slice -p CPUWeight --value)"
    echo "PROVER_UNIT=texas-prover-monad.service"
  } > "$OPT/deploy-state.env"
  echo "created deploy-state.env"
else
  echo "deploy-state.env exists, keep"
fi
cat "$OPT/deploy-state.env"

echo "== 9. 验证 =="
systemctl show zchain-recursion.slice -p MemoryMax -p MemoryHigh -p MemorySwapMax -p CPUQuotaPerSecUSec -p CPUWeight -p IOWeight
systemctl show texas-prover-monad.service -p Nice -p Slice -p MemoryMax -p MemorySwapMax
systemctl is-active zchain-recursion.slice zchain-monad-disk-guard.timer texas.service
"$SBIN/zchain-monad-disk-guard.sh" --dry-run && echo "guard dry-run OK"
echo "== INSTALL DONE =="
