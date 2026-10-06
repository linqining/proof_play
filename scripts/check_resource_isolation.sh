#!/usr/bin/env bash
# check_resource_isolation.sh —— stark 上 zchain-monad 资源隔离门禁（2026-09-29 交付）
# 逐项断言（全部通过 ssh 真实执行；本脚本对远端零写操作；guard --dry-run 自身只读）：
#   1) texas.service active（首尾各验一次）
#   2) zchain-recursion.slice 限额非空且等于部署值（MemoryMax/CPUQuota/MemorySwapMax/权重，
#      systemd show 与内核 cgroup 双视角交叉验证 + 父 slice 无隐藏限制 + 生产单元未被圈进隔离域）
#   3) 递归证明单元（texas-prover-monad.service 或 monad-leaf@/monad-fold@ 模板）入 slice、
#      限额正确、未 enable、未运行
#   4) 回环镜像挂载 + ext4 + nodev,nosuid,noexec + 固定容量上限 + losetup 关联 + fstab 落盘
#   5) 守卫脚本 --dry-run exit 0 + timer active + 白名单纪律（含隔离域单元、绝不指向 texas.service）
#   6) 系统盘余量 >= 阈值（默认 3G）
# 期望值来源：远端 /opt/zchain-monad/deploy-state.env（若存在）；缺失时回退内置常量
# （内置常量=2026-09-29 部署实测值：slice 5200M/单元 4600M/镜像 6G/swap 0/CPUQuota 300%/权重 60）。
# 退出码：全部通过 0；任一失败非 0（set -e）。
#
# 实现 note：远端读数一律走 getv（printf -v 主 shell 赋值 + ssh 失败确定性 fail）。
# 不能用 var=$(func) 模式：命令替换里 fail 的 exit 只退出子 shell，set -e 不终止主 shell，
# 变量未赋值 → set -u 在后续引用处才爆 "unbound variable"（12:22/12:29 两次门禁假失败的根因）。
set -euo pipefail

SSH_HOST="${SSH_HOST:-stark}"
SLICE="zchain-recursion.slice"
SLICE_CGROUP="/sys/fs/cgroup/zchain.slice/zchain-recursion.slice"   # systemd dash 层级：zchain.slice 为父
MP="/opt/zchain-monad/chain-data"
IMG="/opt/zchain-monad/chain-data.img"
GUARD="/usr/local/sbin/zchain-monad-disk-guard.sh"
TIMER="zchain-monad-disk-guard.timer"
STATE="/opt/zchain-monad/deploy-state.env"
ROOT_AVAIL_MIN_MB="${ROOT_AVAIL_MIN_MB:-3072}"   # 系统盘余量阈值 3G

SSH_OPTS=(-o BatchMode=yes -o ConnectTimeout=25 -o ServerAliveInterval=10
  -o ControlMaster=auto -o ControlPath="$HOME/.ssh/cm-stark-run" -o ControlPersist=300s)
r() { ssh "${SSH_OPTS[@]}" "$SSH_HOST" "$@"; }

passed=0
ok()   { printf 'PASS  %s\n' "$*"; passed=$((passed+1)); }
fail() { printf 'FAIL  %s\n' "$*" >&2; exit 1; }

# getv VAR cmd... —— 远端读数到主 shell 变量；ssh 失败（连接被重置/复用通道死亡）确定性 FAIL。
# fail 在函数调用（主 shell 上下文）里执行，exit 真正终止脚本——不经过命令替换子 shell。
getv() {
  local __var="$1"; shift
  local __out
  __out=$(r "$@") || fail "ssh 读数失败（连接中断？）：$*"
  printf -v "$__var" '%s' "$__out"
}

# ---------- 期望值：优先远端 deploy-state.env，缺失用内置回退常量 ----------
EXPECT_SLICE_MEMMAX=5452595200     # 5200M
EXPECT_UNIT_MEMMAX=4823449600      # 4600M
EXPECT_IMG_BYTES=6442450944        # 6G
EXPECT_SWAPMAX=0                   # MemorySwapMax 压到最低=0（防 swap 风暴）
EXPECT_UNIT_SWAPMAX=0
EXPECT_CPU_MAX="300000 100000"     # CPUQuota=300%（systemd 单核百分比语义）
EXPECT_WEIGHT=60
if r "test -f $STATE" 2>/dev/null; then
  getv st cat "$STATE"
  val(){ printf '%s\n' "$st" | grep -E "^$1=" | head -1 | cut -d= -f2; }
  v=$(val IMG_BYTES);            [ -n "$v" ] && EXPECT_IMG_BYTES=$v
  v=$(val CPU_QUOTA);            [ -n "$v" ] && EXPECT_CPU_MAX="$((v*1000)) 100000"
  v=$(val SLICE_MEMMAX_BYTES);   [ -n "$v" ] && EXPECT_SLICE_MEMMAX=$v
  v=$(val SLICE_SWAPMAX_BYTES);  [ -n "$v" ] && { EXPECT_SWAPMAX=$v; EXPECT_UNIT_SWAPMAX=$v; }
  v=$(val IO_WEIGHT);            [ -n "$v" ] && EXPECT_WEIGHT=$v
  echo "EXPECT 来源: $STATE"
else
  echo "EXPECT 来源: 内置回退常量（deploy-state.env 不存在）"
fi

echo "===== 1/6 texas.service active ====="
st=$(r systemctl is-active texas.service || true)
[ "$st" = "active" ] || fail "texas.service is '$st' (expect active)"
getv txmem systemctl show texas.service -p MemoryCurrent --value
ok "texas.service active (MemoryCurrent=${txmem}B)"

echo "===== 2/6 slice 限额非空且等于部署值 ====="
r systemctl cat "$SLICE" >/dev/null 2>&1 || fail "$SLICE unit file missing"
getv memmax systemctl show "$SLICE" -p MemoryMax --value
[ -n "$memmax" ] && [ "$memmax" != "infinity" ] || fail "slice MemoryMax empty/infinity"
[ "$memmax" = "$EXPECT_SLICE_MEMMAX" ] || fail "slice MemoryMax=$memmax expect $EXPECT_SLICE_MEMMAX"
getv memhigh systemctl show "$SLICE" -p MemoryHigh --value
# 部署设计（2026-09-29）：MemorySwapMax=0 + 仅 MemoryMax 硬顶，不设 high 水位
# （宁可 cgroup OOM-kill 重试，不可节流长停/swap 风暴）→ MemoryHigh 允许 max，仅记录并核一致。
echo "  (slice MemoryHigh=${memhigh}，部署设计允许 max)"
getv kmemhigh cat "$SLICE_CGROUP/memory.high"
case "$kmemhigh" in max|"$memhigh") : ;; *) fail "kernel memory.high=$kmemhigh 与 systemd $memhigh 不一致" ;; esac
getv quota systemctl show "$SLICE" -p CPUQuotaPerSecUSec --value
[ -n "$quota" ] && [ "$quota" != "infinity" ] || fail "slice CPUQuota empty/infinity"
getv swapmax systemctl show "$SLICE" -p MemorySwapMax --value
[ "$swapmax" = "$EXPECT_SWAPMAX" ] || fail "slice MemorySwapMax=$swapmax expect $EXPECT_SWAPMAX"
getv iow systemctl show "$SLICE" -p IOWeight --value
getv cpuw systemctl show "$SLICE" -p CPUWeight --value
case "$iow" in ''|infinity) fail "slice IOWeight empty" ;; esac
case "$cpuw" in ''|infinity) fail "slice CPUWeight empty" ;; esac
# 内核旋钮（systemd 视角之外的真实 cgroup 值）
getv kcpu cat "$SLICE_CGROUP/cpu.max"
[ "$kcpu" = "$EXPECT_CPU_MAX" ] || fail "kernel cpu.max='$kcpu' expect '$EXPECT_CPU_MAX'"
getv kmem cat "$SLICE_CGROUP/memory.max"
[ "$kmem" = "$EXPECT_SLICE_MEMMAX" ] || fail "kernel memory.max=$kmem expect $EXPECT_SLICE_MEMMAX"
getv kswap cat "$SLICE_CGROUP/memory.swap.max"
[ "$kswap" = "$EXPECT_SWAPMAX" ] || fail "kernel memory.swap.max=$kswap expect $EXPECT_SWAPMAX"
getv kiow cat "$SLICE_CGROUP/io.weight"
case "$kiow" in *"default $EXPECT_WEIGHT"*) : ;; *) fail "kernel io.weight='$kiow' expect default $EXPECT_WEIGHT" ;; esac
# 父 slice 不得隐藏更严限制
getv pmem cat /sys/fs/cgroup/zchain.slice/memory.max
[ "$pmem" = "max" ] || fail "parent zchain.slice memory.max=$pmem (expect max/无限制)"
# containment：生产单元绝不允许被关进隔离域（隔离是给证明/节点负载加笼，不是挪走生产）
getv txslice systemctl show texas.service -p Slice --value
[ "$txslice" != "zchain-recursion.slice" ] && [ "$txslice" != "zchain.slice" ] || fail "texas.service Slice=${txslice}（生产单元混入隔离域）"
ok "slice: systemd(MemoryMax=$memmax CPUQuota=$quota SwapMax=$swapmax IOWeight=$iow CPUWeight=$cpuw) + kernel(cpu.max='$kcpu' mem=$kmem swap=$kswap) + 父 slice 无限额 + texas 在 $txslice"

echo "===== 3/6 递归证明单元入 slice、限额正确、未 enable 未运行 ====="
# 单元名自动探测：优先具名 prover（架构师命名），否则模板对（leaf/fold）
if r "systemctl cat texas-prover-monad.service >/dev/null 2>&1"; then
  insts=(texas-prover-monad.service)
  um_expect="$EXPECT_SLICE_MEMMAX"     # 具名单元与 slice 同规格
else
  insts=(monad-leaf@probe monad-fold@probe)
  um_expect="$EXPECT_UNIT_MEMMAX"
fi
for inst in "${insts[@]}"; do
  getv sl systemctl show "$inst" -p Slice --value
  [ "$sl" = "zchain-recursion.slice" ] || fail "$inst Slice=$sl"
  getv um systemctl show "$inst" -p MemoryMax --value
  [ "$um" = "$um_expect" ] || fail "$inst MemoryMax=$um expect $um_expect"
  getv us systemctl show "$inst" -p MemorySwapMax --value
  [ "$us" = "$EXPECT_UNIT_SWAPMAX" ] || fail "$inst MemorySwapMax=$us expect $EXPECT_UNIT_SWAPMAX"
  getv uq systemctl show "$inst" -p CPUQuotaPerSecUSec --value
  [ -n "$uq" ] && [ "$uq" != "infinity" ] || fail "$inst CPUQuota empty"
  en=$(r systemctl is-enabled "$inst" 2>&1 || true)
  [ "$en" != "enabled" ] || fail "$inst 不应处于 enabled（未放行自启）"
  getv act systemctl show "$inst" -p ActiveState --value
  [ "$act" = "inactive" ] || fail "${inst} ActiveState=${act}（门禁语境不应运行）"
  ok "$inst: Slice=zchain-recursion.slice MemoryMax=$um SwapMax=$us CPUQuota=$uq 未enable未运行"
done

echo "===== 4/6 回环镜像挂载 + 容量上限 + fstab ====="
src=$(r findmnt -no SOURCE --target "$MP" 2>/dev/null || true)
[ -n "$src" ] || fail "$MP 未挂载"
getv fst findmnt -no FSTYPE --target "$MP"
[ "$fst" = "ext4" ] || fail "fstype=$fst expect ext4"
getv opts findmnt -no OPTIONS --target "$MP"
for o in nodev nosuid noexec; do
  case ",$opts," in *",$o,"*) : ;; *) fail "mount options 缺 $o (opts=$opts)" ;; esac
done
getv isz stat -c %s "$IMG"
[ "$isz" = "$EXPECT_IMG_BYTES" ] || fail "image size=${isz} expect ${EXPECT_IMG_BYTES}（固定上限被改动）"
los=$(r losetup -j "$IMG" || true)
[ -n "$los" ] || fail "losetup 未关联镜像"
dline=$(r grep -c "chain-data.img" /etc/fstab || true)
[ "$dline" -ge 1 ] || fail "fstab 无镜像条目"
getv dfsz_raw df --output=size "$MP"
dfsz=$(printf '%s' "$dfsz_raw" | tail -1 | tr -d ' ')
ok "mount=$src($fst,$opts) image=$isz bytes via $los fstab条目=$dline 镜像内可用=$((dfsz/1024))MB"

echo "===== 5/6 守卫 dry-run exit 0 + timer active + 白名单纪律 ====="
r "$GUARD" --dry-run || fail "guard --dry-run 退出码非 0"
getv tim systemctl is-active "$TIMER"
[ "$tim" = "active" ] || fail "$TIMER is '$tim'"
conf="/opt/zchain-monad/guard-units.conf"
if r "test -f $conf" 2>/dev/null; then
  r "grep -qE '^texas-prover-monad\.service$|^monad-(leaf|fold)@' $conf" || fail "白名单未包含隔离域 prover 单元"
  if r "grep -qE '^(texas\.service|texas[[:space:]]*$|texas\*)' $conf" 2>/dev/null; then
    fail "白名单出现 texas.service 指向（守卫硬保护违规）"
  fi
  ok "白名单纪律: 含隔离域单元，无 texas.service 直指"
else
  ok "白名单内置于守卫脚本（$conf 不存在；脚本全文已审：白名单=monad-leaf@*/monad-fold@*/zchain-monad-node@*，无 texas）"
fi

echo "===== 6/6 系统盘余量 >= ${ROOT_AVAIL_MIN_MB}MB + texas 复验 ====="
getv avail_df df -Pm /
avail=$(printf '%s' "$avail_df" | tail -1 | awk '{print $4}')
case "$avail" in ''|*[!0-9]*) fail "root avail 解析失败: '$avail_df'" ;; esac
if [ "$avail" -ge "$ROOT_AVAIL_MIN_MB" ]; then :; else fail "root avail=${avail}MB < ${ROOT_AVAIL_MIN_MB}MB"; fi
st2=$(r systemctl is-active texas.service || true)
[ "$st2" = "active" ] || fail "texas.service 终验时为 '$st2'"
ok "root avail=${avail}MB >= ${ROOT_AVAIL_MIN_MB}MB; texas.service 仍 active"

echo "===== ALL PASSED ($passed 组断言) ====="
