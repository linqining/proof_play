#!/bin/bash
# survey_stark.sh —— 单连接内一次抓全部署决策所需事实（本地准备，ssh stark 'bash -s' < 本文件）
exec 2>&1
echo "=== 0. identity ==="
id; hostname; date '+%F %T %z'
echo "=== 1. hardware/os ==="
uname -a
nproc
lscpu 2>/dev/null | grep -E '^CPU\(s\)|Model name|^Thread|^Core'
systemd --version | head -1
stat -fc %T /sys/fs/cgroup
echo "=== 2. memory/swap ==="
free -m
swapon --show || echo "NO_SWAP"
cat /proc/sys/vm/overcommit_memory 2>/dev/null
echo "=== 3. disk ==="
df -h /
df -h /opt 2>/dev/null || true
echo "=== 4. texas.service (只读) ==="
systemctl is-active texas.service
systemctl show texas.service -p MainPID -p Slice -p ActiveState -p SubState -p MemoryCurrent -p MemoryMax -p CPUQuotaPerSecUSec -p Nice -p CPUWeight
echo "=== 5. 已有隔离工件: systemd ==="
systemctl list-unit-files --no-pager | grep -Ei 'zchain|monad|guard|recursion' || echo "(no matching unit files)"
systemctl list-units --all --no-pager --no-legend | grep -Ei 'zchain|monad|guard|recursion' || echo "(no matching units)"
for u in zchain-recursion.slice zchain.slice texas-prover-monad.service monad-leaf@.service monad-fold@.service zchain-monad-disk-guard.service zchain-monad-disk-guard.timer; do
  echo "--- systemctl cat $u ---"
  systemctl cat "$u" 2>&1
done
echo "=== 6. 已有隔离工件: cgroup 内核视图 ==="
ls /sys/fs/cgroup/ | head -50
for f in /sys/fs/cgroup/zchain.slice/memory.max /sys/fs/cgroup/zchain.slice/zchain-recursion.slice/cpu.max /sys/fs/cgroup/zchain.slice/zchain-recursion.slice/memory.max /sys/fs/cgroup/zchain.slice/zchain-recursion.slice/memory.high /sys/fs/cgroup/zchain.slice/zchain-recursion.slice/memory.swap.max /sys/fs/cgroup/zchain.slice/zchain-recursion.slice/io.weight /sys/fs/cgroup/zchain.slice/zchain-recursion.slice/cpu.weight; do
  printf '%s = ' "$f"; cat "$f" 2>&1 || true
done
echo "=== 7. 磁盘隔离现状 ==="
ls -la /opt/ 2>&1
ls -la /opt/zchain-monad/ 2>&1
findmnt --target /opt/zchain-monad/chain-data 2>&1 || echo "(chain-data 未挂载)"
losetup -a 2>&1
losetup -f 2>&1 || true
echo "--- fstab ---"
grep -n "chain-data\|loop" /etc/fstab 2>&1 || echo "(fstab 无相关条目)"
echo "=== 8. 守卫现状 ==="
ls -la /usr/local/sbin/ 2>&1 | head -10
systemctl is-active zchain-monad-disk-guard.timer 2>&1 || true
cat /opt/zchain-monad/guard-units.conf 2>&1 || true
cat /opt/zchain-monad/deploy-state.env 2>&1 || true
ls -la /opt/zchain-monad/bin/ 2>&1 || true
echo "=== 9. 节点单元与数据目录候选 ==="
systemctl list-unit-files --no-pager | grep -Ei 'node|poker|chain' || echo "(none)"
du -sh /opt/* /root/* 2>/dev/null | sort -rh | head -15
echo "=== 10. 尾部复核 texas ==="
systemctl is-active texas.service
systemctl show texas.service -p MemoryCurrent --value
echo "=== SURVEY DONE ==="
