#!/bin/bash
# detail_fetch.sh —— 阶段2：单连接只读详查（零写入），补齐门禁裁决所需证据
exec 2>&1
echo "=== A. 部署的守卫脚本全文 ==="
cat /usr/local/sbin/zchain-monad-disk-guard.sh
echo "=== B. 守卫 dry-run 实测 ==="
/usr/local/sbin/zchain-monad-disk-guard.sh --dry-run; echo "guard_dryrun_exit=$?"
echo "=== C. 守卫实跑证据（journal 最近 6 小时）==="
journalctl -u zchain-monad-disk-guard.service --since "-6h" --no-pager 2>/dev/null | tail -12
echo "=== D. 迁移文档 ==="
ls -la /opt/zchain-monad/docs/ 2>&1
echo "--- node-unit-migration.md ---"
cat /opt/zchain-monad/docs/node-unit-migration.md 2>&1
echo "=== E. 探针残留说明 ==="
cat /usr/local/sbin/zmonad-memhog.sh 2>&1
systemctl show zmonad-cage-probe.scope -p Result -p ExecMainStatus -p ActiveState 2>&1
systemctl show monad-leaf@probe1 -p Result -p ExecMainStatus 2>&1
systemctl show monad-fold@probe1 -p Result -p ExecMainStatus 2>&1
echo "=== F. 节点单元现状（迁移说明的对象）==="
systemctl cat zchain-monad-node@.service 2>&1 | head -40
systemctl is-enabled zchain-monad-node@1 zchain-monad-node@2 2>&1 || true
echo "=== G. 系统盘与镜像内用量 ==="
df -Pm / /opt/zchain-monad/chain-data
echo "=== H. texas 终态 ==="
systemctl is-active texas.service
systemctl show texas.service -p MemoryCurrent --value
echo "=== DETAIL DONE ==="
