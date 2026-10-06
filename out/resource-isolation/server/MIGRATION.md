# zchain-monad 节点单元迁移到隔离挂载点 —— 操作说明（本轮不执行、不启用）

服务器：stark（8.218.68.215，Linux x86_64）
日期：2026-09-29
纪律：**只增不删**；生产 `texas.service` 全程不受影响；所有步骤可回退。

## 0. 背景

- 9-28 决策：4 节点链单元全部 `stop + disable`（恢复路径已另行交接）。
- 本轮新建磁盘隔离：固定大小 ext4 回环镜像挂载于 `/opt/zchain-monad/chain-data`，
  镜像写满只会在挂载点内 ENOSPC，**不伤系统盘**（详见 `df -P /opt/zchain-monad/chain-data`）。
- 本说明描述如何把节点数据目录迁入该挂载点，**本文档本身不触发任何迁移**。

## 1. 前提核对（迁移前逐项确认）

```bash
systemctl list-unit-files | grep -E 'monad|zchain|node'   # 确认单元名与 enabled/disabled 状态
systemctl is-active <各节点单元>                            # 必须全部 inactive（保持 stop）
findmnt /opt/zchain-monad/chain-data                       # 隔离盘已挂载，fstype=ext4
df -h /opt/zchain-monad/chain-data /                       # 记录迁移前基线
du -sh <当前节点数据目录…>                                  # 源数据总量
```

容量红线：源数据总量 ≤ 镜像容量 × 80%（预留 ext4 元数据 + prover 产物 + 水位守卫余量）。
不满足则**先扩镜像再迁移**（见 §5），不得硬迁。

## 2. 迁移步骤（未来执行时按序）

1. **复制（不删源）**：
   ```bash
   mkdir -p /opt/zchain-monad/chain-data/nodes
   rsync -aH --info=progress2 <节点数据目录>/ /opt/zchain-monad/chain-data/nodes/<角色>/
   ```
   逐节点复制；rsync 中断可重跑（增量）。
2. **校验**：`du -sb` 源/目标对比；抽样文件 `cmp`。差异非零 → 停止，回退（§4）。
3. **单元切换（drop-in，不改原 unit 文件）**：
   ```bash
   systemctl edit <节点单元>@N
   # 写入（示例，按单元实际参数形态替换数据目录项）：
   #   [Service]
   #   Environment=CHAIN_DATA_DIR=/opt/zchain-monad/chain-data/nodes/<角色>
   #   # 若数据目录是 ExecStart 位置参数，则用覆盖式：
   #   # ExecStart=
   #   # ExecStart=<原命令> /opt/zchain-monad/chain-data/nodes/<角色> <其余参数不变>
   systemctl daemon-reload
   ```
4. **灰度**：先 `systemctl start` 单个节点实例，观察 journal 与水位（`df -P /opt/zchain-monad/chain-data`）；
   确认写入落在镜像内（`lsof +D` 或 `find /opt/zchain-monad/chain-data -mmin -5`）后，再逐个起其余节点。
5. **守卫**：确认 `zchain-monad-disk-guard.timer` active；节点单元名已加入
   `/opt/zchain-monad/guard-units.conf` 白名单（守卫超 90% 水位时自动停它们并 logger 告警）。

## 3. prover 产物轮转（防累积）

递归证明产物（证明 ~1MB/批 + 终证 1.5MB 级 + executable 缓存）统一落在
`/opt/zchain-monad/chain-data/prover-work/`，按批轮转：

```bash
# 保留最近 10 批，其余删除（先 -print 预览再 -delete；由运行方按批号约定执行）
find /opt/zchain-monad/chain-data/prover-work -maxdepth 1 -name 'batch-*' -type d | sort | head -n -10
```

prover 服务单元（隔离域内，-monad 后缀）的 work dir 环境变量指向上述目录。

## 4. 回退路径

- **单元回退**：`systemctl revert <单元>`（删除 drop-in）→ `daemon-reload` → 用原数据目录路径启动
  （源数据从未删除，天然可回退）。
- **挂载回退**（仅在彻底放弃隔离盘时）：
  ```bash
  systemctl stop zchain-monad-disk-guard.timer
  umount /opt/zchain-monad/chain-data
  losetup -d $(losetup -j /opt/zchain-monad/chain-data.img --output NAME --noheadings)
  # 删除 /etc/fstab 中 chain-data.img 行（本轮交付不执行任何删除）
  ```
  注意：镜像文件与其中数据**保留不删**，回退仅解除挂载关联。

## 5. 扩镜像（如需）

ext4 镜像支持在线扩大（只增不删）：
```bash
truncate -s +2G /opt/zchain-monad/chain-data.img   # 在系统盘余量允许时
resize2fs /dev/loopX                                # X=losetup -j 查得
```
扩大前必须满足：`df /` 余量 ≥ 扩大量 + 3G 安全线（同 check 脚本阈值口径）。

## 6. 明确不做的事（本轮）

- 不修改任何节点单元的原 unit 文件；
- 不迁移、不删除任何现有数据；
- 不启用（enable/start）任何节点单元；
- 不给 `texas.service` 加任何 drop-in（MemoryMin=1G 反向兜底为待运维确认项，未动）。
