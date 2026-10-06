# C3 笼内复测留档（2026-09-30，K=64 三门禁全绿）

本目录只保留脚本与证据日志；**二进制不入库**（可由下述命令再生成）。

## 留档文件

- `cage-run.sh` —— 服务器侧笼内执行脚本（systemd-run 瞬态单元内跑，含
  memory.current 100ms 轮询采样与 texas 漂移探针；结尾 `exit $rc` 传播成败）。
- `runner.sh` —— 本机侧编排（DPI 放行窗口轮询 + ControlMaster 复用；
  `push`/`collect` 两阶段，服务端进程脱离 SSH 独立运行）。
- `result-k64.log` —— K=64 收证全量输出（verdict + t7 日志 + journal）。
- `push_start.log` —— 推送轮 SHA256 双侧核对与起服务记录。

结果：steps 397,415（与本机 T7 逐字一致）、峰值 RSS 3,222 MiB（4600M 单元帽
70%）、texas 漂移 0.00%、oom_kill=0。详见
`out/poker-fold-implementation-report.md` §5.3。

## 二进制再生成（本机交叉编译，musl 静态）

```bash
# 测试二进制（fold_batch_test）
CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=rust-lld \
  cargo build --release -p hand-verify-native --test fold_batch_test \
  --target x86_64-unknown-linux-musl
cp target/x86_64-unknown-linux-musl/release/deps/fold_batch_test-* .

# prove-hand 出证 CLI（93MB，strip 后推送）
cd proving-tool && \
CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=rust-lld \
  cargo build --release --target x86_64-unknown-linux-musl

# 推送包内容（当时形态）：
#   fold_batch_test + prove-hand + cage-run.sh + canonical_small.json
#   （proving-tool/params/canonical_small.json 原文件）+ cairo.tar.gz
#   （tar czf cairo.tar.gz -C poker_contracts/hand-verify-native cairo，
#    服务器侧须解包；corelib 另推 third_party/corelib-2.19.4 到
#    /Users/mac/projects/poker_texas_air/ 镜像路径——prove-hand 编译期
#    烙死的 CARGO_MANIFEST_DIR 绝对路径）
```

服务器侧留档：`/root/.zmonad-tmp/fold-c3/`（verdict-k64.txt / t7-k64.log /
samples-k64.log）。
