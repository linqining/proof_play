# 多桌形状笼内复测留档（2026-09-30，四场景三门禁全绿）

本目录只保留脚本与证据；**二进制不入库**（再生成命令见下）。

## 留档文件

- `cage-run-mt.sh` —— 服务器侧单场景笼内脚本（参数：name / test_filter / 可选
  FOLD_PERF_ONLY 值；独立 systemd 单元内执行，100ms 采样 + texas 探针，
  结尾 `exit $rc`）。
- `run-mt-all.sh` —— 服务器侧驱动：四场景顺序入笼（k64 / mt8 / mt2a / mt2b），
  完成后写 ALL_DONE 标记。
- `result-all.txt` —— 四场景 verdict 全文 + 采样首尾存档。

结果：四场景 steps 与本机逐字一致（k64 398,146 / mt8 409,563 / mt2a 98,685 /
mt2b 52,885）；最坏多桌形状（T=8×8 人 ΣK=64）峰值 3,221 MiB（4600M 单元帽
70%，与单桌 K=64 的 3,224 MiB 基本重合）；四场景 oom=0、texas 漂移 0.00%。
详见 `out/fold-multitable-implementation-report.md` §6.1。

## 二进制再生成（本机交叉编译，musl 静态）

```bash
CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=rust-lld \
  cargo build --release -p hand-verify-native --test fold_batch_test \
  --target x86_64-unknown-linux-musl
cp target/x86_64-unknown-linux-musl/release/deps/fold_batch_test-* .

cd proving-tool && \
CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=rust-lld \
  cargo build --release --target x86_64-unknown-linux-musl

# cairo 源包：tar czf cairo.tar.gz -C poker_contracts/hand-verify-native cairo
# 推送目标：/root/.zmonad-tmp/fold-mt/（解包 cairo.tar.gz；corelib 与
# canonical_small.json 在服务器 /Users/mac/... 镜像路径已就位，见 c3-cage-retest/README）
```

服务器侧留档：`/root/.zmonad-tmp/fold-mt/`（verdict/log/samples ×4；二进制已清理）。
