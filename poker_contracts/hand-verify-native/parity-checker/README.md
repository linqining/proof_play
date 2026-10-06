# parity-checker — 跨端 transcript 一致性验证

用**主项目**的 `poker-protocol-core::stark_curve`（host↔Cairo parity 在主项目
侧钉死的参考实现）对同一组固定输入计算 handbatch 挑战/ρ，输出与
hand-verify-native 的 `cargo run --release -- vectors` 逐字节比对。

- 只读主项目源码（path 依赖），独立 workspace + 独立 target，主项目编译
  不受影响；
- 2026-09-05 比对结果：endorsement / reveal / leave / reconstruct / hand_rho
  五个值逐字节一致（spike 侧为 raw felt，参考侧为 mod n 归约——输出
  < n 时两者相等，本次全部相等）。

```bash
cd hand-verify-native/parity-checker
cargo run --release
# 对照: cd .. && cargo run --release -- vectors
```
