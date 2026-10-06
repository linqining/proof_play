# 合约开发者指南（vm-common）

> **目的**：为 zchain 合约开发者提供单一入口，说明如何使用 vm-common 提供的预编译目录、gas 策略、syscall ID 与 crypto 接口。
>
> **目标读者**：在 poker_l1 或 poker_zkvm 上开发合约的工程师。
>
> **关联文档**：
> - vm-common 架构文档：`vm-common/ARCHITECTURE.md`
> - 仓库架构总览：`docs/00-architecture-overview.md`
> - 既有合约开发指南：`docs/37-2-contract-development.md`

---

## 1. 快速入门

### 1.1 我应该用哪个 VM？

| 场景 | VM | gas | 说明 |
| --- | --- | --- | --- |
| **游戏回合** | poker_l1 | **免 gas** | GameTurn 通道，由买入锁仓反滥用 |
| **检查点锚定** | poker_l1 | **免 gas** | CheckpointAnchor，Game 通道 |
| **签到** | poker_l1 | 正常计费 | Public 通道，`checkin` 预编译 |
| **普通业务合约** | poker_l1 | 正常计费 | settle/forfeit/revert 等 |
| **ZK 证明验证** | 两个 VM | 视场景 | L1 用 `zk_verify` 预编译；zkvm 内部用 CCS 约束 |
| **链下 ZK 电路** | poker_zkvm | 无 gas | 仅 step_limit 约束 |

### 1.2 如何查询预编译可用性？

```rust
use vm_common::catalog::{PrecompileCatalog, PrecompileCategory};

let catalog = PrecompileCatalog::default_catalog();

// 查找特定预编译
if let Some(entry) = catalog.find("sha256") {
    println!("sha256: L1={}, zkvm={}, gas_free={}",
        entry.l1_available, entry.zkvm_available, entry.is_gas_free);
}

// 列出所有跨 VM 可用的预编译
for entry in catalog.cross_vm_available() {
    println!("跨 VM: {} ({:?})", entry.name, entry.category);
}

// 列出所有 gas-free 预编译（GameTurn/CheckpointAnchor lane）
for entry in catalog.gas_free() {
    println!("gas-free: {} — {}", entry.name, entry.description);
}

// 按类别筛选
for entry in catalog.by_category(PrecompileCategory::Hash) {
    println!("哈希: {}", entry.name);
}
```

---

## 2. 预编译目录完整清单

`PrecompileCatalog::default_catalog()` 包含 28 个条目，分布在 5 个类别：

### 2.1 哈希函数（4 个，全部跨 VM）

| 名称 | L1 | zkvm | gas-free | 描述 |
| --- | --- | --- | --- | --- |
| `sha256` | ✅ | ✅ | ❌ | SHA-256 哈希 |
| `keccak256` | ✅ | ✅ | ❌ | Keccak-256 哈希（Ethereum 风格） |
| `blake2b_256` | ✅ | ✅ | ❌ | Blake2b-256 哈希 |
| `poseidon` | ✅ | ✅ | ❌ | Poseidon 哈希（ZK 友好） |

### 2.2 签名验证（3 个）

| 名称 | L1 | zkvm | gas-free | 描述 |
| --- | --- | --- | --- | --- |
| `ecdsa_secp256k1` | ✅ | ❌ | ❌ | ECDSA secp256k1 签名验证（poker_l1） |
| `ed25519` | ✅ | ✅ | ❌ | Ed25519 签名验证（跨 VM） |
| `ecdsa_verify` | ❌ | ✅ | ❌ | ECDSA 验签电路（zkvm 专用） |

### 2.3 配对 / 椭圆曲线（3 个）

| 名称 | L1 | zkvm | gas-free | 描述 |
| --- | --- | --- | --- | --- |
| `bls12_381_pairing` | ✅ | ❌ | ❌ | BLS12-381 配对检查（poker_l1 blstrs） |
| `bn254_pairing` | ❌ | ✅ | ❌ | BN254 配对检查（zkvm ark-bn254） |
| `bn254_ops` | ❌ | ✅ | ❌ | BN254 椭圆曲线运算（zkvm） |

### 2.4 业务合约（17 个，仅 L1）

| 名称 | gas-free | 描述 |
| --- | --- | --- |
| **`gameturn`** | ✅ | 游戏回合（GameTurn 通道） |
| **`checkpoint_anchor`** | ✅ | 检查点锚定（Game 通道） |
| `force_advance` | ❌ | 强制推进 |
| `force_settle` | ❌ | 强制结算 |
| `force_checkin` | ❌ | 强制签到 |
| `settle` | ❌ | 结算 |
| `revert` | ❌ | 回退 |
| `hand_started` | ❌ | 手牌开始 |
| `ack_protocol` | ❌ | 确认协议 |
| `forfeit` | ❌ | 弃牌 |
| `censor_detection` | ❌ | 审查检测 |
| `delegated_escape` | ❌ | 委托逃生 |
| `force_checkpoint` | ❌ | 强制检查点 |
| `challenge_delta` | ❌ | 挑战增量 |
| `checkpoint_skip` | ❌ | 检查点跳过 |
| `request_da` | ❌ | 请求 DA |
| `checkin` | ❌ | 签到（Public 通道，正常 gas 计费） |

### 2.5 ZK 证明验证（1 个，跨 VM）

| 名称 | L1 | zkvm | gas-free | 描述 |
| --- | --- | --- | --- | --- |
| `zk_verify` | ✅ | ✅ | ❌ | ZK 证明验证（Stwo/Groth16/IPA） |

---

## 3. Gas 策略

### 3.1 两个 GasStrategy 实现

| 策略 | crate | 指令 gas | syscall gas | meter 启用 | tx limit | block limit |
| --- | --- | --- | --- | --- | --- | --- |
| `BpfGasStrategy` | poker_l1 | 1-20（按类别） | 按 `vm_common::gas` | ✅ | 10M | 50M |
| `ZkvmGasStrategy` | poker_zkvm | **0**（全 0） | **0**（全 0） | ❌ | 0 | 0 |

### 3.2 指令分类（InsnCategory）

跨 VM 通用的 9 个类别，不绑定具体 ISA：

```rust
pub enum InsnCategory {
    Arithmetic,    // ADD/SUB/AND/OR/XOR
    Memory,        // LOAD/STORE
    ControlFlow,   // JUMP/BRANCH/CALL
    Shift,         // SHL/SHR/SAR
    Mul,           // MUL/MULH
    Div,           // DIV/REM
    UpperImm,      // LUI/AUIPC
    System,        // ECALL/EBREAK
    Other,
}
```

### 3.3 BPF 指令 gas 表（poker_l1 专有）

| 类别 | gas | 来源 |
| --- | --- | --- |
| Arithmetic / UpperImm / Other | 1 | `gas_table::GAS_ARITHMETIC` |
| Memory | 3 | `gas_table::GAS_MEMORY_BASE` |
| ControlFlow / System | 2 | `gas_table::GAS_BRANCH` |
| Shift | 2 | 估算 |
| Mul | 20 | 估算 |
| Div | 20 | 估算 |

### 3.4 Syscall gas 表（跨 VM 共享，来自 `vm_common::gas`）

| Syscall | gas 计算 |
| --- | --- |
| `ObjectRead` | `10 + 1 * args_len` |
| `ObjectWrite` | `20 + 1 * args_len` |
| `ObjectCreate` | `50 + 2 * args_len` |
| `EmitEvent` | `5 + 1 * args_len` |
| `VerifySignature` | 固定 500 |
| `ZkVerify` | `zk_verify_gas(0)` |
| 其他 | 0（zkvm 全 0） |

### 3.5 Gas-free lane（GameTurn/CheckpointAnchor）

**硬约束**（来自 project_memory）：

- GameTurn 交易必须免 gas；Public 通道交易遵循正常 gas 计费。
- CheckpointAnchor 交易使用 Game tx 通道并免 gas。
- Checkin 交易使用 Public 通道并遵循正常 gas 计费。

在 `PrecompileCatalog` 中，`gameturn` 与 `checkpoint_anchor` 的 `is_gas_free = true`，其余业务合约 `is_gas_free = false`。

---

## 4. Syscall ID 命名空间

`vm_common::syscall_id::SyscallId` 枚举包含 35 个变体，分布在 3 个 ID 区间：

| 区间 | 用途 | 示例 |
| --- | --- | --- |
| `0x01-0x0F` | zkvm 专有（15 个） | `Sha256=0x01`, `EcdsaVerify=0x03`, `Poseidon=0x05` |
| `0x40-0x5F` | poker_l1 专有（11 个） | `ObjectRead=0x40`, `ObjectWrite=0x41`, `VerifySignature=0x45` |
| `0x80-0x8B` | BLS12-381 共享（12 个） | `BlsG1Add=0x80`, `BlsG2Add=0x82`, `BlsPairing=0x88` |

### 4.1 常用方法

```rust
use vm_common::syscall_id::SyscallId;

// 从 u32 构造
let id = SyscallId::from_u32(0x40).expect("ObjectRead");

// 判断归属
assert!(id.is_poker_l1());
assert!(!id.is_zkvm());
assert!(!id.is_shared());
assert!(!id.is_bls12_381());

// 转回 u32
assert_eq!(id.as_u32(), 0x40);

// 遍历所有变体
for sid in SyscallId::all() {
    println!("{}: 0x{:02X}", sid.name(), sid.as_u32());
}
```

---

## 5. Crypto 接口（CryptoProvider）

`vm_common::crypto::CryptoProvider` trait 定义了 18 个字节级 crypto 方法，由两侧分别实现：

| 实现 | crate | 依赖 | 用途 |
| --- | --- | --- | --- |
| `blstrs` 实现 | poker_l1 | `blstrs`, `secp256k1`, `ed25519-dalek` | 链上快速验证 |
| `arkworks` 实现 | poker_zkvm | `ark-bn254`, `ark-bls12-381` | 链下 ZK 电路内验证 |

### 5.1 设计原则

- **字节级接口**：所有方法接受 `&[u8]` 输入、返回 `Vec<u8>` 或 `bool`，避免暴露曲线专有类型（`G1Affine`/`G2Affine` 等）。
- **不在 vm-common 引入 arkworks 或 blstrs**：保持 vm-common 的"无 ISA 语义"原则。
- **跨实现一致性**：通过 `poker_l1/tests/crypto_consistency.rs`（10 个测试）验证两侧对相同输入产生相同结果。

### 5.2 使用示例

```rust
use vm_common::crypto::CryptoProvider;

// 在 poker_l1 中（链上）
let crypto = poker_l1::vm::crypto_blstrs::BlstrsCryptoProvider::new();
let hash = crypto.sha256(b"hello");
assert!(crypto.ecdsa_secp256k1_verify(pubkey, msg, sig));

// 在 poker_zkvm 中（链下）
let crypto = poker_zkvm::crypto::ArkworksCryptoProvider::new();
let hash = crypto.sha256(b"hello");
// 同一接口，不同实现
```

---

## 6. 预编译元数据接口（PrecompileMetadata）

若你要添加新的预编译合约，需实现 `vm_common::precompile::PrecompileMetadata` trait：

```rust
pub trait PrecompileMetadata: Send + Sync {
    fn id_bytes(&self) -> [u8; 32];
    fn name(&self) -> &str;
    fn version(&self) -> u32 { 1 }
    fn supports_selector(&self, _selector: &[u8; 32]) -> bool { true }
    fn is_gas_free(&self) -> bool { false }
}
```

### 6.1 ID 生成

使用 `precompile_id_from_name(name)` 生成稳定 ID：

```rust
use vm_common::precompile::{precompile_id_from_name, PRECOMPILE_PREFIX};

let id = precompile_id_from_name("my_new_precompile");
assert_eq!(id[0], PRECOMPILE_PREFIX); // 0xFF
```

**算法**：SipHash-1-0-3 哈希 → 第 0 字节固定 `0xFF` → 第 1-8 字节为哈希 LE 编码 → 第 9-31 字节为 0。

### 6.2 治理状态（PrecompileStatus）

```rust
pub enum PrecompileStatus {
    Stub,        // 测试网可用，主网受限
    Production,  // 完整功能，主网可用
}
```

新预编译应先以 `Stub` 状态上线，经审计后通过治理升级为 `Production`。

### 6.3 版本管理（PrecompileVersion）

```rust
pub struct PrecompileVersion {
    pub active_version: u32,
    pub pending_version: Option<u32>,
    pub activation_height: Option<u64>,
}
```

升级流程：提议新版本 → 等待 timelock（默认 7200 区块）→ 激活。详见 `poker_l1/src/vm/precompile.rs` 的 `PrecompileRegistry`。

---

## 7. 添加新预编译合约的步骤

### 7.1 在 poker_l1 添加业务合约

1. 在 `poker_l1/src/contracts/` 创建新文件（如 `my_contract.rs`）。
2. 实现 `Precompile` trait（`poker_l1::vm::precompile::Precompile`，含 `call()`）。
3. 在 `poker_l1/src/contracts/mod.rs` 注册模块。
4. 在 `poker_l1/src/contracts/dispatch.rs` 添加方法选择器（若需要方法路由）。
5. 在 `poker_l1/src/vm/precompile.rs` 的 `PrecompileRegistry` 注册新合约。

### 7.2 在 vm-common 更新目录

1. 在 `vm-common/src/catalog.rs` 的 `default_catalog()` 中添加新条目：
   ```rust
   entries.push(CatalogEntry {
       name: "my_contract",
       category: PrecompileCategory::Business,
       l1_available: true,
       zkvm_available: false,
       is_gas_free: false,
       id_bytes: precompile_id_from_name("my_contract"),
       description: "我的新合约",
   });
   ```
2. 更新 `test_catalog_default_not_empty` 中的总数断言（28 → 29）。
3. 运行 `cargo test -p vm-common catalog` 验证。

### 7.3 在 zkvm 添加对应电路（若跨 VM）

1. 在 `poker_zkvm/src/precompiles/` 创建新电路文件。
2. 实现 `PrecompileCircuit`。
3. 通过 `PrecompileCircuitAdapter` 实现 `PrecompileMetadata`。
4. 在 catalog 中将 `zkvm_available` 改为 `true`。

---

## 8. 常见问题

### Q1: 为什么 BPF 的 `GAS_ARITHMETIC=1` 不在 vm-common？

BPF 专有常量（`GAS_ARITHMETIC`、`GAS_MEMORY_BASE`、`GAS_BRANCH`）保留在 `poker_l1/src/vm/gas_table.rs`，因为它们是 ISA 专有的。vm-common 只包含跨 VM 共享的常量（如 `TX_GAS_LIMIT`、`GAS_SECP256K1_VERIFY`）。`BpfGasStrategy` 通过 `use crate::vm::gas_table::{...}` 复用这些常量。

### Q2: 为什么 `PrecompileMetadata` 不含 `call()` 方法？

`call()` 依赖各 VM 专有类型（`ObjectID`/`Address`/`ObjectDb`/`PokerL1Error`），迁入 vm-common 会破坏"vm-common 不含 ISA 语义"原则。完整 `call()` 统一推迟到有具体业务需求时再做。详见 `vm-common/src/precompile.rs` 模块文档。

### Q3: GasStrategy 什么时候接入 executor？

Phase 4 仅形式化，不接入。接入需要修改 `PokerL1Context::new` 的所有调用点（~30 处），并为 GameTurn gas-free lane 增加专门回归测试。这是 Phase 6+ 的工作。

### Q4: 如何查询某个预编译的稳定 ID？

```rust
use vm_common::precompile::precompile_id_from_name;
let id = precompile_id_from_name("gameturn");
// id[0] == 0xFF, id[1..9] 是 SipHash LE 编码
```

或在 catalog 中查询：

```rust
let entry = PrecompileCatalog::default_catalog().find("gameturn").unwrap();
let id = entry.id_bytes;
```

### Q5: 新合约应该免 gas 吗？

**默认不应免 gas**。只有 GameTurn 通道与 CheckpointAnchor（Game 通道）免 gas，这是 spec 硬约束。普通业务合约（settle/forfeit/checkin 等）遵循正常 gas 计费。若新合约属于游戏回合逻辑且由买入锁仓反滥用，可申请免 gas，需通过治理批准。

---

## 9. 参考实现

| 文件 | 说明 |
| --- | --- |
| `vm-common/src/catalog.rs` | PrecompileCatalog 完整实现（28 条目 + 14 测试） |
| `vm-common/src/gas_strategy.rs` | GasStrategy trait + InsnCategory（3 测试） |
| `vm-common/src/precompile.rs` | PrecompileMetadata trait + ID 生成（7 测试） |
| `vm-common/src/syscall_id.rs` | SyscallId 枚举（35 变体 + 35 测试） |
| `vm-common/src/gas.rs` | gas 常量与纯函数 |
| `poker_l1/src/vm/gas_strategy.rs` | BpfGasStrategy 实现（6 测试） |
| `poker_zkvm/src/syscalls/gas_strategy.rs` | ZkvmGasStrategy 实现（6 测试） |
| `poker_l1/tests/gas_strategy_consistency.rs` | 跨 VM GasStrategy 一致性测试（8 测试） |
| `poker_l1/tests/crypto_consistency.rs` | 跨 VM CryptoProvider 一致性测试（10 测试） |
| `poker_l1/src/contracts/` | 17 个业务合约实现 |
| `poker_l1/src/vm/precompile.rs` | PrecompileRegistry（运行时分派） |

---

## 10. 引用

- vm-common 架构文档：`vm-common/ARCHITECTURE.md`
- 仓库架构总览：`docs/00-architecture-overview.md`
- 既有合约开发指南：`docs/37-2-contract-development.md`
- 续作计划：`.trae/documents/vm_unification_phase3_5_continuation.md`