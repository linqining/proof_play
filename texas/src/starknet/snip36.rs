//! SNIP-36 协议内证明验证的链下侧管线（#2 证明管线切换 + #4 提交工具）。
//!
//! 两笔交易模式（对齐 starkware-libs/starknet-privacy 参考实现）：
//! 1. **create_proof 交易**：调结算合约 `emit_settlement_proof_message`
//!    发出 `to=0、payload=segment` 的 L2→L1 消息；该交易不广播，而是经
//!    自托管 prover（`starknet_transaction_prover`，SNIP-36 的
//!    `starknet_proveTransaction` JSON-RPC）对参考区块状态虚拟执行后产出
//!    证明 + proof_facts；
//! 2. **proved 结算交易**：调 `verify_and_settle_dapv_stark_private_v3`
//!    （calldata 与 v2 同形），tx 携带 `proof`（uint32 数组）与
//!    `proof_facts`（felt252 数组）扩展字段上链，合约读
//!    `get_execution_info_v3_syscall().tx_info.proof_facts` 做绑定断言。
//!
//! starknet-rs 0.17 的账户抽象尚不支持这两个扩展字段，因此本模块手工：
//! - 复刻 sequencer `starknet_api::transaction_hash` 的 Invoke V3 Poseidon
//!   哈希链，并在**链尾**追加 `poseidon(proof_facts)`（仅当非空——官方
//!   主网向量在本模块测试中逐位对拍：`0x1d47…2219`（无 facts）/`0x6d88…726`
//!   （有 facts））；
//! - 用 reqwest 直发 `add_invoke_transaction` 原始 JSON。
//!
//! 权威来源：
//! - sequencer `crates/starknet_api/src/transaction_hash.rs`（哈希链）
//! - sequencer `crates/starknet_transaction_prover`（README：字段约束/错误码）
//! - starknet-privacy `packages/privacy/src/utils.cairo`（消息哈希公式）

use starknet::core::types::Felt;
use starknet_crypto::PoseidonHasher;

/// Invoke V3 交易前缀（Cairo 字符串 "invoke"，小写——starknet-rs
/// PREFIX_INVOKE 同值）。`from_hex_unchecked` 为 const，字面量由官方
/// 主网向量测试逐位对拍覆盖（tests::official_vector_*）。
const PREFIX_INVOKE: Felt = Felt::from_hex_unchecked("0x696e766f6b65");
/// 交易版本 0x3。
const VERSION_THREE: Felt = Felt::THREE;

/// SNIP-36 证明服务的 RPC 错误码（sequencer README 口径）。
pub const ERR_BLOCK_NOT_FOUND: i64 = 24;
pub const ERR_ACCOUNT_VALIDATION_FAILED: i64 = 55;
pub const ERR_UNSUPPORTED_VERSION: i64 = 61;
pub const ERR_INVALID_INPUT: i64 = 1000;
pub const ERR_SERVICE_BUSY: i64 = -32005;

/// 资源上限的 JSON 键集合变体——决定哈希链里的资源 felts 数量：
/// sequencer 侧 `ValidResourceBounds::L1Gas`（只有 L1_GAS+L2_GAS，官方
/// 主网向量即此形态）vs `AllResources`（三资源，starknet-rs execute_v3
/// 构造的交易均为此形态）。两者哈希不同，必须与实际广播的 JSON 一致。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoundsVariant {
    L1GasOnly,
    AllResources,
}

/// 一笔（待）携带 SNIP-36 证明扩展字段的原始 Invoke V3 交易。
#[derive(Debug, Clone)]
pub struct ProvedInvokeV3 {
    pub sender_address: Felt,
    pub calldata: Vec<Felt>,
    pub nonce: Felt,
    /// 证明服务输入校验要求 tip 与所有 max_price_per_unit 为 0（证明在
    /// 客户端侧完成、不收费）；l2_gas.max_amount 非 0（= OS 执行 gas 上限，
    /// 0x5f5e100 ≈ 100 万 Cairo 步）。
    pub tip: u64,
    pub l1_gas: (u64, u128),
    pub l1_data_gas: (u64, u128),
    pub l2_gas: (u64, u128),
    pub bounds_variant: BoundsVariant,
    /// prover 返回的 base64 证明（SNIP-36：`proof` 字段以 uint32 数组上
    /// 行，经 [`proof_base64_to_u32_words`] 转换）。
    pub proof_base64: Option<String>,
    /// prover 返回的 proof_facts（felt252 hex）。非空时参与 tx hash。
    pub proof_facts: Vec<Felt>,
}

/// `starknet_proveTransaction` 的返回（sequencer README：proof 为 base64，
/// proof_facts 为 felt 数组，另有本次虚拟执行发出的 L2→L1 消息）。
#[derive(Debug, Clone)]
pub struct ProveOutput {
    pub proof_base64: String,
    pub proof_facts: Vec<Felt>,
    pub l2_to_l1_messages: Vec<Vec<Felt>>,
}

/// Felt → JSON-RPC 十六进制标量（"0x…" 小写规范形）。
fn felt_hex(f: &Felt) -> String {
    format!("{f:#x}")
}

/// 资源 concat felt：`[0 | 资源名(56bit, 大端 ASCII) | max_amount(64bit) |
/// max_price_per_unit(128bit)]`（SNIP-8；与 sequencer get_concat_resource、
/// starknet-rs resource_buffer 逐位一致）。
fn concat_resource(name: &[u8; 7], max_amount: u64, max_price: u128) -> Felt {
    let mut buf = [0u8; 32];
    // 1 字节零 + 7 字节资源名 = 8 字节头（"L1_GAS\0" 右填充 / "L1_DATA" 全用）。
    buf[1..8].copy_from_slice(name);
    buf[8..16].copy_from_slice(&max_amount.to_be_bytes());
    buf[16..32].copy_from_slice(&max_price.to_be_bytes());
    Felt::from_bytes_be(&buf)
}

/// 资源名 7 字节形态（SNIP-8：右对齐——短名前导补零，`0x…4c315f474153`
/// = "L1_GAS"）。首字节由 [`concat_resource` 的 buf[0]] 恒置零。
const L1_GAS_NAME: &[u8; 7] = b"\0L1_GAS";
const L2_GAS_NAME: &[u8; 7] = b"\0L2_GAS";
const L1_DATA_NAME: &[u8; 7] = b"L1_DATA";

impl ProvedInvokeV3 {
    /// 复刻 `get_invoke_transaction_v3_hash`（starknet_api）：Poseidon 哈希
    /// 链，proof_facts 非空时链尾追加 `poseidon(proof_facts)`。SNIP-36
    /// 原文："If they don't exist, the tx hash will not include them in
    /// the calculation."（无查询变体——我们永远广播真实交易。）
    pub fn transaction_hash(&self, chain_id: Felt) -> Felt {
        // tip + 资源上限子哈希
        let mut fee = PoseidonHasher::new();
        fee.update(Felt::from(self.tip));
        fee.update(concat_resource(L1_GAS_NAME, self.l1_gas.0, self.l1_gas.1));
        fee.update(concat_resource(L2_GAS_NAME, self.l2_gas.0, self.l2_gas.1));
        if self.bounds_variant == BoundsVariant::AllResources {
            fee.update(concat_resource(
                L1_DATA_NAME,
                self.l1_data_gas.0,
                self.l1_data_gas.1,
            ));
        }
        // paymaster_data / account_deployment_data 恒为空（OZ 账户 + 无代付）
        let empty_hash = PoseidonHasher::new().finalize();
        let mut calldata = PoseidonHasher::new();
        for f in &self.calldata {
            calldata.update(*f);
        }
        let mut h = PoseidonHasher::new();
        h.update(PREFIX_INVOKE);
        h.update(VERSION_THREE);
        h.update(self.sender_address);
        h.update(fee.finalize());
        h.update(empty_hash);
        h.update(chain_id);
        h.update(self.nonce);
        // nonce/fee DA 模式恒 L1（starknet-rs 硬编码同值）
        h.update(Felt::ZERO);
        h.update(empty_hash);
        h.update(calldata.finalize());
        if !self.proof_facts.is_empty() {
            let mut pf = PoseidonHasher::new();
            for f in &self.proof_facts {
                pf.update(*f);
            }
            h.update(pf.finalize());
        }
        h.finalize()
    }

    /// 广播 JSON（starknet JSON-RPC 0.10 `add_invoke_transaction` 入参，
    /// 含 SNIP-36 的 `proof`/`proof_facts` 扩展字段）。`signature` 为账户
    /// 对 [`Self::transaction_hash`] 的 ECDSA (r, s)。
    pub fn to_broadcast_json(&self, signature: [Felt; 2]) -> serde_json::Value {
        let mut v = serde_json::json!({
            "type": "INVOKE",
            "sender_address": felt_hex(&self.sender_address),
            "calldata": self.calldata.iter().map(felt_hex).collect::<Vec<_>>(),
            "signature": [felt_hex(&signature[0]), felt_hex(&signature[1])],
            "nonce": felt_hex(&self.nonce),
            "tip": format!("{:#x}", self.tip),
            "resource_bounds": {
                // 键必须小写：节点 add_invoke_transaction 与 transaction-prover
                // 的 serde 都按 RPC 规范小写解析（大写 L1_GAS 会报
                // "missing field l1_gas"——2026-09-19 主网实测）。
                "l1_gas": {
                    "max_amount": format!("{:#x}", self.l1_gas.0),
                    "max_price_per_unit": format!("{:#x}", self.l1_gas.1),
                },
                "l1_data_gas": {
                    "max_amount": format!("{:#x}", self.l1_data_gas.0),
                    "max_price_per_unit": format!("{:#x}", self.l1_data_gas.1),
                },
                "l2_gas": {
                    "max_amount": format!("{:#x}", self.l2_gas.0),
                    "max_price_per_unit": format!("{:#x}", self.l2_gas.1),
                },
            },
            "paymaster_data": [],
            "account_deployment_data": [],
            "nonce_data_availability_mode": "L1",
            "fee_data_availability_mode": "L1",
            "version": "0x3",
        });
        if let Some(b64) = &self.proof_base64 {
            v["proof"] = serde_json::json!(
                proof_base64_to_u32_words(b64)
                    .expect("proof base64 must decode (prover output)")
            );
            v["proof_facts"] = serde_json::json!(
                self.proof_facts.iter().map(felt_hex).collect::<Vec<_>>()
            );
        }
        v
    }

    /// 从 [`ProveOutput`] 组装 proved 结算交易（证明 + facts 就位）。
    pub fn from_prove_output(
        mut base: ProvedInvokeV3,
        output: ProveOutput,
    ) -> Self {
        base.proof_base64 = Some(output.proof_base64);
        base.proof_facts = output.proof_facts;
        base
    }
}

/// prover 的 base64 证明 → SNIP-36 `proof` 字段的 uint32 数组（小端序
/// 每 4 字节一词；尾部不足 4 字节按零填充——注意：字节序与填充规则以
/// sequencer 反序列化实现为最终依据，sepolia 首次真实提交前应对拍）。
pub fn proof_base64_to_u32_words(b64: &str) -> Result<Vec<u32>, String> {
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|e| format!("snip36: proof base64 decode: {e}"))?;
    Ok(bytes
        .chunks(4)
        .map(|c| {
            let mut w = [0u8; 4];
            w[..c.len()].copy_from_slice(c);
            u32::from_le_bytes(w)
        })
        .collect())
}

/// 自托管证明服务客户端（`starknet_transaction_prover` 容器）。
///
/// 部署：`docker run --rm -p 3000:3000 -e RPC_URL=https://<v0.10 节点>
/// ghcr.io/starkware-libs/starknet-privacy/transaction-prover`。
/// 服务**无鉴权**——必须放在内网或反向代理之后。
pub struct Snip36ProverClient {
    endpoint: String,
    http: reqwest::Client,
}

impl Snip36ProverClient {
    pub fn new(endpoint: impl Into<String>) -> Self {
        // 虚拟执行出证实测 ≈2 分钟/笔：显式放宽整体超时到 10 分钟
        // （悬挂兜底），连接阶段 30 秒快速失败。
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(600))
            .connect_timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("reqwest client");
        Self { endpoint: endpoint.into(), http }
    }

    /// 对参考区块虚拟执行 `invoke` 并产出证明。
    ///
    /// `block_id`：`"latest"` 或 `{"block_number": N}` / `{"block_hash": "0x…"}`
    /// （仅已 finalization 的区块）。错误码映射见模块级常量。
    pub async fn prove_transaction(
        &self,
        block_id: serde_json::Value,
        invoke: &serde_json::Value,
    ) -> Result<ProveOutput, String> {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "starknet_proveTransaction",
            "params": [block_id, invoke],
        });
        let resp = self
            .http
            .post(&self.endpoint)
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("snip36 prover request: {e}"))?;
        let status = resp.status();
        let doc: serde_json::Value =
            resp.json().await.map_err(|e| format!("snip36 prover body: {e}"))?;
        if let Some(err) = doc.get("error") {
            let code = err.get("code").and_then(|c| c.as_i64()).unwrap_or(-32603);
            let message = err.get("message").and_then(|m| m.as_str()).unwrap_or("");
            return Err(match code {
                ERR_BLOCK_NOT_FOUND => format!("prover: block not found ({message})"),
                ERR_ACCOUNT_VALIDATION_FAILED => {
                    format!("prover: account validation failed ({message})")
                }
                ERR_UNSUPPORTED_VERSION => format!("prover: unsupported version ({message})"),
                ERR_INVALID_INPUT => format!("prover: invalid input ({message})"),
                ERR_SERVICE_BUSY => format!("prover: service busy, retry later ({message})"),
                _ => format!("prover: rpc error {code}: {message}"),
            });
        }
        if !status.is_success() {
            return Err(format!("prover: http {status}"));
        }
        let result = doc
            .get("result")
            .ok_or_else(|| format!("prover: missing result: {doc}"))?;
        let proof_base64 = result
            .get("proof")
            .and_then(|p| p.as_str())
            .ok_or("prover: missing result.proof")?
            .to_string();
        let proof_facts = result
            .get("proof_facts")
            .and_then(|p| p.as_array())
            .ok_or("prover: missing result.proof_facts")?
            .iter()
            .map(|f| {
                let s = f
                    .as_str()
                    .ok_or_else(|| "prover: proof_facts element not a string".to_string())?;
                Felt::from_hex(s).map_err(|e| format!("prover: bad felt {s}: {e:?}"))
            })
            .collect::<Result<Vec<_>, String>>()?;
        let l2_to_l1_messages = result
            .get("l2_to_l1_messages")
            .and_then(|p| p.as_array())
            .map(|msgs| {
                msgs.iter()
                    .map(|m| {
                        m.as_array()
                            .map(|felts| {
                                felts
                                    .iter()
                                    .filter_map(|f| f.as_str().and_then(|s| Felt::from_hex(s).ok()))
                                    .collect()
                            })
                            .unwrap_or_default()
                    })
                    .collect()
            })
            .unwrap_or_default();
        Ok(ProveOutput { proof_base64, proof_facts, l2_to_l1_messages })
    }
}

// ============================================================
// 测试：官方主网向量对拍（sequencer transaction_hash.json，同笔交易
// 带/不带 proof_facts 的 hash 对）+ base64 转换 + prover 客户端 mock。
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    const SN_MAIN: Felt = Felt::from_hex_unchecked("0x534e5f4d41494e");

    /// 官方向量公共字段（sequencer `crates/starknet_api/resources/
    /// transaction_hash.json` 条目 2/3，主网区块 636864）。
    fn vector_tx(proof_facts: Vec<Felt>) -> ProvedInvokeV3 {
        ProvedInvokeV3 {
            sender_address: Felt::from_hex(
                "0x69c0f9bcd79697bdceaf7748e3ff8f34aa39e4063ce44896af664c0c96f6c10",
            )
            .unwrap(),
            calldata: [
                "0x1",
                "0x4c0a5193d58f74fbace4b74dcf65481e734ed1714121bdc571da345540efa05",
                "0x3943907ef0ef6f9d2e2408b05e520a66daaf74293dbf665e5a20b117676170e",
                "0x2",
                "0x49d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7",
                "0x16345785d8a0000",
            ]
            .iter()
            .map(|s| Felt::from_hex(s).unwrap())
            .collect(),
            nonce: Felt::from_hex("0x9d").unwrap(),
            tip: 0,
            l1_gas: (0xa9e, 0x7f2a1ad4f2f1),
            // 官方向量为 L1Gas 变体（无 L1_DATA_GAS 键）
            l1_data_gas: (0, 0),
            l2_gas: (0, 0),
            bounds_variant: BoundsVariant::L1GasOnly,
            proof_base64: None,
            proof_facts,
        }
    }

    #[test]
    fn official_vector_without_proof_facts() {
        // 主网实收交易：hash = 0x1d4735f4…（sequencer 向量条目 2）
        let tx = vector_tx(vec![]);
        assert_eq!(
            tx.transaction_hash(SN_MAIN),
            Felt::from_hex("0x1d4735f4ba73a67be2f648d9b21cab3783383b8c229566b46b027c46012219")
                .unwrap()
        );
    }

    #[test]
    fn official_vector_with_proof_facts() {
        // 同一笔交易 + proof_facts [1,2,3]：链尾追加 poseidon(facts) 后
        // hash = 0x6d885b1a…（sequencer 向量条目 3）——SNIP-36 扩展的
        // 权威对拍。
        let tx = vector_tx(vec![Felt::ONE, Felt::TWO, Felt::THREE]);
        assert_eq!(
            tx.transaction_hash(SN_MAIN),
            Felt::from_hex("0x6d885b1a2b7cb7946480c63aa1697888a33e9ccd0b1516f41c41731a1628726")
                .unwrap()
        );
    }

    #[test]
    fn all_resources_variant_changes_hash() {
        // AllResources（三资源，starknet-rs execute_v3 形态）与 L1GasOnly
        // 哈希不同——广播 JSON 必须与 bounds_variant 一致。
        let mut tx = vector_tx(vec![]);
        tx.bounds_variant = BoundsVariant::AllResources;
        assert_ne!(tx.transaction_hash(SN_MAIN), vector_tx(vec![]).transaction_hash(SN_MAIN));
    }

    #[test]
    fn broadcast_json_carries_snip36_fields() {
        let mut tx = vector_tx(vec![Felt::ONE]);
        tx.proof_base64 = Some("AAAAAA==".to_string()); // 3 个零字节 → 1 词
        let v = tx.to_broadcast_json([Felt::ONE, Felt::TWO]);
        assert_eq!(v["type"], "INVOKE");
        assert_eq!(v["version"], "0x3");
        assert_eq!(v["proof"], serde_json::json!([0u32]));
        assert_eq!(v["proof_facts"], serde_json::json!(["0x1"]));
        // 无证明时不得出现扩展字段（普通 V3 交易形态）
        let plain = vector_tx(vec![]).to_broadcast_json([Felt::ONE, Felt::TWO]);
        assert!(plain.get("proof").is_none());
        assert!(plain.get("proof_facts").is_none());
    }

    #[test]
    fn base64_to_u32_words_roundtrip() {
        assert_eq!(proof_base64_to_u32_words("AAAAAA==").unwrap(), vec![0u32]);
        assert_eq!(proof_base64_to_u32_words("AQIDBA==").unwrap(), vec![0x04030201]);
        // 3 字节 → 1 词（尾部零填充）；4 字节 → 1 词。
        assert_eq!(proof_base64_to_u32_words("Aw==").unwrap(), vec![3u32]);
        assert!(proof_base64_to_u32_words("!!!").is_err());
    }

    /// prover 客户端对 mock JSON-RPC 服务的端到端（成功 + 错误码映射）。
    #[tokio::test]
    async fn prover_client_happy_and_error_paths() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        // 应答序列：1 次成功、1 次 service-busy。
        tokio::spawn(async move {
            for _ in 0..2 {
                let (mut sock, _) = listener.accept().await.unwrap();
                let mut buf = vec![0u8; 8192];
                let n = sock.read(&mut buf).await.unwrap();
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let body = if req.contains("busy_block") {
                    serde_json::json!({"jsonrpc":"2.0","id":1,"error":{"code":-32005,"message":"queue full"}})
                } else if req.contains("starknet_proveTransaction") {
                    serde_json::json!({"jsonrpc":"2.0","id":1,"result":{
                        "proof":"AQIDBA==",
                        "proof_facts":["0x1","0x2","0x3"],
                        "l2_to_l1_messages":[["0xdead"]]
                    }})
                } else {
                    serde_json::json!({"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"no method"}})
                };
                let payload = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.to_string().len(),
                    body
                );
                sock.write_all(payload.as_bytes()).await.unwrap();
            }
        });
        let client = Snip36ProverClient::new(format!("http://{addr}/"));
        let invoke = serde_json::json!({"type": "INVOKE", "version": "0x3"});

        let ok = client
            .prove_transaction(serde_json::json!({"block_number": 636864}), &invoke)
            .await
            .expect("mock prove ok");
        assert_eq!(ok.proof_base64, "AQIDBA==");
        assert_eq!(ok.proof_facts, vec![Felt::ONE, Felt::TWO, Felt::THREE]);
        assert_eq!(ok.l2_to_l1_messages, vec![vec![Felt::from_hex("0xdead").unwrap()]]);

        let busy = client
            .prove_transaction(serde_json::json!({"block_name": "busy_block"}), &invoke)
            .await
            .unwrap_err();
        assert!(busy.contains("service busy"), "busy mapping, got: {busy}");
    }
}
