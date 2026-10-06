//! Starknet 运维工具：declare / deploy / invoke / call。
use clap::{Parser, Subcommand};
use starknet::accounts::{Account, SingleOwnerAccount};
use starknet::contract::ContractFactory;
use starknet::core::types::{Call, Felt};
use starknet::providers::jsonrpc::HttpTransport;
use starknet::providers::{JsonRpcClient, Provider};
use starknet::signers::{LocalWallet, SigningKey};
use std::sync::Arc;

/// 默认 UDC（Universal Deployer Contract）地址：主网原始 UDC（与旧
/// `ContractFactory::new` 行为一致，starknet-contract 0.16 `UdcSelector::Legacy`）。
const DEFAULT_UDC: &str = "0x041a78e741e5af2fec34b695679bc6891742439f7afb8484ecd7766661ad02bf";

#[derive(Parser)]
#[command(name = "snops")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
    #[arg(long)]
    url: String,
    #[arg(long, default_value = "")]
    pk: String,
    #[arg(long, default_value = "")]
    addr: String,
}

#[derive(Subcommand, Clone)]
enum Cmd {
    Declare {
        #[arg(long)] class: String,
        #[arg(long)] compiled: String,
        #[arg(long, default_value = "")] compiled_hash: String,
        /// 跳过链上估算，直接给定资源上限（某些公共 RPC 对 estimateFee
        /// 的请求体大小有限制，大合约会 503）。
        #[arg(long, default_value = "")] l1_gas: String,
        #[arg(long, default_value = "")] l1_data_gas: String,
        #[arg(long, default_value = "")] l2_gas: String,
    },
    Deploy {
        #[arg(long)] class_hash: String,
        #[arg(long, default_value = "")] calldata: String,
        /// UDC（Universal Deployer Contract）地址，须与实际部署/预测地址用同一值。
        #[arg(long, default_value = DEFAULT_UDC)]
        udc: String,
    },
    Invoke {
        #[arg(long)] contract: String,
        #[arg(long)] r#fn: String,
        #[arg(long, default_value = "")] calldata: String,
    },
    Call {
        #[arg(long)] contract: String,
        #[arg(long)] r#fn: String,
        #[arg(long, default_value = "")] calldata: String,
    },
    /// 生成随机账户密钥并计算 OZ 账户地址（不部署、不上链）。
    GenKey,
    /// 计算契约类的 sierra / casm class hash（离线，不连链）。
    ClassHash {
        #[arg(long)] class: String,
        #[arg(long)] compiled: String,
    },
    /// 部署账户（deploy_account 交易；需账户地址已有 STRK 支付费用）。
    DeployAcct {
        #[arg(long, default_value = "0x05b4b537eaa2399e3aa99c4e2e0208ebd6c71bc1467938cd52c798c601e43564")]
        class_hash: String,
    },
    /// SNIP-36 第一步：构造并签名 create_proof 交易（调
    /// `emit_settlement_proof_message` 形态入口，零价字段），送自托管
    /// prover `starknet_proveTransaction` 证明，把 block_id + invoke +
    /// 证明应答落盘（--out）。交易不广播。
    Prove {
        #[arg(long)] contract: String,
        #[arg(long)] r#fn: String,
        #[arg(long, default_value = "")] calldata: String,
        /// 自托管 prover（starknet_transaction_prover 容器）的 JSON-RPC 端点。
        #[arg(long, default_value = "http://127.0.0.1:3000")]
        prover_url: String,
        /// 被证明的参考区块：latest 或十进制块号（仅已 finalization 区块）。
        #[arg(long, default_value = "latest")]
        block_id: String,
        /// l2_gas.max_amount = OS 执行 gas 上限（0x5f5e100 ≈ 100 万 Cairo 步）。
        #[arg(long, default_value = "0x5f5e100")]
        l2_gas: String,
        /// 产物落盘路径（缺省打印 stdout）。
        #[arg(long, default_value = "")]
        out: String,
    },
    /// SNIP-36 第二步：读取 Prove 落盘产物，构造/签名并广播携带
    /// proof/proof_facts 的 Invoke V3（调 verify_and_settle_dapv_…_v3；
    /// 合约读 proof_facts 做绑定断言）。nonce 取链上最新。
    SubmitProof {
        #[arg(long)] contract: String,
        #[arg(long)] r#fn: String,
        #[arg(long, default_value = "")] calldata: String,
        /// Prove 子命令落盘的 JSON（含 block_id/invoke/output）。
        #[arg(long)]
        proof_file: String,
        /// l2_gas.max_amount，须与 Prove 阶段一致。
        #[arg(long, default_value = "0x5f5e100")]
        l2_gas: String,
    },
    /// SNIP-36 对拍（§5 #8）：拉取一笔真实 proved 交易的原始 JSON，打印
    /// proof/proof_facts 字段并逐槽解读（facts[1] variant / facts[2] 虚拟
    /// OS 哈希 / facts[7] 消息数 / facts[8] 消息哈希）——用于冻结合约
    /// 钉扎常量。starknet-rs 0.17 类型无 proof 字段，故直读原始 JSON。
    DumpProofFacts {
        #[arg(long)]
        tx_hash: String,
    },
}

fn felt(s: &str) -> Felt {
    let t = s.trim();
    // 0x 前缀按 hex，其余按十进制（与 starknet 生态工具惯例一致，
    // 避免 "100000000000000000000" 这类十进制金额被当成 hex 解析成 2^80）。
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        Felt::from_hex(hex).expect("felt hex parse")
    } else {
        Felt::from_dec_str(t).expect("felt decimal parse")
    }
}

fn encode_byte_array(s: &str) -> Vec<Felt> {
    let bytes = s.as_bytes();
    let n_full = bytes.len() / 31;
    let rem = &bytes[n_full * 31..];
    let mut out = vec![Felt::from(n_full as u64)];
    for i in 0..n_full {
        out.push(Felt::from_bytes_be(&bytes[i*31..(i+1)*31].try_into().unwrap()));
    }
    if !rem.is_empty() {
        // ByteArray 序列化顺序：pending_word 在前，pending_word_len 在后
        let mut buf = [0u8; 32];
        buf[1..1 + rem.len()].copy_from_slice(rem);
        out.push(Felt::from_bytes_be(&buf));
        out.push(Felt::from(rem.len() as u64));
    } else {
        out.push(Felt::ZERO);
    }
    out
}

fn parse_args_mixed(s: &str) -> Vec<Felt> {
    let t = s.trim();
    if t.is_empty() { return vec![]; }
    let mut out = Vec::new();
    for part in t.split(',') {
        if let Some(rest) = part.strip_prefix("@str:") {
            out.extend(encode_byte_array(rest));
        } else {
            out.push(felt(part));
        }
    }
    out
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli: Cli = Cli::parse();

    // 无网络依赖：生成密钥 + 计算 OZ 账户地址（deployer 0、salt 0）。
    if let Cmd::GenKey = cli.cmd {
        let sk = SigningKey::from_random();
        let pubkey = sk.verifying_key().scalar();
        let oz_class = Felt::from_hex(
            "0x05b4b537eaa2399e3aa99c4e2e0208ebd6c71bc1467938cd52c798c601e43564",
        )?;
        let address = starknet::core::utils::get_contract_address(
            Felt::ZERO,
            oz_class,
            &[pubkey],
            Felt::ZERO,
        );
        println!("PRIVATE_KEY={pk:#x}", pk = sk.secret_scalar());
        println!("PUBLIC_KEY={pubkey:#x}");
        println!("ADDRESS={address:#x}");
        return Ok(());
    }

    let provider = Arc::new(JsonRpcClient::new(HttpTransport::new(
        url::Url::parse(&cli.url)?,
    )));

    // deploy_account：账户尚不存在，不走 SingleOwnerAccount，直接用 factory。
    if let Cmd::DeployAcct { class_hash } = cli.cmd {
        use starknet::accounts::{AccountFactory, OpenZeppelinAccountFactory};
        let factory = OpenZeppelinAccountFactory::new(
            felt(&class_hash),
            provider.chain_id().await?,
            LocalWallet::from_signing_key(SigningKey::from_secret_scalar(felt(&cli.pk))),
            provider.clone(),
        )
        .await?;
        let res = factory.deploy_v3(Felt::ZERO).send().await?;
        println!("ADDRESS={:#x}", res.contract_address);
        println!("TX={:#x}", res.transaction_hash);
        return Ok(());
    }

    // class-hash：纯离线计算，不需要账户。
    if let Cmd::ClassHash { class, compiled } = cli.cmd {
        use starknet::core::types::contract::{CompiledClass, SierraClass};
        let sierra: SierraClass = serde_json::from_reader(std::fs::File::open(&class)?)?;
        let compiled_cls: CompiledClass = serde_json::from_reader(std::fs::File::open(&compiled)?)?;
        println!("SIERRA_CLASS_HASH={:#x}", sierra.class_hash()?);
        println!("CASM_CLASS_HASH={:#x}", compiled_cls.class_hash()?);
        return Ok(());
    }

    let Cmd::Call { contract, r#fn, calldata } = cli.cmd.clone() else {
        let signer = LocalWallet::from_signing_key(SigningKey::from_secret_scalar(felt(&cli.pk)));
        let account = Arc::new(SingleOwnerAccount::new(
            provider.clone(),
            signer,
            felt(&cli.addr),
            provider.chain_id().await?,
            starknet::accounts::ExecutionEncoding::New,
        ));
        match cli.cmd {
            Cmd::Declare { class, compiled, compiled_hash: forced_hash, l1_gas, l1_data_gas, l2_gas } => {
                use starknet::core::types::contract::{CompiledClass, SierraClass};
                let sierra: SierraClass =
                    serde_json::from_reader(std::fs::File::open(&class)?)?;
                let class_hash = sierra.class_hash()?;
                let flattened = sierra.flatten()?;
                let compiled_cls: CompiledClass =
                    serde_json::from_reader(std::fs::File::open(&compiled)?)?;
                let compiled_hash = if forced_hash.is_empty() {
                    compiled_cls.class_hash()?
                } else {
                    Felt::from_hex(&forced_hash)?
                };
                // 显式资源上限（--l*-gas 给出时跳过链上估算）：某些公共 RPC
                // 对 estimateFee 的请求体大小有限制，大合约会直接 503。
                let parse_gas = |s: &str, dflt: u64| -> u64 {
                    if s.is_empty() { dflt } else { felt(s).to_string().parse().unwrap_or(dflt) }
                };
                let manual = !l1_gas.is_empty() || !l2_gas.is_empty();
                // starknet-core 的 casm hash 与 devnet 计算可能有版本差异：
                // 首次提交失败时从错误中提取 Actual hash 重试一次。
                let declare = account.declare_v3(Arc::new(flattened.clone()), compiled_hash);
                let declare = if manual {
                    declare
                        .l1_gas(parse_gas(&l1_gas, 800))
                        .l1_data_gas(parse_gas(&l1_data_gas, 1_000))
                        .l2_gas(parse_gas(&l2_gas, 20_000_000))
                } else {
                    declare
                };
                let res = match declare.send().await {
                    Ok(r) => r,
                    Err(e) if format!("{e:?}").contains("Mismatch compiled class hash") => {
                        // 从嵌套/终态错误文本提取 devnet 计算的 casm hash
                        let text = format!("{e:?}");
                        eprintln!("[snops] mismatch error text: {text}");
                        // devnet 的 "Expected: 0x..." 才是规范 casm hash
                        // （starknet-core 0.16 的计算与 cairo-lang 有版本差异）
                        let actual = text
                            .split("Expected: ")
                            .nth(1)
                            .and_then(|s| s.split_whitespace().next())
                            .map(|s| s.trim_end_matches(|c: char| !c.is_ascii_hexdigit()).to_string())
                            .unwrap_or_default();
                        let actual_hash = Felt::from_hex(&actual)?;
                        account
                            .declare_v3(Arc::new(flattened), actual_hash)
                            .send()
                            .await?
                    }
                    Err(e) => return Err(e.into()),
                };
                println!("CLASS_HASH={class_hash:#x}");
                println!("TX={:#x}", res.transaction_hash);
            }
            Cmd::Deploy { class_hash, calldata, udc } => {
                // 单一 UDC 地址贯穿"实际部署 + 预测地址"两处，避免两处各写一份漂移。
                let udc = Felt::from_hex(&udc)?;
                let factory = ContractFactory::new_with_udc(
                    felt(&class_hash),
                    account,
                    starknet::contract::UdcSelector::Custom(udc),
                );
                let cd = parse_args_mixed(&calldata);
                let salt = Felt::ZERO;
                let res = factory.deploy_v3(cd.clone(), salt, true).send().await?;
                // UDC deploy_v3 默认 unique 模式（deployer 地址参与地址推导）
                let address = starknet::core::utils::get_udc_deployed_address(
                    salt,
                    felt(&class_hash),
                    &starknet::core::utils::UdcUniqueness::Unique(
                        starknet::core::utils::UdcUniqueSettings {
                            deployer_address: felt(&cli.addr),
                            udc_contract_address: udc,
                        },
                    ),
                    &cd,
                );
                println!("CONTRACT_ADDRESS={address:#x}");
                println!("TX={:#x}", res.transaction_hash);
            }
            Cmd::Invoke { contract, r#fn, calldata } => {
                let call = Call {
                    to: felt(&contract),
                    selector: starknet::core::utils::starknet_keccak(r#fn.as_bytes()),
                    calldata: parse_args_mixed(&calldata),
                };
                let res = account.execute_v3(vec![call]).send().await?;
                println!("TX={:#x}", res.transaction_hash);
            }
            Cmd::DeployAcct { class_hash } => {
                use starknet::accounts::{AccountFactory, OpenZeppelinAccountFactory};
                let factory = OpenZeppelinAccountFactory::new(
                    felt(&class_hash),
                    provider.chain_id().await?,
                    LocalWallet::from_signing_key(SigningKey::from_secret_scalar(felt(&cli.pk))),
                    provider.clone(),
                )
                .await?;
                let res = factory.deploy_v3(Felt::ZERO).send().await?;
                println!("ADDRESS={:#x}", res.contract_address);
                println!("TX={:#x}", res.transaction_hash);
            }
            Cmd::Prove { contract, r#fn, calldata, prover_url, block_id, l2_gas, out } => {
                prove_subcommand(
                    &provider, &felt(&cli.pk), &felt(&cli.addr), &calldata,
                    &prover_url, &block_id, &l2_gas, &out,
                )
                .await?;
            }
            Cmd::SubmitProof { contract, r#fn, calldata, proof_file, l2_gas } => {
                submit_proof_subcommand(
                    &provider, &cli.url, &felt(&cli.pk), &felt(&cli.addr),
                    &calldata, &proof_file, &l2_gas,
                )
                .await?;
            }
            Cmd::DumpProofFacts { tx_hash } => {
                dump_proof_facts(&cli.url, &tx_hash).await?;
            }
            Cmd::GenKey | Cmd::Call { .. } | Cmd::ClassHash { .. } => unreachable!(),
        }
        return Ok(());
    };
    let request = starknet::core::types::FunctionCall {
        contract_address: felt(&contract),
        entry_point_selector: starknet::core::utils::starknet_keccak(r#fn.as_bytes()),
        calldata: parse_args_mixed(&calldata),
    };
    let res = provider
        .call(request, starknet::core::types::BlockId::Tag(starknet::core::types::BlockTag::Latest))
        .await?;
    for f in res {
        println!("OUT={f:#x}");
    }
    Ok(())
}

// ============================================================
// SNIP-36（协议内证明验证）：两笔交易管线（#2 管线切换 + #4 提交工具）。
// 1. prove：create_proof 交易（emit_settlement_proof_message 形态，零价、
//    不广播）→ 自托管 prover `starknet_proveTransaction` 证明 → 落盘；
// 2. submit-proof：同一 calldata 的 v3 结算交易 + proof/proof_facts 扩展
//    字段 → 签名（hash 含 proof_facts）→ add_invoke_transaction 广播。
// ============================================================

// texas 无 lib target：snip36 模块文件按路径挂进本 bin 的模块树
// （主 bin 的 src/main.rs 同源编译，单一实现两处复用）。
#[path = "../starknet/snip36.rs"]
mod snip36;

use snip36::{BoundsVariant, ProvedInvokeV3, Snip36ProverClient};

/// create_proof 交易 JSON（零价字段，prover 输入校验要求；签名覆盖其
/// 交易哈希，供虚拟执行中账户 __validate__ 验证）。
async fn build_create_proof_invoke(
    provider: &JsonRpcClient<HttpTransport>,
    pk: &Felt,
    sender: &Felt,
    calldata: Vec<Felt>,
    l2_gas_max: u64,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {    let nonce = provider
        .get_nonce(
            starknet::core::types::BlockId::Tag(starknet::core::types::BlockTag::Latest),
            *sender,
        )
        .await?;
    let tx = ProvedInvokeV3 {
        sender_address: *sender,
        calldata,
        nonce,
        tip: 0,
        l1_gas: (0, 0),
        l1_data_gas: (0, 0),
        l2_gas: (l2_gas_max, 0),
        bounds_variant: BoundsVariant::AllResources,
        proof_base64: None,
        proof_facts: vec![],
    };
    let hash = tx.transaction_hash(provider.chain_id().await?);
    let sig = SigningKey::from_secret_scalar(*pk).sign(&hash)?;
    Ok(tx.to_broadcast_json([sig.r, sig.s]))
}

fn parse_block_id(s: &str) -> serde_json::Value {
    if s.trim() == "latest" {
        serde_json::json!("latest")
    } else {
        serde_json::json!({ "block_number": s.trim().parse::<u64>().expect("block number or latest") })
    }
}

async fn prove_subcommand(
    provider: &JsonRpcClient<HttpTransport>,
    pk: &Felt,
    sender: &Felt,
    calldata: &str,
    prover_url: &str,
    block_id: &str,
    l2_gas: &str,
    out: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let l2_max = u64::try_from(felt(l2_gas)).expect("l2_gas fits u64");
    let invoke = build_create_proof_invoke(provider, pk, sender, parse_args_mixed(calldata), l2_max)
        .await?;
    let block = parse_block_id(block_id);
    let output = Snip36ProverClient::new(prover_url)
        .prove_transaction(block.clone(), &invoke)
        .await
        .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
    let doc = serde_json::json!({
        "block_id": block,
        "invoke": invoke,
        "output": {
            "proof_base64": output.proof_base64,
            "proof_facts": output.proof_facts.iter().map(|f| format!("{f:#x}")).collect::<Vec<_>>(),
            "l2_to_l1_messages": output
                .l2_to_l1_messages
                .iter()
                .map(|m| m.iter().map(|f| format!("{f:#x}")).collect::<Vec<_>>())
                .collect::<Vec<_>>(),
        },
    });
    if out.is_empty() {
        println!("{}", serde_json::to_string_pretty(&doc)?);
    } else {
        std::fs::write(out, serde_json::to_vec_pretty(&doc)?)?;
        println!("PROOF_FILE={out}");
        println!("PROOF_FACTS={}", doc["output"]["proof_facts"].as_array().map(|a| a.len()).unwrap_or(0));
    }
    Ok(())
}

async fn submit_proof_subcommand(
    provider: &JsonRpcClient<HttpTransport>,
    rpc_url: &str,
    pk: &Felt,
    sender: &Felt,
    calldata: &str,
    proof_file: &str,
    l2_gas: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let doc: serde_json::Value =
        serde_json::from_reader(std::fs::File::open(proof_file)?)?;
    let proof_base64 = doc["output"]["proof_base64"]
        .as_str()
        .ok_or("proof file missing output.proof_base64")?
        .to_string();
    let proof_facts = doc["output"]["proof_facts"]
        .as_array()
        .ok_or("proof file missing output.proof_facts")?
        .iter()
        .map(|f| Felt::from_hex(f.as_str().unwrap_or_default()))
        .collect::<Result<Vec<_>, _>>()?;
    let l2_max = u64::try_from(felt(l2_gas)).expect("l2_gas fits u64");
    let nonce = provider
        .get_nonce(
            starknet::core::types::BlockId::Tag(starknet::core::types::BlockTag::Latest),
            *sender,
        )
        .await?;
    let tx = ProvedInvokeV3 {
        sender_address: *sender,
        calldata: parse_args_mixed(calldata),
        nonce,
        tip: 0,
        l1_gas: (0, 0),
        l1_data_gas: (0, 0),
        l2_gas: (l2_max, 0),
        bounds_variant: BoundsVariant::AllResources,
        proof_base64: Some(proof_base64),
        proof_facts,
    };
    let hash = tx.transaction_hash(provider.chain_id().await?);
    let sig = SigningKey::from_secret_scalar(*pk).sign(&hash)?;
    let invoke = tx.to_broadcast_json([sig.r, sig.s]);
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "add_invoke_transaction",
        "params": [invoke],
    });
    let resp = reqwest::Client::new()
        .post(rpc_url)
        .json(&body)
        .send()
        .await?;
    let status = resp.status();
    let reply: serde_json::Value = resp.json().await?;
    if let Some(err) = reply.get("error") {
        return Err(format!("submit failed: {err}").into());
    }
    if !status.is_success() {
        return Err(format!("submit http {status}").into());
    }
    println!(
        "TX={}",
        reply["result"]["transaction_hash"].as_str().unwrap_or_default()
    );
    Ok(())
}

/// SNIP-36 对拍（§5 #8）：`starknet_getTransactionByHash` 原始 JSON 直读
/// （starknet-rs 0.17 类型无 proof 字段），逐槽解读 proof_facts：
///   [1] program variant（应为 "VIRTUAL_SNOS" ASCII）
///   [2] 虚拟 OS program hash（合约 `virtual_snos_program_hash` 钉扎值）
///   [7] L2→L1 消息数（应为 1）
///   [8] 首条消息哈希（== 合约 `snip36_message_hash(本合约地址, segment)`）
/// 样本一致后冻结 poker_dual_settlement.cairo 的 VIRTUAL_SNOS_VARIANT 与
/// owner 钉扎输入。
async fn dump_proof_facts(rpc_url: &str, tx_hash: &str) -> Result<(), Box<dyn std::error::Error>> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "starknet_getTransactionByHash",
        "params": [tx_hash],
    });
    let resp = reqwest::Client::new().post(rpc_url).json(&body).send().await?;
    let reply: serde_json::Value = resp.json().await?;
    if let Some(err) = reply.get("error") {
        return Err(format!("getTransactionByHash: {err}").into());
    }
    let tx = reply["result"].clone();
    println!("tx = {}", serde_json::to_string_pretty(&tx)?);
    let Some(facts) = tx["proof_facts"].as_array() else {
        println!("no proof_facts on this tx (not a proved transaction?)");
        return Ok(());
    };
    let felt_at = |i: usize| {
        facts.get(i).and_then(|v| v.as_str()).map(String::from)
    };
    let ascii_of = |hex: &str| {
        Felt::from_hex(hex).ok().map(|f| {
            let bytes = f.to_bytes_be();
            let printable: String = bytes
                .iter()
                .copied()
                .filter(|b| (0x20..0x7f).contains(b))
                .map(|b| b as char)
                .collect();
            printable
        })
    };
    println!("\n=== proof_facts 解读（{} 词）===", facts.len());
    for (i, f) in facts.iter().enumerate() {
        println!("facts[{i}] = {}", f.as_str().unwrap_or_default());
    }
    if let Some(v) = felt_at(1).as_deref().and_then(ascii_of) {
        println!("\nfacts[1] variant ASCII = {v:?}");
    }
    if let Some(h) = felt_at(2) {
        println!("facts[2] virtual OS program hash = {h}");
    }
    if let Some(n) = felt_at(7) {
        println!("facts[7] message count = {n}");
    }
    if let Some(m) = felt_at(8) {
        println!("facts[8] first message hash = {m}");
    }
    println!("\n对拍：把 facts[2] 作为 set_virtual_snos_program_hash 的输入，");
    println!("并用发起 create_proof 交易的 calldata 复算 snip36_message_hash 与 facts[8] 比对。");
    Ok(())
}
