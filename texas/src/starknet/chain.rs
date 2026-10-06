//! Starknet RPC 客户端（provider + 操作员账户）。
//!
//! `JsonRpcClient<HttpTransport>` 处理读调用（isValidSignature / balanceOf /
//! chip_balance / tx 回执），`SingleOwnerAccount` 在结算上链时签发
//! register_aggregate / settle_hand 交易。操作员私钥只在创建账户时使用一次。

use starknet::accounts::SingleOwnerAccount;
use starknet::core::types::{BlockId, BlockTag, FunctionCall, Felt};
use starknet::providers::jsonrpc::HttpTransport;
use starknet::providers::{JsonRpcClient, Provider};
use starknet::signers::{LocalWallet, SigningKey};
use std::sync::Arc;

use super::config::StarknetConfig;

pub type JsonRpcHttp = JsonRpcClient<HttpTransport>;
pub type OperatorAccount = SingleOwnerAccount<Arc<JsonRpcHttp>, LocalWallet>;

const DEVNET_RPC: &str = "http://localhost:5050";

pub struct StarknetChain {
    pub config: StarknetConfig,
    provider: Arc<JsonRpcHttp>,
    operator: tokio::sync::OnceCell<Option<Arc<OperatorAccount>>>,
}

impl StarknetChain {
    pub fn new(config: StarknetConfig) -> Self {
        let url = url::Url::parse(if config.rpc_enabled() {
            &config.rpc_url
        } else {
            DEVNET_RPC
        })
        .unwrap_or_else(|_| url::Url::parse(DEVNET_RPC).unwrap());
        Self {
            provider: Arc::new(JsonRpcClient::new(HttpTransport::new(url))),
            operator: tokio::sync::OnceCell::new(),
            config,
        }
    }

    /// SNIP-36 原始交易管线所需的 provider 访问（chain_id / nonce 读取）。
    pub fn provider(&self) -> &JsonRpcClient<HttpTransport> {
        &self.provider
    }

    /// 惰性构建操作员账户（需要地址 + 私钥 + RPC 齐备）。
    pub async fn operator(&self) -> Option<Arc<OperatorAccount>> {
        if !self.config.settlement_enabled() {
            return None;
        }
        self.operator
            .get_or_init(|| async {
                let address = parse_felt(&self.config.operator_address)?;
                let secret = parse_felt(&self.config.operator_private_key)?;
                let chain_id = self.provider.chain_id().await.ok()?;
                let account = SingleOwnerAccount::new(
                    self.provider.clone(),
                    LocalWallet::from_signing_key(SigningKey::from_secret_scalar(secret)),
                    address,
                    chain_id,
                    starknet::accounts::ExecutionEncoding::New,
                );
                // starknet-rs 0.16 默认 block_id 已是 PreConfirmed（nonce 读取
                // 包含已提交未 accepted 的交易，公共 RPC 上连续结算交易不撞
                // nonce）；显式标注仅为防止未来依赖升级改变默认值。
                let mut account = account;
                account.set_block_id(BlockId::Tag(BlockTag::PreConfirmed));
                Some(Arc::new(account))
            })
            .await
            .clone()
    }

    /// 通用合约只读调用（selector + calldata → 返回 felts）。
    pub async fn call_contract(
        &self,
        contract_address: Felt,
        entry_point: Felt,
        calldata: Vec<Felt>,
    ) -> Result<Vec<Felt>, String> {
        let request = FunctionCall {
            contract_address,
            entry_point_selector: entry_point,
            calldata,
        };
        self.provider.call(request, BlockId::Tag(BlockTag::Latest)).await
            .map_err(|e| format!("call_contract failed: {e}"))
    }

    /// finalized 高度公共 state root 取数通道。
    ///
    /// 读取承载 ObjectDb 根承诺的合约视图
    /// `finalized_state_root(key_hi: felt252, key_lo: felt252) -> felt252`
    /// （`state_object_key` = blake2b_256(ObjectID)，256 位无法进单个
    /// felt252，故拆两个 128 位半字入 calldata）。返回首个返回值的
    /// 32 字节大端根。地址与 selector 由调用方按 `DEPLOYMENTS.md`
    /// 记账的根承诺合约提供；调用失败即 fail-closed（不回退 prover 根），
    /// 结果专供 `state_image_admission` 接纳门使用。
    pub async fn finalized_state_root(
        &self,
        state_root_contract: Felt,
        entry_point: Felt,
        state_object_key: &[u8; 32],
    ) -> Result<[u8; 32], String> {
        let calldata = state_object_key_calldata(state_object_key);
        let felts = self
            .call_contract(state_root_contract, entry_point, calldata)
            .await?;
        state_root_from_return_felts(&felts)
    }
}

/// `state_object_key`（256 位）→ 两个 128 位大端半字 felt（hi, lo）。
fn state_object_key_calldata(key: &[u8; 32]) -> Vec<Felt> {
    let half = |bytes: &[u8]| {
        let mut word = [0u8; 16];
        word.copy_from_slice(bytes);
        let mut padded = [0u8; 32];
        padded[16..].copy_from_slice(&word);
        Felt::from_bytes_be(&padded)
    };
    vec![half(&key[0..16]), half(&key[16..32])]
}

/// 视图返回 felts → 32 字节大端根（取首个返回值；空返回 fail-closed）。
fn state_root_from_return_felts(felts: &[Felt]) -> Result<[u8; 32], String> {
    let first = felts
        .first()
        .ok_or_else(|| "finalized_state_root view returned no value".to_string())?;
    Ok(first.to_bytes_be())
}

#[cfg(test)]
mod state_root_channel_tests {
    use super::*;

    #[test]
    fn state_object_key_calldata_splits_key_into_two_halves() {
        let key = core::array::from_fn(|i| i as u8);
        let calldata = state_object_key_calldata(&key);
        assert_eq!(calldata.len(), 2);
        // hi = key[0..16] 右对齐进 felt。
        let mut hi = [0u8; 32];
        hi[16..].copy_from_slice(&key[0..16]);
        assert_eq!(calldata[0], Felt::from_bytes_be(&hi));
        let mut lo = [0u8; 32];
        lo[16..].copy_from_slice(&key[16..32]);
        assert_eq!(calldata[1], Felt::from_bytes_be(&lo));
    }

    #[test]
    fn state_root_decode_takes_first_return_and_rejects_empty() {
        // 合约返回的 felt 必为域内规范值（< P），故根首字节恒 0；
        // 32B 大端解码即该规范编码。
        let mut root = [0x7Au8; 32];
        root[0] = 0;
        let felt = Felt::from_bytes_be(&root);
        assert_eq!(
            state_root_from_return_felts(&[felt, Felt::ZERO]).unwrap(),
            root
        );
        assert!(state_root_from_return_felts(&[]).is_err());
    }
}

/// 解析 felt 字符串（0x hex 或十进制）。空串 / 非法输入返回 None。
pub fn parse_felt(s: &str) -> Option<Felt> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    // 钱包端签名数组以十进制字符串序列化（bigint.toString()），且十进制
    // 数字串当 hex 解析会超出域大小而失败，故两种进制都要支持。
    Felt::from_hex(s).ok().or_else(|| Felt::from_dec_str(s).ok())
}

/// 钱包标识 → felt（账户身份在所有账本层的统一解析入口）。
///
/// Starknet 钱包（≤31 字节地址）原样走 [`parse_felt`]；zchain 侧钱包是
/// 33 字节 tagged pubkey（0x + 66 hex），超出 felt252 位宽——用 blake2s_256
/// 确定性压缩（高 4 位清零保证落在域内）。镜像（vm_session）、结算钱包
/// 映射（hooks::hand_wallet_map）、appchain 出口（exit）必须同用本函数，
/// 同一钱包字符串才能在 VM 镜像与 appchain 账本落到同一身份。
pub fn parse_wallet_felt(s: &str) -> Option<Felt> {
    if let Some(f) = parse_felt(s) {
        return Some(f);
    }
    let t = s.trim().trim_start_matches("0x");
    let bytes = hex::decode(t).ok()?;
    if bytes.len() != 33 {
        return None;
    }
    // poker_appchain::keys::blake2s32 = Blake2s-256（与 appchain 账本派生
    // 同一摘要原语，零新增依赖）。
    let mut h = poker_appchain::keys::blake2s32(&[&bytes]).to_vec();
    h[0] &= 0x0F; // 保证 < 2^252（felt 域）
    Felt::from_bytes_be(&h.try_into().ok()?).into()
}

/// 合约入口名 → selector（`starknet_keccak`）。lock / chips 等 vault 调用共用。
pub fn selector(name: &str) -> Felt {
    starknet::core::utils::starknet_keccak(name.as_bytes())
}

/// 字节序列 → 小写 hex（无 `0x` 前缀、不去前导零）。
///
/// starknet 层各处本地 hex 辅助（lock::wallet_of_felt 的 32 字节钱包、
/// recursion_prover 的仿射坐标/标量、dual_settle 测试向量行）统一于此；
/// 需要 `0x` 前缀的调用方自行拼接。注意 `pokergame::actions::hex_encode_starknet`
/// 有去前导零语义（`0x0` 归一），与本函数不同，保持独立。
pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

