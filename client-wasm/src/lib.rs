use wasm_bindgen::prelude::*;
use serde::{Serialize, Deserialize};
use poker_protocol::z_poker::convert;
use poker_protocol::z_poker::protocol::ClientPlayer;
use poker_protocol::crypto::{ElGamalCiphertext, Scalar, EcPoint, Plaintext, DefaultCurve, CurveScalar, CurvePoint};
use poker_protocol::zk_shuffle::reveal_token_proof::RevealTokenProof;
use poker_protocol::crypto::types::base_g;
use rand_core::OsRng;
use serde_wasm_bindgen;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

fn console_log(msg: &str) {
    let _ = log(&format!("[client-wasm] {}", msg));
}

// hex 编码薄弱化（2026-09-10 收敛）：单一权威在
// poker_protocol::z_poker::convert（此前的逐行重写拷贝删除）。
// wasm_bindgen 边界的 String/&str 转换留在本包装层。
//
// 2026-09-07 回归注记：hex_to_ecpoint 曾按 BLS12-381 时代断言 48 字节，
// Stark 压缩点 32 字节 → 浏览器洗牌全挂（2026-09-06 重建 pkg 首次把
// 遗留代码编进产物后爆发）。长度校验现为 convert/from_compressed 的
// 单一实现（≠32B 一律拒绝），回归测试 ecpoint_hex_rejects_wrong_length
// 继续守护。
pub fn scalar_to_hex(s: &Scalar) -> String {
    convert::scalar_to_hex(s)
}

fn hex_to_scalar(hex_str: &str) -> Result<Scalar, String> {
    convert::hex_to_scalar(hex_str)
}

pub fn ecpoint_to_hex(p: &EcPoint) -> String {
    convert::ecpoint_to_hex(p)
}

fn hex_to_ecpoint(hex_str: &str) -> Result<EcPoint, String> {
    convert::hex_to_ecpoint(hex_str)
}

fn ct_to_json(ct: &ElGamalCiphertext) -> String {
    format!(
        r#"{{"c1_hex":"{}","c2_hex":"{}"}}"#,
        ecpoint_to_hex(&ct.c1),
        ecpoint_to_hex(&ct.c2)
    )
}

fn ct_generic_to_json(ct: &poker_protocol::crypto::ElGamalCiphertextGeneric<DefaultCurve>) -> String {
    format!(
        r#"{{"c1_hex":"{}","c2_hex":"{}"}}"#,
        ecpoint_to_hex(&ct.c1),
        ecpoint_to_hex(&ct.c2)
    )
}

fn obj_string_to_ct(val: serde_json::Value) -> Result<ElGamalCiphertext, String> {
    match val {
        serde_json::Value::Object(obj) => {
            Ok(ElGamalCiphertext {
                c1: hex_to_ecpoint(obj["c1_hex"].as_str().unwrap_or(""))?,
                c2: hex_to_ecpoint(obj["c2_hex"].as_str().unwrap_or(""))?,
            })
        }
        _ => {
            console_log(&format!("obj_string_to_ct: parsed {:?}", val));
            Err("Invalid JSON object".to_string())
        }
    }
}

fn json_to_ct(json_str: &str) -> Result<ElGamalCiphertext, String> {
    let val: serde_json::Value = serde_json::from_str(json_str)
        .map_err(|e| format!("JSON parse error: {}", e))?;
    Ok(ElGamalCiphertext {
        c1: hex_to_ecpoint(val["c1_hex"].as_str().unwrap_or(""))?,
        c2: hex_to_ecpoint(val["c2_hex"].as_str().unwrap_or(""))?,
    })
}

fn convert_digest32(hex_str: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(hex_str).map_err(|e| format!("bad digest hex: {e}"))?;
    bytes
        .try_into()
        .map_err(|_| "digest must be 32 bytes".to_string())
}

fn hex_encode_bytes32(bytes: &[u8; 32]) -> String {
    hex::encode(bytes)
}

fn ct_vec_to_json(cts: &[ElGamalCiphertext]) -> String {
    let arr: Vec<String> = cts.iter().map(ct_to_json).collect();
    format!("[{}]", arr.join(","))
}

fn scalar_vec_to_json(values: &[Scalar]) -> String {
    let encoded: Vec<String> = values.iter().map(scalar_to_hex).collect();
    serde_json::to_string(&encoded).unwrap_or_else(|_| "[]".to_string())
}

fn point_vec_to_json(values: &[EcPoint]) -> String {
    let encoded: Vec<String> = values.iter().map(ecpoint_to_hex).collect();
    serde_json::to_string(&encoded).unwrap_or_else(|_| "[]".to_string())
}

fn schnorr_proof_to_json(
    proof: &poker_protocol::zk_shuffle::generalized_schnorr_proof::GeneralizedSchnorrProof<DefaultCurve>,
) -> String {
    format!(
        r#"{{"commitment_hex":"{}","responses_hex":{}}}"#,
        ecpoint_to_hex(&proof.commitment),
        scalar_vec_to_json(&proof.responses),
    )
}

fn bayer_groth_proof_to_json(
    proof: &poker_protocol::zk_shuffle::bayer_groth::BayerGrothShuffleProof<DefaultCurve>,
) -> String {
    let mexp = &proof.multi_exponentiation;
    let product = &proof.product;
    format!(
        r#"{{"c_permutation_hex":"{}","c_permuted_powers_hex":"{}","multi_exponentiation":{{"c_alpha_hex":"{}","c_beta_hex":"{}","ciphertext_0":{},"ciphertext_1":{},"alpha_response_hex":{},"commitment_response_hex":"{}","beta_hex":"{}","beta_blinding_response_hex":"{}","rerandomization_response_hex":"{}"}},"product":{{"c_d_hex":"{}","c_delta_hex":"{}","c_capital_delta_hex":"{}","a_response_hex":{},"b_response_hex":{},"r_response_hex":"{}","s_response_hex":"{}"}}}}"#,
        ecpoint_to_hex(&proof.c_permutation),
        ecpoint_to_hex(&proof.c_permuted_powers),
        ecpoint_to_hex(&mexp.c_alpha),
        ecpoint_to_hex(&mexp.c_beta),
        ct_generic_to_json(&mexp.ciphertext_0),
        ct_generic_to_json(&mexp.ciphertext_1),
        scalar_vec_to_json(&mexp.alpha_response),
        scalar_to_hex(&mexp.commitment_response),
        scalar_to_hex(&mexp.beta),
        scalar_to_hex(&mexp.beta_blinding_response),
        scalar_to_hex(&mexp.rerandomization_response),
        ecpoint_to_hex(&product.c_d),
        ecpoint_to_hex(&product.c_delta),
        ecpoint_to_hex(&product.c_capital_delta),
        scalar_vec_to_json(&product.a_response),
        scalar_vec_to_json(&product.b_response),
        scalar_to_hex(&product.r_response),
        scalar_to_hex(&product.s_response),
    )
}

fn shuffle_proof_to_json(proof: &poker_protocol::zk_shuffle::ShuffleProof) -> String {
    use poker_protocol::zk_shuffle::versioned::VersionedShuffleProof;

    match proof {
        VersionedShuffleProof::LegacyV1(proof) => format!(
            r#"{{"sum_c1_commit_hex":"{}","sum_c2_commit_hex":"{}","combined_schnorr_proof":{},"sum_c1_schnorr_proof":{},"sum_c2_schnorr_proof":{},"nonce_hex":"{}"}}"#,
            ecpoint_to_hex(&proof.sum_c1_commit),
            ecpoint_to_hex(&proof.sum_c2_commit),
            schnorr_proof_to_json(&proof.combined_schnorr_proof),
            schnorr_proof_to_json(&proof.sum_c1_schnorr_proof),
            schnorr_proof_to_json(&proof.sum_c2_schnorr_proof),
            scalar_to_hex(&proof.nonce),
        ),
        VersionedShuffleProof::BayerGrothV2(proof) => format!(
            r#"{{"version":2,"proof":{}}}"#,
            bayer_groth_proof_to_json(proof),
        ),
    }
}

/// 解析浏览器端传入的洗牌置换（JSON 数组，长度必须恰为 N_CARDS）。
/// 双射校验由协议层 `ShuffleRound::execute` fail-closed 承担。
fn parse_permute(permute_json: &str) -> Result<[usize; poker_protocol::crypto::N_CARDS], JsValue> {
    let vec: Vec<usize> = serde_json::from_str(permute_json)
        .map_err(|e| JsValue::from_str(&format!("invalid permute json: {e}")))?;
    let arr: [usize; poker_protocol::crypto::N_CARDS] = vec.try_into().map_err(|v: Vec<usize>| {
        JsValue::from_str(&format!("permute length must be {}, got {}", poker_protocol::crypto::N_CARDS, v.len()))
    })?;
    Ok(arr)
}

fn json_to_ct_vec(json_str: &str) -> Result<Vec<ElGamalCiphertext>, String> {
    let arr: Vec<serde_json::Value> = serde_json::from_str(json_str)
        .map_err(|e| format!("JSON parse error: {}", e))?;
    let mut result:Vec<ElGamalCiphertext> = vec![];
    for v in arr {
        result.push(obj_string_to_ct(v)?);
    }
    Ok(result)
}

fn reveal_token_proof_to_json(proof: &RevealTokenProof<DefaultCurve>) -> String {
    format!(
        r#"{{"user_public_key_hex":"{}","commitment_t1_hex":"{}","commitment_t2_hex":"{}","response_s_hex":"{}","nonce_hex":"{}"}}"#,
        ecpoint_to_hex(&proof.user_public_key),
        ecpoint_to_hex(&proof.commitment_t1),
        ecpoint_to_hex(&proof.commitment_t2),
        scalar_to_hex(&proof.response_s),
        scalar_to_hex(&proof.nonce)
    )
}

fn json_to_reveal_token_proof(json_str: &str) -> Result<RevealTokenProof<DefaultCurve>, String> {
    let val: serde_json::Value = serde_json::from_str(json_str)
        .map_err(|e| format!("JSON parse error: {}", e))?;
    Ok(RevealTokenProof {
        user_public_key: hex_to_ecpoint(val["user_public_key"].as_str().unwrap_or(""))?,
        commitment_t1: hex_to_ecpoint(val["commitment_t1"].as_str().unwrap_or(""))?,
        commitment_t2: hex_to_ecpoint(val["commitment_t2"].as_str().unwrap_or(""))?,
        response_s: hex_to_scalar(val["response_s"].as_str().unwrap_or(""))?,
        nonce: hex_to_scalar(val["nonce"].as_str().unwrap_or(""))?,
    })
}

#[derive(Serialize, Deserialize)]
pub struct PlayerKeys {
    pub player_pk: String,
    pub sk: String,
    pub pk: String,
}

#[wasm_bindgen]
pub struct WasmClientPlayer {
    inner: ClientPlayer,
}

fn json_val_to_jsvalue(s: String) -> JsValue {
    JsValue::from_str(&s)
}

#[wasm_bindgen]
impl WasmClientPlayer {
    #[wasm_bindgen(constructor)]
    pub fn new(wallet_address: &str) -> WasmClientPlayer {
        console_log("Creating client player");
        WasmClientPlayer {
            inner: ClientPlayer::new_with_wallet_address(wallet_address),
        }
    }

    /// 根据钱包地址确定性生成密钥对（与 new 行为相同，显式命名）
    pub fn new_with_wallet_address(wallet_address: &str) -> WasmClientPlayer {
        console_log("Creating client player with wallet address");
        WasmClientPlayer {
            inner: ClientPlayer::new_with_wallet_address(wallet_address),
        }
    }

    /// 随机会话密钥（Part B 默认模式）：CSPRNG 生成，与钱包零派生关系。
    /// sk 经 get_sk_hex 存 localStorage，重载用 from_sk 恢复。
    pub fn new_random() -> WasmClientPlayer {
        WasmClientPlayer {
            inner: ClientPlayer::new(),
        }
    }

    /// 口令派生身份（Part B1.5，用户可选的可恢复模式）：同一口令在任何
    /// 设备派生出同一 (sk, pk)。KDF 参数冻结在 "zgame:player-key:v1"。
    /// 注意：不要用钱包助记词/恢复短语作为口令。
    pub fn new_with_passphrase(passphrase: &str) -> WasmClientPlayer {
        WasmClientPlayer {
            inner: ClientPlayer::new_with_passphrase(passphrase),
        }
    }

    pub fn from_sk(sk_hex: &str) -> Result<WasmClientPlayer, JsValue> {
        let sk = match hex_to_scalar(sk_hex) {
            Ok(s) => s,
            Err(e) => return Err(JsValue::from_str(&e)),
        };
        let pk = base_g() * &sk;
        Ok(WasmClientPlayer {
            inner: ClientPlayer { sk, pk },
        })
    }

    pub fn get_pk_hex(&self) -> String { ecpoint_to_hex(&self.inner.pk) }

    pub fn get_sk_hex(&self) -> String { scalar_to_hex(&self.inner.sk) }

    pub fn to_keys(&self) -> JsValue {
        let keys = PlayerKeys {
            player_pk: ecpoint_to_hex(&self.inner.pk),
            sk: scalar_to_hex(&self.inner.sk),
            pk: ecpoint_to_hex(&self.inner.pk),
        };
        match serde_wasm_bindgen::to_value(&keys) {
            Ok(v) => v,
            Err(_) => JsValue::NULL,
        }
    }

    pub fn generate_pk_proof(&self) -> JsValue {
        let proof = self.inner.generate_pk_proof();
        let s = format!(
            r#"{{"commitment_hex":"{}","response_hex":"{}"}}"#,
            ecpoint_to_hex(&proof.commitment),
            scalar_to_hex(&proof.response)
        );
        json_val_to_jsvalue(s)
    }

    pub fn decrypt_card(&self, ct_json: &str) -> Result<String, JsValue> {
        let ct = json_to_ct(ct_json).map_err(|e| JsValue::from_str(&e))?;
        let pt = self.inner.decrypt_card(&ct);
        Ok(ecpoint_to_hex(&pt))
    }

    pub fn peek_own_card(&self, ct_json: &str) -> Result<String, JsValue> {
        let ct = json_to_ct(ct_json).map_err(|e| JsValue::from_str(&e))?;
        let pt = self.inner.peek_own_card(&ct);
        Ok(ecpoint_to_hex(&pt))
    }

    pub fn peek_card(&self, ct_json: &str, tokens_json: &str, plain_cards_json: &str) -> Result<String, JsValue> {
        let ct = json_to_ct(ct_json).map_err(|e| JsValue::from_str(&e))?;
        let tokens_arr: Vec<serde_json::Value> = match serde_json::from_str(tokens_json) {
            Ok(arr) => arr,
            Err(e) => return Err(JsValue::from_str(&format!("JSON error: {}", e))),
        };

        use poker_protocol::z_poker::protocol::RevealToken as RT;
        let mut tokens: Vec<RT> = vec![];
        for tval in &tokens_arr {
            let encrypted_card = match json_to_ct(&tval.to_string()) {
                Ok(ct) => ct,
                Err(e) => return Err(JsValue::from_str(&e)),
            };
            let reveal_token = match hex_to_ecpoint(tval["reveal_token"].as_str().unwrap_or("")) {
                Ok(p) => p,
                Err(e) => return Err(JsValue::from_str(&e)),
            };
            let proof = match json_to_reveal_token_proof(&tval["proof"].to_string()) {
                Ok(p) => p,
                Err(e) => return Err(JsValue::from_str(&e)),
            };
            tokens.push(RT { user_public_key: hex_to_ecpoint(tval["user_public_key"].as_str().unwrap_or(""))?, encrypted_card, proof, reveal_token });
        }

        let pt_arr: Vec<String> = serde_json::from_str(plain_cards_json)
            .map_err(|e| JsValue::from_str(&format!("JSON error: {}", e)))?;
        let plain_cards: Vec<Plaintext> = pt_arr.iter()
            .map(|s| hex_to_ecpoint(s))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| JsValue::from_str(&e))?;

        let pt = self.inner.peek_card(&ct, &tokens, &plain_cards).map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;
        Ok(ecpoint_to_hex(&pt.0))
    }

    pub fn generate_reveal_token(&self, ct_json: &str) -> Result<JsValue, JsValue> {
        let ct = json_to_ct(ct_json).map_err(|e| JsValue::from_str(&e))?;
        let token = self.inner.generate_reveal_token(&ct);

        let s = format!(
            r#"{{"encrypted_card":{},"reveal_token":"{}","proof":{}}}"#,
            ct_to_json(&token.encrypted_card),
            ecpoint_to_hex(&token.reveal_token),
            reveal_token_proof_to_json(&token.proof)
        );
        Ok(json_val_to_jsvalue(s))
    }

    pub fn batch_generate_reveal_token(&self, cts_json: &str) -> Result<JsValue, JsValue> {
        let cts = json_to_ct_vec(cts_json).map_err(|e| JsValue::from_str(&e))?;
        let tokens = self.inner.batch_generate_reveal_token(&cts);

        let items: Vec<String> = tokens.iter().enumerate().map(|(i, token)| {
            format!(
                r#"{{"card_index":{},"encrypted_card":{},"reveal_token_proof":{},"reveal_token_hex":"{}"}}"#,
                i,
                ct_to_json(&token.encrypted_card),
                reveal_token_proof_to_json(&token.proof),
                ecpoint_to_hex(&token.reveal_token)
            )
        }).collect();
        Ok(json_val_to_jsvalue(format!("[{}]", items.join(","))))
    }

    pub fn verify_and_reveal_from_token(token_json: &str) -> Result<String, JsValue> {
        let val: serde_json::Value = match serde_json::from_str(token_json) {
            Ok(v) => v,
            Err(e) => return Err(JsValue::from_str(&format!("JSON error: {}", e))),
        };
        let encrypted_card = match json_to_ct(&val["encrypted_card"].to_string()) {
            Ok(ct) => ct,
            Err(e) => return Err(JsValue::from_str(&e)),
        };
        let reveal_token = match hex_to_ecpoint(val["reveal_token"].as_str().unwrap_or("")) {
            Ok(p) => p,
            Err(e) => return Err(JsValue::from_str(&e)),
        };
        let proof = match json_to_reveal_token_proof(&val["proof"].to_string()) {
            Ok(p) => p,
            Err(e) => return Err(JsValue::from_str(&e)),
        };

        let token = poker_protocol::z_poker::protocol::RevealToken {
            user_public_key: hex_to_ecpoint(val["user_public_key_hex"].as_str().unwrap_or(""))?,
            encrypted_card,
            proof,
            reveal_token,
        };

        let pt = ClientPlayer::verify_and_reveal_from_token(&token)
            .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;
        Ok(ecpoint_to_hex(&pt))
    }

    /// 用户洗牌：`permute_json` 为浏览器端生成的洗牌置换（JSON 数组）——
    /// 洗牌决定权在用户客户端，库不代生成。非双射置换 fail-closed 拒绝。
    pub fn shuffle(
        &self,
        deck_encrypted_json: &str,
        agg_pk_hex: &str,
        permute_json: &str,
    ) -> Result<JsValue, JsValue> {
        let deck = json_to_ct_vec(deck_encrypted_json).map_err(|e| JsValue::from_str(&e))?;
        let agg_pk = hex_to_ecpoint(agg_pk_hex).map_err(|e| JsValue::from_str(&e))?;
        let permute = parse_permute(permute_json)?;

        let round = self
            .inner
            .shuffle(&deck, &agg_pk, permute)
            .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

        let shuffle_proof_json = shuffle_proof_to_json(&round.proof);

        let s = format!(
            r#"{{"player_pk":"{}","input_cards":{},"output_cards":{},"shuffle_proof":{}}}"#,
            ecpoint_to_hex(&self.inner.pk),
            ct_vec_to_json(&round.input_cards),
            ct_vec_to_json(&round.output_cards),
            shuffle_proof_json,
        );
        Ok(json_val_to_jsvalue(s))
    }

    pub fn join_game_and_shuffle(
        &self,
        deck_encrypted_json: &str,
        agg_pk_hex: &str,
        permute_json: &str,
    ) -> Result<JsValue, JsValue> {
        let deck = json_to_ct_vec(deck_encrypted_json).map_err(|e| JsValue::from_str(&e))?;
        let agg_pk = hex_to_ecpoint(agg_pk_hex).map_err(|e| JsValue::from_str(&e))?;
        let permute = parse_permute(permute_json)?;

        let round = self
            .inner
            .join_game_and_shuffle(&deck, &agg_pk, permute)
            .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;
        let ms = &round.mask_and_shuffle_round;
        let per_card_commitments_hex: Vec<String> = ms.remask_proof.per_card_commitments.iter()
            .map(ecpoint_to_hex).collect();
        let remask_proof_json = format!(
            r#"{{"per_card_commitments_hex":{},"commitment_pk_hex":"{}","response_hex":"{}","nonce_hex":"{}"}}"#,
            serde_json::to_string(&per_card_commitments_hex).unwrap_or("[]".to_string()),
            ecpoint_to_hex(&ms.remask_proof.commitment_pk),
            scalar_to_hex(&ms.remask_proof.response),
            scalar_to_hex(&ms.remask_proof.nonce),
        );

        let shuffle_proof_json = shuffle_proof_to_json(&ms.proof);

        let mask_and_shuffle_json = format!(
            r#"{{"mask_cards":{},"remask_proof":{},"output_cards":{},"shuffle_proof":{}}}"#,
            ct_vec_to_json(&ms.mask_cards),
            remask_proof_json,
            ct_vec_to_json(&ms.output_cards),
            shuffle_proof_json,
        );

        let proof = round.pk_ownership_proof;
        let pk_proof_json = format!(
            r#"{{"commitment_hex":"{}","response_hex":"{}"}}"#,
            ecpoint_to_hex(&proof.commitment),
            scalar_to_hex(&proof.response)
        );

        let join_game_and_shuffle_json = format!(
            r#"{{"pk_ownership_proof":{},"pk_hex":"{}","mask_and_shuffle_round":{}}}"#,
            pk_proof_json,
            round.pk_hex,
            mask_and_shuffle_json,
        );
        Ok(json_val_to_jsvalue(join_game_and_shuffle_json))
    }

    /// `excluded_indices_json`: JSON 数组，玩家自己手牌在牌组中的槽位
    /// （离开/弃牌剥层排除这些槽——剥层输出会公开 sk·c1 = reveal token，
    /// 不排除自己手牌等于向串谋者亮牌）。验证方从发牌状态推导同一集合。
    pub fn leave_game(
        &self,
        deck_encrypted_json: &str,
        excluded_indices_json: &str,
    ) -> Result<JsValue, JsValue> {
        let deck = json_to_ct_vec(deck_encrypted_json).map_err(|e| JsValue::from_str(&e))?;
        let excluded: Vec<usize> = serde_json::from_str(excluded_indices_json)
            .map_err(|e| JsValue::from_str(&format!("excluded indices JSON: {e}")))?;

        let round = self.inner.leave_game_with_exclusions(&deck, &excluded);

        let per_card_commitments_hex: Vec<String> = round.leave_proof.per_card_commitments.iter()
            .map(ecpoint_to_hex).collect();
        let leave_proof_json = format!(
            r#"{{"per_card_commitments_hex":{},"commitment_pk_hex":"{}","response_hex":"{}","nonce_hex":"{}"}}"#,
            serde_json::to_string(&per_card_commitments_hex).unwrap_or("[]".to_string()),
            ecpoint_to_hex(&round.leave_proof.commitment_pk),
            scalar_to_hex(&round.leave_proof.response),
            scalar_to_hex(&round.leave_proof.nonce),
        );

        let leave_game_json = format!(
            r#"{{"input_cards":{},"output_cards":{},"leave_proof":{}}}"#,
            ct_vec_to_json(&round.input_cards),
            ct_vec_to_json(&round.output_cards),
            leave_proof_json,
        );
        Ok(json_val_to_jsvalue(leave_game_json))
    }

    pub fn reveal_own_card(
        &self,
        hand_index: usize,
        hand_encrypted_json: &str,
        deck_plaintext_json: &str,
        agg_pk_hex: &str,
    ) -> Result<JsValue, JsValue> {
        let hand = json_to_ct_vec(hand_encrypted_json).map_err(|e| JsValue::from_str(&e))?;

        let pt_arr: Vec<String> = match serde_json::from_str(deck_plaintext_json) {
            Ok(arr) => arr,
            Err(e) => return Err(JsValue::from_str(&format!("JSON error: {}", e))),
        };
        let deck_pt: Vec<Plaintext> = pt_arr.iter()
            .map(|s| hex_to_ecpoint(s))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| JsValue::from_str(&e))?;

        let agg_pk = hex_to_ecpoint(agg_pk_hex).map_err(|e| JsValue::from_str(&e))?;

        let token = self.inner.reveal_own_card(hand_index, &hand, &deck_pt, &agg_pk)
            .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

        let s = format!(
            r#"{{"encrypted_card":{},"reveal_token":"{}","proof":{}}}"#,
            ct_to_json(&token.encrypted_card),
            ecpoint_to_hex(&token.reveal_token),
            reveal_token_proof_to_json(&token.proof)
        );
        Ok(json_val_to_jsvalue(s))
    }

    pub fn reveal_community(&self, comm_plaintext_hex: &str) -> Result<JsValue, JsValue> {
        let comm_pt = hex_to_ecpoint(comm_plaintext_hex).map_err(|e| JsValue::from_str(&e))?;
        let token = self.inner.reveal_community(comm_pt);

        let s = format!(
            r#"{{"encrypted_card":{},"reveal_token":"{}","proof":{}}}"#,
            ct_to_json(&token.encrypted_card),
            ecpoint_to_hex(&token.reveal_token),
            reveal_token_proof_to_json(&token.proof)
        );
        Ok(json_val_to_jsvalue(s))
    }

    pub fn generate_expel_proof(
        &self,
        _hand_encrypted_json: &str,
        _agg_pk_hex: &str,
        _per_card_tokens_json: &str,
    ) -> Result<JsValue, JsValue> {
        Err(JsValue::from_str("generate_expel_proof is no longer supported"))
    }

    pub fn remask_card(&self, ct_json: &str, pk_hex: &str) -> Result<JsValue, JsValue> {
        let ct = json_to_ct(ct_json).map_err(|e| JsValue::from_str(&e))?;
        let pk = hex_to_ecpoint(pk_hex).map_err(|e| JsValue::from_str(&e))?;

        let (remasked, _alpha) = self.inner.remask_card(&ct, &pk);
        Ok(json_val_to_jsvalue(ct_to_json(&remasked)))
    }

    pub fn distributed_decrypt(&self, ct_json: &str, tokens_hexes: &str) -> Result<String, JsValue> {
        let ct = json_to_ct(ct_json).map_err(|e| JsValue::from_str(&e))?;
        let token_hexes: Vec<String> = match serde_json::from_str(tokens_hexes) {
            Ok(arr) => arr,
            Err(e) => return Err(JsValue::from_str(&format!("JSON error: {}", e))),
        };
        let tokens: Vec<EcPoint> = token_hexes.iter()
            .map(|h| hex_to_ecpoint(h))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| JsValue::from_str(&e))?;

        let pt = self.inner.distributed_decrypt(&ct, &tokens);
        Ok(ecpoint_to_hex(&pt))
    }

    pub fn distributed_decrypt_from_tokens(&self, ct_json: &str, tokens_json: &str) -> Result<String, JsValue> {
        let ct = json_to_ct(ct_json).map_err(|e| JsValue::from_str(&e))?;
        let tokens_arr: Vec<serde_json::Value> = match serde_json::from_str(tokens_json) {
            Ok(arr) => arr,
            Err(e) => return Err(JsValue::from_str(&format!("JSON error: {}", e))),
        };

        use poker_protocol::z_poker::protocol::RevealToken as RT;
        let mut tokens: Vec<RT> = vec![];
        for tval in &tokens_arr {
            let encrypted_card = json_to_ct(&tval.to_string()).map_err(|e| JsValue::from_str(&e))?;
            let reveal_token = hex_to_ecpoint(tval["reveal_token"].as_str().unwrap_or(""))
                .map_err(|e| JsValue::from_str(&e))?;
            let proof = json_to_reveal_token_proof(&tval["proof"].to_string())
                .map_err(|e| JsValue::from_str(&e))?;
            tokens.push(RT { user_public_key: hex_to_ecpoint(tval["user_public_key"].as_str().unwrap_or(""))?, encrypted_card, proof, reveal_token });
        }

        let pt = ClientPlayer::distributed_decrypt_from_tokens(&ct, &tokens)
            .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;
        Ok(ecpoint_to_hex(&pt))
    }

    pub fn mask_card(&self, plaintext_hex: &str, pk_hex: &str) -> Result<JsValue, JsValue> {
        let pt = hex_to_ecpoint(plaintext_hex).map_err(|e| JsValue::from_str(&e))?;
        let pk = hex_to_ecpoint(pk_hex).map_err(|e| JsValue::from_str(&e))?;

        let (encrypted, _r) = self.inner.mask_card(&pt, &pk);
        Ok(json_val_to_jsvalue(ct_to_json(&encrypted)))
    }

    pub fn decrypt_playing_card(&self, ct_json: &str, other_tokens_json: &str, deck_plaintext_json: &str) -> Result<String, JsValue> {
        let ct = json_to_ct(ct_json).map_err(|e| JsValue::from_str(&e))?;
        let tokens_arr: Vec<serde_json::Value> = serde_json::from_str(other_tokens_json)
            .map_err(|e| JsValue::from_str(&format!("JSON error: {}", e)))?;
        let mut other_tokens = Vec::new();
        for tval in &tokens_arr {
            let token_hex = tval.as_str().unwrap_or("");
            other_tokens.push(hex_to_ecpoint(token_hex).map_err(|e| JsValue::from_str(&e))?);
        }

        let pt_arr: Vec<String> = serde_json::from_str(deck_plaintext_json)
            .map_err(|e| JsValue::from_str(&format!("JSON error: {}", e)))?;
        let deck_plaintext: Vec<Plaintext> = pt_arr.iter()
            .map(|s| hex_to_ecpoint(s))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| JsValue::from_str(&e))?;

        self.inner.decrypt_playing_card(&ct, other_tokens, deck_plaintext)
            .map(|card| card.to_string())
            .ok_or_else(|| JsValue::from_str("Failed to decrypt playing card"))
    }

    pub fn decrypt_readable_card(&self, ct_json: &str, deck_plaintext_json: &str) -> Result<String, JsValue>  {
        let ct = json_to_ct(ct_json).map_err(|e| JsValue::from_str(&e))?;

        let pt_arr: Vec<String> = serde_json::from_str(deck_plaintext_json)
            .map_err(|e| JsValue::from_str(&format!("JSON error: {}", e)))?;
        let deck_plaintext: Vec<Plaintext> = pt_arr.iter()
            .map(|s| hex_to_ecpoint(s))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| JsValue::from_str(&e))?;

        self.inner.decrypt_owner_residual_carrier(&ct, deck_plaintext)
        .map(|card| card.to_string())
        .ok_or_else(|| {
            // 诊断信息：帮助定位连续打牌场景下的解密失败原因
            // 主要触发点：relayer 未重建 player_assignments → 前端无 reveal_token → 链上 partial_decrypt_c2 错误
            console_log(&format!(
                "decrypt_readable_card failed: c1={} c2={} deck_plaintext_size={}",
                ecpoint_to_hex(&ct.c1),
                ecpoint_to_hex(&ct.c2),
                deck_plaintext_json.len()
            ));
            JsValue::from_str("Failed to decrypt readable card")
        })
    }

    /// 新协议 reconstruction：输入服务端 ReconstructNotice 下发的
    /// context_digest / epoch / prior_state_digest / 聚合钥与自己的
    /// residual carriers，产出 statement + proof（JSON，与 texas 服务端
    /// ReconstructionStatementJson/ReconstructProofJson 适配器逐字段对齐）。
    #[allow(clippy::too_many_arguments)]
    pub fn reconstruct(
        &self,
        origin_cards_json: &str,
        residual_carriers_json: &str,
        context_digest_hex: &str,
        reconstruction_epoch: u64,
        prior_state_digest_hex: &str,
        aggregate_pk_hex: &str,
    ) -> Result<JsValue, JsValue> {
        let origin_pt_arr: Vec<String> = serde_json::from_str(origin_cards_json)
            .map_err(|e| JsValue::from_str(&format!("JSON error: {}", e)))?;
        let origin_cards: Vec<EcPoint> = origin_pt_arr.iter()
            .map(|s| hex_to_ecpoint(s))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| JsValue::from_str(&e))?;

        let residual_carriers = json_to_ct_vec(residual_carriers_json)
            .map_err(|e| JsValue::from_str(&e))?;

        let context_digest = convert_digest32(context_digest_hex)
            .map_err(|e| JsValue::from_str(&e))?;
        let prior_state_digest = convert_digest32(prior_state_digest_hex)
            .map_err(|e| JsValue::from_str(&e))?;

        let aggregate_pk = hex_to_ecpoint(aggregate_pk_hex)
            .map_err(|e| JsValue::from_str(&e))?;

        let result = self.inner.reconstruct(
            context_digest,
            reconstruction_epoch,
            prior_state_digest,
            &origin_cards,
            &residual_carriers,
            &aggregate_pk,
        ).map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

        fn cross_key_proof_to_json(
            proof: &poker_protocol::zk_shuffle::reconstruction::CrossKeyNegationProof<DefaultCurve>,
        ) -> String {
            format!(
                r#"{{"commitment_owner_key_hex":"{}","commitment_contribution_c1_hex":"{}","commitment_joint_c2_hex":"{}","response_owner_sk_hex":"{}","response_contribution_randomness_hex":"{}"}}"#,
                ecpoint_to_hex(&proof.commitment_owner_key),
                ecpoint_to_hex(&proof.commitment_contribution_c1),
                ecpoint_to_hex(&proof.commitment_joint_c2),
                scalar_to_hex(&proof.response_owner_sk),
                scalar_to_hex(&proof.response_contribution_randomness),
            )
        }

        fn slot_or_proof_to_json(
            proof: &poker_protocol::zk_shuffle::reconstruction::SlotContributionOrProof<DefaultCurve>,
        ) -> String {
            let pt2 = |pts: &[EcPoint; 2]| -> String {
                serde_json::to_string(&[
                    ecpoint_to_hex(&pts[0]),
                    ecpoint_to_hex(&pts[1]),
                ]).unwrap_or_else(|_| "[]".to_string())
            };
            let sc2 = |scs: &[Scalar; 2]| -> String {
                serde_json::to_string(&[
                    scalar_to_hex(&scs[0]),
                    scalar_to_hex(&scs[1]),
                ]).unwrap_or_else(|_| "[]".to_string())
            };
            format!(
                r#"{{"commitment_g":{},"commitment_pk":{},"challenges":{},"responses":{}}}"#,
                pt2(&proof.commitment_g),
                pt2(&proof.commitment_pk),
                sc2(&proof.challenges),
                sc2(&proof.responses),
            )
        }

        let cross_key_json: Vec<String> = result.proof.cross_key_proofs.iter()
            .map(cross_key_proof_to_json).collect();
        let slot_json: Vec<String> = result.proof.slot_membership_proofs.iter()
            .map(slot_or_proof_to_json).collect();

        let statement_json = format!(
            r#"{{"version":{},"context_digest":"{}","reconstruction_epoch":{},"prior_state_digest":"{}","aggregate_pk":"{}","owner_pk":"{}","cards":{},"residual_carriers":{},"contributions":{}}}"#,
            result.statement.version,
            hex_encode_bytes32(&result.statement.context_digest),
            result.statement.reconstruction_epoch,
            hex_encode_bytes32(&result.statement.prior_state_digest),
            ecpoint_to_hex(&result.statement.aggregate_pk),
            ecpoint_to_hex(&result.statement.owner_pk),
            point_vec_to_json(&result.statement.cards),
            ct_vec_to_json(&result.statement.residual_carriers),
            ct_vec_to_json(&result.statement.contributions),
        );

        let proof_json = format!(
            r#"{{"version":{},"negative_contributions":{},"cross_key_proofs":[{}],"contribution_shuffle_proof":{},"slot_membership_proofs":[{}]}}"#,
            poker_protocol::zk_shuffle::reconstruction::RECONSTRUCTION_PROOF_VERSION,
            ct_vec_to_json(&result.proof.negative_contributions),
            cross_key_json.join(","),
            bayer_groth_proof_to_json(&result.proof.contribution_shuffle_proof),
            slot_json.join(","),
        );

        let s = format!(
            r#"{{"statement":{},"proof":{}}}"#,
            statement_json,
            proof_json
        );
        Ok(json_val_to_jsvalue(s))
    }
}

#[wasm_bindgen]
pub fn compute_aggregate_key(pk_hexes: &str) -> Result<String, JsValue> {
    let pks: Vec<String> = match serde_json::from_str(pk_hexes) {
        Ok(arr) => arr,
        Err(e) => return Err(JsValue::from_str(&format!("JSON error: {}", e))),
    };

    let mut agg = EcPoint::identity();
    for pk_hex in &pks {
        let pk = match hex_to_ecpoint(pk_hex) {
            Ok(p) => p,
            Err(e) => return Err(JsValue::from_str(&e)),
        };
        agg = agg + pk;
    }
    Ok(ecpoint_to_hex(&agg))
}

#[wasm_bindgen]
pub fn encrypt_plaintext(plaintext_hex: &str, pk_hex: &str) -> Result<JsValue, JsValue> {
    let pt = hex_to_ecpoint(plaintext_hex).map_err(|e| JsValue::from_str(&e))?;
    let pk = hex_to_ecpoint(pk_hex).map_err(|e| JsValue::from_str(&e))?;
    let r = Scalar::random(&mut OsRng);
    let ct = ElGamalCiphertext::encrypt(&pt, &pk, &r);
    Ok(json_val_to_jsvalue(ct_to_json(&ct)))
}


/// #16 抗审查动作签名：以牌局身份 SK 对 (table_id, hand_id, seq, action,
/// amount) 签名（Starknet-Poseidon 域分离同族：`zgame.action-sig.v3`，与
/// texas 服务端 `game_action.rs` 验签口径逐字节一致）。返回 `{ r_hex, s_hex }`
/// ——客户端把 `(seq, r_hex, s_hex)` 附在动作消息上；服务端按座位 pk 验签。
/// v3：hand_id 进签名域，签名升级为逐手归属凭证（endorsement 通道已删除）。
///
/// `sk_hex` 为 ClientPlayer 的 sk（32 字节大端 hex，localStorage `sk` 同源）；
/// `hand_id` 为开局广播分配的本手 id。
#[wasm_bindgen]
pub fn sign_action(
    sk_hex: &str,
    table_id: u32,
    hand_id: u32,
    seq: u64,
    action: &str,
    amount: u64,
) -> Result<JsValue, JsValue> {
    // #16：游戏身份 SK 在 Stark curve 上（与座位 pk 同域）
    let sk_bytes = hex::decode(sk_hex).map_err(|e| JsValue::from_str(&format!("sk hex: {e}")))?;
    let sk = <poker_protocol::crypto::curve::StarkCurve as poker_protocol::crypto::curve::Curve>::Scalar::from_canonical_bytes(&sk_bytes)
        .ok_or_else(|| JsValue::from_str("sk out of range"))?;
    let (r_hex, s_hex) = poker_protocol::z_poker::protocol::sign_game_action(
        &sk, table_id, hand_id, seq, action, amount, &mut rand_core::OsRng,
    );
    serde_json::to_value(serde_json::json!({ "r_hex": r_hex, "s_hex": s_hex }))
        .map_err(|e| JsValue::from_str(&format!("serialize error: {e}")))
        .map(|v| serde_wasm_bindgen::to_value(&v).unwrap_or(JsValue::NULL))
}


// =============================================================================
// P1-2 会话委托：VM 层交易签名的会话密钥（2026-09-10）
//
// 与 ElGamal 会话密钥（WasmClientPlayer）平行的第二把会话钥：它是玩家在
// VM/链运行时（TableRuntime）交易签名的**授权锚**——买入时经 vault
// `set_session_tx_pk`（非私密路径玩家 multicall / 私密路径 anonymizer 同笔
// 私交易 `set_session_tx_pk_for`）登记到链上，join 时随 payload 声明、
// 服务端 view 对拍核验。重连只需 localStorage 恢复（get_sk_hex/from_sk），
// 零钱包交互。
//
// 签名核心单一源：poker-protocol-core::tx_schnorr（与 poker_l1
// `signature::stark_scheme` 同一实现）。sig = R_compressed(32B) ‖ s(32B)；
// 域常量 zchain.schnorr.v1 / zchain.schnorr.nonce.v1 见 core——此前
// "必须与 poker_l1 逐字节同步"的本地重声明已删除（漂移面收敛为零）。
// =============================================================================

/// VM 交易会话密钥（随机新鲜钥，与钱包地址零派生关系）。
#[wasm_bindgen]
pub struct WasmTxSession {
    sk: Scalar,
    pk: EcPoint,
}

#[wasm_bindgen]
impl WasmTxSession {
    /// 生成随机会话密钥（进入牌桌前调用一次；sk 存 localStorage）。
    #[wasm_bindgen(constructor)]
    pub fn generate() -> WasmTxSession {
        let sk = Scalar::random(&mut OsRng);
        let pk = base_g() * &sk;
        WasmTxSession { sk, pk }
    }

    /// 从 localStorage 的 sk hex 恢复（重连路径——零钱包交互）。
    pub fn from_sk(sk_hex: &str) -> Result<WasmTxSession, JsValue> {
        let sk = hex_to_scalar(sk_hex).map_err(|e| JsValue::from_str(&e))?;
        let pk = base_g() * &sk;
        Ok(WasmTxSession { sk, pk })
    }

    /// 会话公钥（32B 压缩点 hex）——join payload 的 `sessionTxPk` 字段与
    /// 链上登记 felt 使用同一编码。
    pub fn get_pk_hex(&self) -> String {
        hex::encode(self.pk.compress().as_ref())
    }

    /// 会话私钥 hex（localStorage 持久化）。
    pub fn get_sk_hex(&self) -> String {
        scalar_to_hex(&self.sk)
    }

    /// Stark Schnorr 签名（msg_hash = 32B hex；返回 64B 签名的 hex）——
    /// 消息哈希公式见 poker_l1 `dispatch::tx_message_hash`（客户端须用
    /// 同一公式构造待签哈希）。核心在 poker-protocol-core::tx_schnorr
    /// （与 poker_l1 stark_scheme 同一实现，确定性 nonce + 域分离挑战）。
    pub fn sign(&self, msg_hash_hex: &str) -> Result<String, JsValue> {
        let hash_bytes = hex::decode(msg_hash_hex.trim_start_matches("0x"))
            .map_err(|e| JsValue::from_str(&format!("Invalid msg hash hex: {e}")))?;
        if hash_bytes.len() != 32 {
            return Err(JsValue::from_str("msg hash must be 32 bytes"));
        }
        let mut msg = [0u8; 32];
        msg.copy_from_slice(&hash_bytes);

        let sig = poker_protocol_core::tx_schnorr::sign(&self.sk, &msg);
        Ok(hex::encode(sig))
    }
}

#[cfg(test)]
mod curve_hex_tests {
    use super::*;

    /// 2026-09-07 回归：hex_to_ecpoint 曾按 BLS12-381 时代断言 48 字节，
    /// Stark 压缩点 32 字节 → 浏览器洗牌全挂（2026-09-06 重建 pkg 首次
    /// 把遗留代码编进产物后爆发）。roundtrip 必须闭环。
    #[test]
    fn ecpoint_hex_roundtrip() {
        use poker_protocol::crypto::curve::{Curve, CurveScalar};
        let sk = Scalar::from_u64(12345);
        let p = <DefaultCurve as Curve>::base_g() * sk;
        let hex = ecpoint_to_hex(&p);
        assert_eq!(hex.len(), 64, "32 bytes = 64 hex chars");
        let back = hex_to_ecpoint(&hex).expect("roundtrip");
        assert_eq!(back, p);
    }

    #[test]
    fn ecpoint_hex_rejects_wrong_length() {
        assert!(hex_to_ecpoint(&"00".repeat(48)).is_err(), "BLS-era 48B must be rejected");
        assert!(hex_to_ecpoint(&"00".repeat(33)).is_err(), "bad point rejected");
    }

    /// 2026-09-08 回归：客户端签名 → 服务端验签的全链路（hex 编码穿过
    /// wasm/serde 边界）。线上复现：签名已到达服务端但 verify_action_sig
    /// 失败（hand 1788808419，seq 82 的 check）。
    #[test]
    fn sign_action_verifies_through_hex() {
        let player = ClientPlayer::new();
        let pk_hex = ecpoint_to_hex(&player.pk);
        let sk_hex = scalar_to_hex(&player.sk);
        // 复刻 wasm sign_action 的内部路径（sk hex → scalar → sign）
        let sk_bytes = hex::decode(&sk_hex).expect("sk hex");
        let sk = <Scalar as CurveScalar>::from_canonical_bytes(&sk_bytes).expect("sk range");
        let (r_hex, s_hex) = poker_protocol::z_poker::protocol::sign_game_action(
            &sk, 1, 1788808419, 82, "check", 0, &mut rand_core::OsRng,
        );
        assert!(
            poker_protocol::z_poker::protocol::verify_game_action_hex(
                &pk_hex, 1, 1788808419, 82, "check", 0, &r_hex, &s_hex
            ),
            "sign→verify roundtrip through hex must hold (domain: table_id, hand_id, seq, action, amount)"
        );
    }

/// 跨 crate 已知答案向量（P2-2）：与 poker_l1 stark_scheme 测试同一
    /// sk/msg/期望签名——签名核心已收敛到 poker-protocol-core::tx_schnorr
    /// （2026-09-10），本向量从"防对方漂移"升级为"同一实现的自证"：
    /// wasm 侧接线（hex 边界/类型转发）漂移时在此失败。
    /// sk = hash_to_scalar(b"zgame.tx-vector.kat.v1")。
    #[test]
    fn tx_session_known_answer_vector_matches_poker_l1() {
        let sk_hex = "02d6ef6369a765d8c8d80b9df96637ac2bec0b85e8cb1da3e59aff65c1b9c72c";
        let session = WasmTxSession::from_sk(sk_hex).expect("KAT sk");
        assert_eq!(
            session.get_pk_hex(),
            "82496bd9c700a1c1252d27b5b8063bdeab149411436157dc3dfe1dd29c79faa3",
            "KAT pk mismatch — derivation drifted from poker_l1"
        );
        let sig = session.sign(&hex::encode([0x42u8; 32])).expect("KAT sign");
        assert_eq!(
            sig,
            "80e93d41175f69487f916da094a1cacb0d2b1dfc0c4c5caa386c7263ca78a09e007bfd2b92bf6112390243cc66f4b77fdfd71c03021a1d33c9ccae0543200c42",
            "KAT mismatch — wasm signature space drifted from poker_l1"
        );
    }

    /// P1-2 会话委托：密钥恢复一致 + 签名确定性（与 poker_l1 stark_scheme
    /// 同公式——同 sk 同消息必得同签名，重放/对拍基准）。
    #[test]
    fn tx_session_restore_and_deterministic_sign() {
        let session = WasmTxSession::generate();
        let sk_hex = session.get_sk_hex();
        let pk_hex = session.get_pk_hex();
        let restored = WasmTxSession::from_sk(&sk_hex).expect("restore");
        assert_eq!(restored.get_pk_hex(), pk_hex, "restore derives same pk");

        let msg = [0x42u8; 32];
        let sig1 = session.sign(&hex::encode(msg)).expect("sign");
        let sig2 = restored.sign(&hex::encode(msg)).expect("sign");
        assert_eq!(sig1, sig2, "deterministic nonce: same sk+msg => same sig");
        assert_eq!(sig1.len(), 128, "64-byte signature hex");
        // 不同消息不同签名
        let other = session.sign(&hex::encode([0x43u8; 32])).expect("sign");
        assert_ne!(sig1, other);
    }
}

