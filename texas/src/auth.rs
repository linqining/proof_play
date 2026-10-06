use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub user: ClaimUser,
    pub exp: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ClaimUser {
    pub id: String,
}

pub fn create_token(user_id: &str, secret: &str, expires_in_ms: u64) -> Result<String, jsonwebtoken::errors::Error> {
    let exp = chrono::Utc::now().timestamp() as usize + (expires_in_ms / 1000) as usize;
    let claims = Claims {
        user: ClaimUser { id: user_id.to_string() },
        exp,
    };
    encode(&Header::default(), &claims, &EncodingKey::from_secret(secret.as_bytes()))
}

pub fn verify_token(token: &str, secret: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
    decode::<Claims>(token, &DecodingKey::from_secret(secret.as_bytes()), &Validation::default())
        .map(|data| data.claims)
}
