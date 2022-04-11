use ethers_core::types::H160;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
pub struct AuthRequest {
    pub message: String,
    pub signature: String,
}

#[derive(Deserialize, Serialize, Debug)]
pub enum AuthState {
    Authorized(AuthMessage),
    Unauthorized(UnauthorizedMessage),
}

// We copy the implementation of siwe::Message here to derive Serialization and Debug
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct AuthMessage {
    pub domain: String,
    pub address: String,
    pub statement: Option<String>,
    pub uri: String,
    pub version: String,
    pub chain_id: String,
    pub nonce: String,
    pub issued_at: u64,
    pub expiration_time: Option<u64>,
    pub resources: Vec<String>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct UnauthorizedMessage {
    pub nonce: String,
    pub expiration_time: u64,
}

impl From<siwe::Message> for AuthMessage {
    fn from(message: siwe::Message) -> Self {
        AuthMessage {
            domain: message.domain.as_str().to_string(),
            address: format!("{:?}", H160(message.address)),
            statement: message.statement,
            uri: message.uri.to_string(),
            version: format!("{}", message.version as u64),
            chain_id: message.chain_id.to_string(),
            nonce: message.nonce.to_string(),
            issued_at: (message.issued_at.as_ref().timestamp() as u64),
            expiration_time: message
                .expiration_time
                .map(|t| t.as_ref().timestamp() as u64),
            resources: message.resources.iter().map(|r| r.to_string()).collect(),
        }
    }
}
