use serde::{Deserialize, Serialize};
use serde_json::json;
use bincode::{serialize, deserialize};
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use std::convert::TryInto;
use base64;

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct Validation {
    pub msg: [u8; 6],
    pub pub_keys: Vec<Vec<CompressedRistretto>>,
    pub challenge: Scalar,
    pub responses: Vec<Scalar>,
    pub key_images: Vec<CompressedRistretto>
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct JSONValidation {
    pub msg: String,
    pub pub_keys: String,
    pub challenge: String,
    pub responses: String,
    pub key_images: String,
}

pub fn validation_to_json(validation: Validation) -> Result<String, serde_json::Error> {
    let msg = String::from_utf8_lossy(&validation.msg[..]).to_string();
    let pub_keys = serialize(&validation.pub_keys).map(|v| base64::encode(v)).unwrap_or_default();
    let challenge = base64::encode(serialize(&validation.challenge).unwrap_or_default());
    let responses = serialize(&validation.responses).map(|v| base64::encode(v)).unwrap_or_default();
    let key_images = serialize(&validation.key_images).map(|v| base64::encode(v)).unwrap_or_default();

    let json_val = JSONValidation {msg, pub_keys, challenge, responses, key_images};
    serde_json::to_string(&json_val)
}

pub fn json_to_validation(json_str: &str) -> Result<Validation, serde_json::Error> {
    let json_val: JSONValidation = serde_json::from_str(json_str)?;

    let msg = json_val.msg.as_bytes().try_into().unwrap();
    let pub_keys = deserialize(&base64::decode(&json_val.pub_keys).unwrap_or_default()).unwrap_or_default();
    let challenge = deserialize(&base64::decode(&json_val.challenge).unwrap_or_default()).unwrap_or_default();
    let responses = deserialize(&base64::decode(&json_val.responses).unwrap_or_default()).unwrap_or_default();
    let key_images = deserialize(&base64::decode(&json_val.key_images).unwrap_or_default()).unwrap_or_default();

    Ok(Validation {msg, pub_keys, challenge, responses, key_images})
}