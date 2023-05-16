use serde::{Deserialize, Serialize};
use serde_json::json;
use bincode::{serialize, deserialize};
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use std::convert::TryInto;
use base64;

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct Vote {
    pub msg: [u8; 6],
    pub challenge: Scalar,
    pub responses: Vec<Scalar>,
    pub key_images: Vec<CompressedRistretto>
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct JSONVote {
    pub msg: String,
    pub challenge: String,
    pub responses: String,
    pub key_images: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct Voter {
    pub identifier: String,
    pub pub_keys: Vec<CompressedRistretto>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct JSONVoter {
    pub identifier: String,
    pub pub_keys: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct Poll {
    pub name: String,
    pub voters: Vec<JSONVoter>,
}

pub fn voter_to_json(voter: Voter) -> Result<JSONVoter, serde_json::Error> {
    let pub_keys = serialize(&voter.pub_keys).map(|v| base64::encode(v)).unwrap_or_default();
    let identifier = voter.identifier;
    Ok(JSONVoter { identifier: identifier, pub_keys: pub_keys })
}

pub fn vote_to_json(vote: Vote) -> Result<JSONVote, serde_json::Error> {
    let msg = String::from_utf8_lossy(&vote.msg[..]).to_string();
    let challenge = base64::encode(serialize(&vote.challenge).unwrap_or_default());
    let responses = serialize(&vote.responses).map(|v| base64::encode(v)).unwrap_or_default();
    let key_images = serialize(&vote.key_images).map(|v| base64::encode(v)).unwrap_or_default();

    Ok(JSONVote {msg, challenge, responses, key_images})
}

pub fn vote_to_string(vote: Vote) -> Result<String, serde_json::Error> {
    let json_val = vote_to_json(vote).unwrap();
    serde_json::to_string(&json_val)
}

pub fn voter_to_string(voter: Voter) -> Result<String, serde_json::Error> {
    let json_val = voter_to_json(voter).unwrap();
    serde_json::to_string(&json_val)
}

pub fn all_voters_to_string(voters: Vec<Voter>) -> Result<String, serde_json::Error> {
    let mut json_voters: Vec<JSONVoter> = Vec::new();
    for voter in voters {
        let json_voter = voter_to_json(voter).unwrap();
        json_voters.push(json_voter);
    }
    serde_json::to_string(&json_voters)
}

pub fn str_to_all_voters(json_str: &str) -> Result<Vec<Voter>, serde_json::Error> {
    let json_values: Vec<JSONVoter> = serde_json::from_str(json_str)?;
    let mut voters: Vec<Voter> = Vec::new();
    for json_val in json_values {
        let pub_keys = deserialize(&base64::decode(&json_val.pub_keys).unwrap_or_default()).unwrap_or_default();
        let identifier = json_val.identifier;
        let voter = Voter {identifier: identifier, pub_keys: pub_keys};
        voters.push(voter);
    }

    Ok(voters)
}

pub fn str_to_vote(json_str: &str) -> Result<Vote, serde_json::Error> {
    let json_val: JSONVote = serde_json::from_str(json_str)?;

    let msg = json_val.msg.as_bytes().try_into().unwrap();
    let challenge = deserialize(&base64::decode(&json_val.challenge).unwrap_or_default()).unwrap_or_default();
    let responses = deserialize(&base64::decode(&json_val.responses).unwrap_or_default()).unwrap_or_default();
    let key_images = deserialize(&base64::decode(&json_val.key_images).unwrap_or_default()).unwrap_or_default();

    Ok(Vote {msg, challenge, responses, key_images})
}

pub fn str_to_voter(json_str: &str) -> Result<Voter, serde_json::Error> {
    let json_val: JSONVoter = serde_json::from_str(json_str)?;
    let pub_keys = deserialize(&base64::decode(&json_val.pub_keys).unwrap_or_default()).unwrap_or_default();
    let identifier = json_val.identifier;

    Ok(Voter {identifier: identifier, pub_keys: pub_keys})
}