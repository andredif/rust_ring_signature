use serde::{Deserialize, Serialize};
use bincode::{serialize, deserialize};
use curve25519_dalek::ristretto::{CompressedRistretto};
use curve25519_dalek::scalar::Scalar;
use std::convert::TryInto;
use base64;

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct Vote {
    pub msg: String,
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
    let pub_keys = pub_keys_to_string(voter.pub_keys).unwrap();
    let identifier = voter.identifier;
    Ok(JSONVoter { identifier: identifier, pub_keys: pub_keys })
}

pub fn vote_to_json(vote: Vote) -> Result<JSONVote, serde_json::Error> {
    let this_msg = vote.msg.clone();
    let challenge = base64::encode(serialize(&vote.challenge).unwrap_or_default());
    let responses = serialize(&vote.responses).map(|v| base64::encode(v)).unwrap_or_default();
    let key_images = serialize(&vote.key_images).map(|v| base64::encode(v)).unwrap_or_default();

    Ok(JSONVote {
        msg:this_msg,
        challenge: challenge,
        responses: responses,
        key_images: key_images
    })
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
        let pub_keys = string_to_pub_keys(json_val.pub_keys).unwrap();
        let identifier = json_val.identifier;
        let voter = Voter {identifier: identifier, pub_keys: pub_keys};
        voters.push(voter);
    }

    Ok(voters)
}

pub fn str_to_vote(json_str: &str) -> Result<Vote, serde_json::Error> {
    let json_val: JSONVote = serde_json::from_str(json_str)?;

    let msg = json_val.msg.clone();
    let challenge = deserialize(&base64::decode(&json_val.challenge).unwrap_or_default()).unwrap_or_default();
    let responses = deserialize(&base64::decode(&json_val.responses).unwrap_or_default()).unwrap_or_default();
    let key_images = deserialize(&base64::decode(&json_val.key_images).unwrap_or_default()).unwrap_or_default();

    Ok(Vote {msg, challenge, responses, key_images})
}

pub fn str_to_voter(json_str: &str) -> Result<Voter, serde_json::Error> {
    let json_val: JSONVoter = serde_json::from_str(json_str)?;
    let pub_keys = string_to_pub_keys(json_val.pub_keys).unwrap();
    let identifier = json_val.identifier;

    Ok(Voter {identifier: identifier, pub_keys: pub_keys})
}

pub fn string_to_pub_keys(pubkeys: String) -> Result<Vec<CompressedRistretto>, serde_json::Error> {
    Ok(deserialize(&base64::decode(&pubkeys).unwrap_or_default()).unwrap_or_default())
}

pub fn pub_keys_to_string(pub_keys: Vec<CompressedRistretto>) -> Result<String, serde_json::Error> {
    Ok(serialize(&pub_keys).map(|v| base64::encode(v)).unwrap_or_default())
}