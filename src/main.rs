extern crate clsag;
extern crate curve25519_dalek;

use std::time::{Duration, Instant};
use clsag::member::{Member, generate_signer};
use clsag::clsag::Clsag;
use clsag::signature::Signature;
use clsag::{tests_helper::*, signature};
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use serde::{Deserialize, Serialize};
use serde_with;
use bincode::{deserialize, serialize};
use clsag::validation::{Validation, json_to_validation, validation_to_json};

fn main() {
    // Define setup parameters
    let num_keys = 1;
    let num_voters = 5;
    let msg = b"Bit4Id";


    //Signers collection
    let mut all_signers: Vec<Member> = Vec::new();


    //Generate all the signers

    for _ in 0..num_voters {
        let start_generating = Instant::now();
        let signer = generate_signer(num_keys);
        all_signers.push(signer);
        let duration_generating = start_generating.elapsed();
        println!("Key pair generation took {:?} seconds", duration_generating);
    }

    for jack in 0..5 {
        for signer in all_signers.iter() {
            // Define a clsag object which will be used to create a signature
            let mut clsag = Clsag::new();
            // Generate and add decoys
            for member in &all_signers {
                let curr_member = member.clone();
                match curr_member.is_current_signer(signer.hashed_pubkey_basepoint){
                    true =>{
                        clsag.add_member(curr_member);
                    }
                    false =>{
                        let decoy = Member::new_member_with_responses(curr_member.public_set);
                        clsag.add_member(decoy);
                    }
                }
            }

            let start_signing = Instant::now();
            let signature = clsag.sign(msg).unwrap();
            let duration_signing = start_signing.elapsed();
            println!("Applying signature took {:?} seconds", duration_signing);
            println!("{:#?}", signer.hashed_pubkey_basepoint);
            println!("{:#?}", signature.key_images);
            println!("challenges\n{:?}", signature.challenge);
            // let json_signature = Validation{
            //     pub_keys : clsag.public_keys(),
            //     key_images : signature.key_images,
            //     challenge : signature.challenge,
            //     responses : signature.responses,
            //     msg : *msg

            // };

            let json_pub_keys = clsag.public_keys();
            let json_key_images = signature.key_images;
            let json_challenge = signature.challenge;
            let json_responses = signature.responses;
            let json_msg = *msg;

            // };



            // let mut json_path = String::from("../data.json");
            // json_path.insert_str(7, &jack.to_string());
            let serialized_pub_keys = serialize(&json_pub_keys).unwrap();
            println!("serialized_pub_keys = {:?}", serialized_pub_keys);
            let serialized_key_images = serialize(&json_key_images).unwrap();
            // println!("serialized_key_images = {:?}", serialized_key_images);
            let serialized_challenge = serialize(&json_challenge).unwrap();
            // println!("serialized_challenge = {:?}", serialized_challenge);
            let serialized_responses = serialize(&json_responses).unwrap();
            // println!("serialized_responses = {:?}", serialized_responses);
            let serialized_msg = serialize(&json_msg).unwrap();
            // println!("serialized_msg = {:?}", serialized_msg);
            // std::fs::write(json_path, serde_json::to_string(&json).expect("error"));


            // let mut data_received = std::fs::read_to_string(json_path).expect("error");
            // println!("{:?}", data_received);
            let mut deserialized_pub_keys : Vec<Vec<CompressedRistretto>> = deserialize::<Vec<Vec<CompressedRistretto>>>(&serialized_pub_keys).unwrap();
            println!("{:?}", deserialized_pub_keys);
            let mut deserialized_key_images : Vec<CompressedRistretto> = deserialize::<Vec<CompressedRistretto>>(&serialized_key_images).unwrap();
            println!("{:?}", deserialized_key_images);
            let mut deserialized_challenge : Scalar = deserialize::<Scalar>(&serialized_challenge).unwrap();
            println!("{:?}", deserialized_challenge);
            let mut deserialized_responses : Vec<Scalar> = deserialize::<Vec<Scalar>>(&serialized_responses).unwrap();
            println!("{:?}", deserialized_responses);
            let mut deserialized_msg : [u8;6] = deserialize::<[u8;6]>(&serialized_msg).unwrap();
            println!("{:?}", deserialized_msg);
            let verify_signature = Signature{
                challenge: deserialized_challenge,
                responses: deserialized_responses,
                key_images: deserialized_key_images
            };
            let msg = deserialized_msg;
            let start_verifying = Instant::now();
            let res = verify_signature.verify(&mut deserialized_pub_keys, &msg);
            let duration_verifying = start_verifying.elapsed();
            println!("Verifying signature took {:?} seconds", duration_verifying);


        }
    }
}
// fn main() {
//     let validation = Validation {
//         msg: [0u8; 6],
//         pub_keys: vec![vec![CompressedRistretto([0u8; 32])]],
//         challenge: Scalar::zero(),
//         responses: vec![Scalar::zero()],
//         key_images: vec![CompressedRistretto([0u8; 32])]
//     };
//     println!("Validation {:?}", validation);

//     let json_val_str = validation_to_json(validation.clone()).unwrap();
//     println!("JSON string: {}", json_val_str);

//     let validation_deserialized = json_to_validation(&json_val_str).unwrap();
//     assert_eq!(validation, validation_deserialized);
// }