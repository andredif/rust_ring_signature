extern crate clsag;
extern crate curve25519_dalek;

use std::time::{Duration, Instant};
use clsag::member::{Member, generate_signer};
use clsag::clsag::Clsag;
use clsag::signature::Signature;
use clsag::{tests_helper::*, signature};
use clsag::validation;

fn main() {
    // Define setup parameters
    let num_keys = 1;
    let num_voters = 5;
    let msg = b"Bit4Id";


    //Signers collection
    let mut all_signers: Vec<Member> = Vec::new();

    let mut all_voters: Vec<validation::Voter> = Vec::new();


    //Generate all the signers

    for i in 1..=num_voters {
        let start_generating = Instant::now();
        let signer = generate_signer(num_keys);
        let identifier = format!("Voter-{}", i);
        let pubkeys = signer.public_set.to_keys();
        let voter = validation::Voter {identifier: identifier, pub_keys: pubkeys};
        all_signers.push(signer);
        all_voters.push(voter);
        let duration_generating = start_generating.elapsed();
        println!("Key pair generation took {:?} seconds", duration_generating);
    }
    println!("Inital voters are: {:?}", all_voters);
    let json_voters = validation::all_voters_to_string(all_voters);

    let reloaded_voters = validation::str_to_all_voters(&json_voters);
    println!("Reloaded voters are: {:?}", reloaded_voters);

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

            let json_signature = Validation{
                pub_keys : clsag.public_keys(),
                key_images : signature.key_images,
                challenge : signature.challenge,
                responses : signature.responses,
                msg : *msg

            };

            let json_val_str = validation_to_string(json_signature.clone()).unwrap();
            println!("JSON string: {}", json_val_str);

            let mut validation_deserialized = str_to_validation(&json_val_str).unwrap();
            assert_eq!(json_signature, validation_deserialized);

            let verify_signature = Signature{
                challenge: validation_deserialized.challenge,
                responses: validation_deserialized.responses,
                key_images: validation_deserialized.key_images
            };
            let msg = validation_deserialized.msg;
            let start_verifying = Instant::now();
            let res = verify_signature.verify(&mut validation_deserialized.pub_keys, &msg);
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