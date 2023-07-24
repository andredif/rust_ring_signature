extern crate curve25519_dalek;
use std::time::{Instant};
use rust_ring_signature::member::{Member, signer_from_private_key};
use rust_ring_signature::clsag::Clsag;
use rust_ring_signature::signature::Signature;
use rust_ring_signature::validation;
use std::fs::File;
use std::io::Write;

fn main() {
    // Define setup parameters
    let num_keys = 1;
    let num_voters = 5;
    let msg = "Bit4Id";


    //Signers collection
    let mut all_signers: Vec<Member> = Vec::new();

    let mut all_voters: Vec<validation::Voter> = Vec::new();

    let mut all_private_keys  = [
        "634c1052d410d1e71b1ab6349d808962571231c2bcf8e284655a148ce393f790",
        "b1250fc6b7f887e79bddbf067110f77409319c09f3e41fb817cbc87a6473abcd",
        "3b492a9f2a1542a518610bbe17a74608972c66f976f469cc1563ea56a12d902e",
        "ee96005f67479a572b6e76f4a19374d483cb230004ed6dd0fceb5ec167d9bbe2",
        "43b0dbbf5864abf2a8a7f1ca79abe32b94d5d566e07c87e689544631add865f2"];

    let mut all_choices = [ "a", "b", "Henry King", "element", "a"];
    let mut all_voters_string_singles = Vec::new();
    let mut all_votes = Vec::new();
    // let mut decompressed_voters: Vec<Vec<RistrettoPoint>> = Vec::new();
    //Generate all the signers

    for i in 0..num_voters {
        let start_generating = Instant::now();

        //Generate Member
        let signer = signer_from_private_key(all_private_keys[i]).unwrap();

        //Generate Voter
        let identifier = format!("Voter-{}", i);
        let pubkeys = signer.public_set.to_keys();
        let voter = validation::Voter {identifier: identifier.clone(), pub_keys: pubkeys.clone()};

        //Insert Member and Voter in arrays
        all_signers.push(signer.clone());
        all_voters.push(voter.clone());

        let decoy_1 = Member::new_decoy_from_compressed_ristretto(pubkeys.clone());
        let pubkeys_decoy = decoy_1.public_set.to_keys();

        assert_eq!(signer.public_set.0, decoy_1.public_set.0);
        assert_eq!(pubkeys, pubkeys_decoy);
        println!("Signer original pubkeys are{:?}", signer.public_set.to_keys());
        let voter = validation::Voter {identifier: identifier.clone(), pub_keys: pubkeys.clone()};

        let new_voter_string = validation::voter_to_string(voter.clone()).unwrap();
        let new_voter_json = validation::voter_to_json(voter.clone()).unwrap();
        println!("Voter string is {:?}", new_voter_json);
        all_voters_string_singles.push(new_voter_string);
        let converted_pub_keys = validation::string_to_pub_keys(new_voter_json.pub_keys).unwrap();
        println!("Signer converted pubkeys are{:?}", converted_pub_keys);


        let duration_generating = start_generating.elapsed();
        println!("Key pair generation took {:?} seconds", duration_generating);
    }

    let all_voters_string = validation::all_voters_to_string(all_voters).unwrap();
    let all_voters_reloaded = validation::str_to_all_voters(&all_voters_string).unwrap();
    // println!("Inital voters are: {:?}", all_voters);
    // let json_voters = validation::all_voters_to_string(all_voters).unwrap();

    // let reloaded_voters = validation::str_to_all_voters(&json_voters);
    // println!("Reloaded voters are: {:?}", reloaded_voters);

    for (i, signer) in all_signers.iter().enumerate() {
        // Define a clsag object which will be used to create a signature
        let mut clsag = Clsag::new();
        clsag.add_member(signer.clone());

        let mut reloaded_clsag = Clsag::new();
        reloaded_clsag.add_member(signer.clone());

        // Generate and add decoys canonical clsag
        for member in &all_signers {
            let curr_member = member.clone();
            match curr_member.is_current_signer(signer.hashed_pubkey_basepoint){
                true =>{
                    continue;
                }
                false =>{
                    let decoy = Member::new_member_with_responses(curr_member.public_set);
                    clsag.add_member(decoy);
                }
            }
        }
        println!("Pubkeys are: {:?}",clsag.public_keys());
        // Generate and add decoys reloaded clsag
        for voter in &all_voters_reloaded {
            let curr_voter = Member::new_decoy_from_compressed_ristretto(voter.pub_keys.clone());
            match curr_voter.is_current_signer(signer.hashed_pubkey_basepoint){
                true =>{
                    continue;
                }
                false =>{
                    reloaded_clsag.add_member(curr_voter);
                }
            }
        }

        let start_signing = Instant::now();
        let signature = clsag.sign(msg).unwrap();
        let duration_signing = start_signing.elapsed();
        println!("Applying signature took {:?} seconds", duration_signing);
        println!("{:?}", signature.responses);

        let start_signing = Instant::now();
        let reloaded_signature = reloaded_clsag.sign(msg).unwrap();
        let duration_signing = start_signing.elapsed();
        println!("Applying signature took {:?} seconds", duration_signing);

        // println!("{:#?}", signer.hashed_pubkey_basepoint);
        // println!("{:#?}", signature.key_images);
        // println!("challenges\n{:?}", signature.challenge);

        let json_signature = validation::Vote{
            key_images : signature.key_images,
            challenge : signature.challenge,
            responses : signature.responses,
            msg : all_choices[i].to_string()

        };

        let reloaded_json_signature = validation::Vote{
            key_images : reloaded_signature.key_images,
            challenge : reloaded_signature.challenge,
            responses : reloaded_signature.responses,
            msg : msg.to_string()

        };

        let json_val_str = validation::vote_to_string(json_signature.clone()).unwrap();
        all_votes.push(json_val_str.clone());
        println!("JSON string: {}", json_val_str);

        let mut validation_deserialized = validation::str_to_vote(&json_val_str).unwrap();
        println!("Vote deserialized is: {:?}", validation_deserialized);
        assert_eq!(json_signature, validation_deserialized);

        let reloaded_json_val_str = validation::vote_to_string(reloaded_json_signature.clone()).unwrap();
        println!("JSON string: {}", json_val_str);

        let mut reloaded_validation_deserialized = validation::str_to_vote(&reloaded_json_val_str).unwrap();
        assert_eq!(json_signature, validation_deserialized);

        let verify_signature = Signature{
            challenge: validation_deserialized.challenge,
            responses: validation_deserialized.responses,
            key_images: validation_deserialized.key_images
        };
        let msg = validation_deserialized.msg;

        let reloaded_verify_signature = Signature{
            challenge: reloaded_validation_deserialized.challenge,
            responses: reloaded_validation_deserialized.responses,
            key_images: reloaded_validation_deserialized.key_images
        };
        let msg = reloaded_validation_deserialized.msg;

        let start_verifying = Instant::now();
        let first_res = verify_signature.verify(&mut clsag.public_keys(), &msg).unwrap();
        let duration_verifying = start_verifying.elapsed();
        println!("Verifying signature took {:?} seconds with result {:?}", duration_verifying, first_res);

        let start_verifying = Instant::now();
        let second_res = verify_signature.verify(&mut reloaded_clsag.public_keys(), &msg).unwrap();
        let duration_verifying = start_verifying.elapsed();
        println!("Verifying signature took {:?} seconds with result {:?}", duration_verifying, second_res);

        let start_verifying = Instant::now();
        let third_res = reloaded_verify_signature.verify(&mut reloaded_clsag.public_keys(), &msg).unwrap();
        let duration_verifying = start_verifying.elapsed();
        println!("Verifying signature took {:?} seconds with result {:?}", duration_verifying, third_res);

        let start_verifying = Instant::now();
        let fourth_res = reloaded_verify_signature.verify(&mut clsag.public_keys(), &msg).unwrap();
        let duration_verifying = start_verifying.elapsed();
        println!("Verifying signature took {:?} seconds with result {:?}", duration_verifying, fourth_res);


    }
    println!("validation test {:?}",  validation::string_to_pub_keys("AQAAAAAAAAAgAAAAAAAAAEB/TFYIk02Fz1T6Yt4H3A3D4pYAMVE3h7rHJj5I/iQu".to_string()).unwrap());
    println!("{:?}",all_votes );
    println!("{:?}",all_voters_string_singles );
}
