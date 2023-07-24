use crate::clsag::calc_aggregation_coefficients;
use crate::constants::BASEPOINT;
use crate::member::compute_challenge_ring;
use crate::transcript::TranscriptProtocol;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::VartimeMultiscalarMul;
use merlin::Transcript;
use sha2::Sha512;

#[derive(Debug)]
pub struct Signature {
    pub challenge: Scalar,
    pub responses: Vec<Scalar>,
    pub key_images: Vec<CompressedRistretto>,
}

#[derive(Debug)]
pub enum Error {
    // This error occurs if the signature contains an amount of public keys
    // that does not match the number of public keys
    IncorrectNumOfPubKeys,
    // This error occurs when either one of the key images supplied cannot be decompressed
    BadKeyImages,
    // This error occurs when the calculated challenge is different from the challenge in the signature
    ChallengeMismatch,
    // This error occurs when the point cannot be correctly decompressed
    BadPoint,
    // This error occurs when an underlying error from the member package occurs
    MemberError(String),
}

impl From<crate::member::Error> for Error {
    fn from(e: crate::member::Error) -> Error {
        let err_string = format!(" underlying member error {:?}", e);
        Error::MemberError(err_string)
    }
}

impl Signature {
    pub fn verify<T: AsRef<[u8]>>(
        &self,
        public_keys: &mut Vec<Vec<CompressedRistretto>>,
        original_msg: T,
    ) -> Result<String, Error> {
        // Skip subgroup check as ristretto points have co-factor 1.
        let msg: &[u8] = original_msg.as_ref();
        let num_responses = self.responses.len();
        let num_pubkey_sets = public_keys.len();

        // -- Check that we have the correct amount of public keys
        if num_pubkey_sets != num_responses {
            println!("IncorrectNumOfPubKeys");
            return Err(Error::IncorrectNumOfPubKeys);
        }

        let pubkey_matrix_bytes: Vec<u8> = self.pubkeys_to_bytes(public_keys);

        // Calculate aggregation co-efficients
        let agg_coeffs = calc_aggregation_coefficients(&pubkey_matrix_bytes, &self.key_images, msg);

        let mut challenge = self.challenge.clone();
        for (pub_keys, response) in public_keys.iter().zip(self.responses.iter()) {
            let first_pubkey = pub_keys[0];
            let hashed_pubkey = RistrettoPoint::hash_from_bytes::<Sha512>(first_pubkey.as_bytes());
            println!("now printing elements to calculate the challenge");
            println!("Pub keys are: {:?}", pub_keys);
            println!("Challenge is: {:?}", challenge);
            println!("Key images are: {:?}", self.key_images);
            println!("Response is: {:?}", response);
            println!("Agg coeffs are: {:?}", agg_coeffs);
            println!("Hashed pubkey is: {:?}", hashed_pubkey);
            println!("Pubkey matrix bytes are: {:?}", pubkey_matrix_bytes);

            challenge = compute_challenge_ring(
                pub_keys,
                &challenge,
                &self.key_images,
                response,
                &agg_coeffs,
                &hashed_pubkey,
                &pubkey_matrix_bytes,
            );
        }
        println!("Self challenge is: {:?}", self.challenge);
        println!("Calculated challenge is: {:?}", challenge);
        if self.challenge != challenge {
            println!("ChallengeMismatch");
            return Err(Error::ChallengeMismatch);
        }

        Ok("Valid signature".to_string())
    }

    pub fn optimised_verify(
        &self,
        public_keys: &mut Vec<Vec<CompressedRistretto>>,
        msg: &[u8],
    ) -> Result<(), Error> {
        // Skip subgroup check as ristretto points have co-factor 1.

        let num_responses = self.responses.len();
        let num_pubkey_sets = public_keys.len();

        // -- Check that we have the correct amount of public keys
        if num_pubkey_sets != num_responses {
            return Err(Error::IncorrectNumOfPubKeys);
        }

        // Calculate all response * BASEPOINT
        let response_points: Vec<RistrettoPoint> = self
            .responses
            .iter()
            .map(|response| response * BASEPOINT)
            .collect();

        // calculate all response * H(signingKeys)
        let response_hashed_points: Vec<RistrettoPoint> = self
            .responses
            .iter()
            .zip(public_keys.iter())
            .map(|(response, pub_keys)| {
                let first_pubkey = pub_keys[0];
                let hashed_pubkey =
                    RistrettoPoint::hash_from_bytes::<Sha512>(first_pubkey.as_bytes());

                response * hashed_pubkey
            })
            .collect();

        // compute the public key bytes
        let pubkey_matrix_bytes = self.pubkeys_to_bytes(public_keys);

        // Calculate aggregation co-efficients
        let agg_coeffs = calc_aggregation_coefficients(&pubkey_matrix_bytes, &self.key_images, msg);

        let mut challenge = self.challenge.clone();

        for ((resp_point, resp_hashed_point), pub_keys) in response_points
            .iter()
            .zip(response_hashed_points.iter())
            .zip(public_keys.iter())
        {
            let challenge_agg_coeffs: Vec<Scalar> =
                agg_coeffs.iter().map(|ac| ac * &challenge).collect();

            let mut l_i = RistrettoPoint::optional_multiscalar_mul(
                &challenge_agg_coeffs,
                pub_keys.iter().map(|pt| pt.decompress()),
            )
            .ok_or(Error::BadPoint)?;
            l_i = l_i + resp_point;

            let mut r_i = RistrettoPoint::optional_multiscalar_mul(
                &challenge_agg_coeffs,
                self.key_images.iter().map(|pt| pt.decompress()),
            )
            .ok_or(Error::BadPoint)?;
            r_i = r_i + resp_hashed_point;

            let mut transcript = Transcript::new(b"clsag");
            transcript.append_message(b"", &pubkey_matrix_bytes);
            transcript.append_point(b"", &l_i);
            transcript.append_point(b"", &r_i);

            challenge = transcript.challenge_scalar(b"");
        }

        if challenge != self.challenge {
            return Err(Error::ChallengeMismatch);
        }

        Ok(())
    }

    fn pubkeys_to_bytes(&self, pubkey_matrix: &Vec<Vec<CompressedRistretto>>) -> Vec<u8> {
        let mut bytes: Vec<u8> =
            Vec::with_capacity(self.key_images.len() * self.responses.len() * 64);
        for i in 0..pubkey_matrix.len() {
            let pubkey_bytes: Vec<u8> = pubkey_matrix[i]
                .iter()
                .map(|pubkey| pubkey.to_bytes().to_vec())
                .flatten()
                .collect();
            bytes.extend(pubkey_bytes);
        }
        bytes
    }

}


// #[cfg(test)]
// mod test {
//     extern crate test;
//     use test::Bencher;

//     use crate::tests_helper::*;
//     use rand::seq::SliceRandom;
//     use rand::thread_rng;

//     #[test]
//     fn test_verify() {
//         let num_keys = 1;
//         let num_decoys = 1;
//         let msg = b"hello world";

//         let mut clsag = generate_clsag_with(num_decoys, num_keys);
//         clsag.add_member(generate_signer(num_keys));
//         let sig = clsag.sign(msg).unwrap();
//         let mut pub_keys = clsag.public_keys();

//         let expected_pubkey_bytes = clsag.public_keys_bytes();
//         let have_pubkey_bytes = sig.pubkeys_to_bytes(&pub_keys);

//         assert_eq!(expected_pubkey_bytes, have_pubkey_bytes);
//         assert!(sig.optimised_verify(&mut pub_keys, msg).is_ok());
//     }

//     #[test]
//     fn test_verify_fail_shuffle_keys() {
//         let num_keys = 2;
//         let num_decoys = 11;
//         let msg = b"hello world";

//         let mut clsag = generate_clsag_with(num_decoys, num_keys);
//         clsag.add_member(generate_signer(num_keys));
//         let sig = clsag.sign(msg).unwrap();
//         let mut pub_keys = clsag.public_keys();

//         // shuffle public key ordering
//         pub_keys.shuffle(&mut thread_rng());
//         assert!(sig.optimised_verify(&mut pub_keys, msg).is_err());
//     }
//     #[test]
//     fn test_verify_fail_incorrect_num_keys() {
//         let num_keys = 2;
//         let num_decoys = 11;
//         let msg = b"hello world";

//         let mut clsag = generate_clsag_with(num_decoys, num_keys);
//         clsag.add_member(generate_signer(num_keys));
//         let sig = clsag.sign(msg).unwrap();
//         let mut pub_keys = clsag.public_keys();

//         // Add extra key
//         let extra_key = generate_rand_compressed_points(num_keys);
//         pub_keys.push(extra_key);
//         assert!(sig.optimised_verify(&mut pub_keys, msg).is_err());

//         // remove the extra key and test should pass
//         pub_keys.remove(pub_keys.len() - 1);
//         assert!(sig.optimised_verify(&mut pub_keys, msg).is_ok());

//         // remove another key and tests should fail
//         pub_keys.remove(pub_keys.len() - 1);
//         assert!(sig.optimised_verify(&mut pub_keys, msg).is_err());
//     }

//     macro_rules! param_bench_verify {
//         ($func_name: ident,$num_keys:expr, $num_decoys :expr) => {
//             #[bench]
//             fn $func_name(b: &mut Bencher) {
//                 let num_keys = $num_keys;
//                 let num_decoys = $num_decoys;
//                 let msg = b"hello world";

//                 let mut clsag = generate_clsag_with(num_decoys, num_keys);
//                 clsag.add_member(generate_signer(num_keys));
//                 let sig = clsag.sign(msg).unwrap();
//                 let mut pub_keys = clsag.public_keys();

//                 b.iter(|| sig.optimised_verify(&mut pub_keys, msg));
//             }
//         };
//     }

//     param_bench_verify!(bench_verify_2, 2, 2);
//     param_bench_verify!(bench_verify_4, 2, 3);
//     param_bench_verify!(bench_verify_6, 2, 5);
//     param_bench_verify!(bench_verify_8, 2, 7);
//     param_bench_verify!(bench_verify_11, 2, 10);
//     param_bench_verify!(bench_verify_16, 2, 15);
//     param_bench_verify!(bench_verify_32, 2, 31);
//     param_bench_verify!(bench_verify_64, 2, 63);
//     param_bench_verify!(bench_verify_128, 2, 127);
//     param_bench_verify!(bench_verify_256, 2, 255);
//     param_bench_verify!(bench_verify_512, 2, 511);
// }
