extern crate clsag;
extern crate curve25519_dalek;

use std::time::{Duration, Instant};
use clsag::member::{Member, generate_signer};
use clsag::clsag::Clsag;
use clsag::tests_helper::*;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn get_signer() -> Member {
    generate_signer(1)
}