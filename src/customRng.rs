use getrandom::getrandom;
use rand_core::{CryptoRng, RngCore, Error, impls};

/// use rand_core::{RngCore, CustomRng};
///
/// let mut key = [0u8; 16];
/// OsRng.fill_bytes(&mut key);
/// let random_u64 = OsRng.next_u64();
/// ```
///
/// [getrandom]: https://crates.io/crates/getrandom
#[derive(Clone, Copy, Debug, Default)]
pub struct CustomRng;

impl CryptoRng for CustomRng {}

impl RngCore for CustomRng {
    fn next_u32(&mut self) -> u32 {
        impls::next_u32_via_fill(self)
    }

    fn next_u64(&mut self) -> u64 {
        impls::next_u64_via_fill(self)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        if let Err(e) = self.try_fill_bytes(dest) {
            panic!("Error: {}", e);
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        getrandom(dest).unwrap();
        Ok(())
    }
}