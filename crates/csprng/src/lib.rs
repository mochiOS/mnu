#![no_std]
#![deny(unsafe_code)]

use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use zeroize::Zeroize;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Uninitialized,
}

pub struct Csprng {
    inner: Option<ChaCha20Rng>,
}

impl Csprng {
    pub const fn uninitialized() -> Self {
        Self { inner: None }
    }

    pub fn initialize(&mut self, seed: &mut [u8; 32]) {
        self.inner = Some(ChaCha20Rng::from_seed(*seed));
        seed.zeroize();
    }

    pub fn fill(&mut self, destination: &mut [u8]) -> Result<(), Error> {
        let generator = self.inner.as_mut().ok_or(Error::Uninitialized)?;
        generator.fill_bytes(destination);
        Ok(())
    }

    pub fn is_initialized(&self) -> bool {
        self.inner.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_fill_before_initialization() {
        let mut generator = Csprng::uninitialized();
        let mut output = [0u8; 32];
        assert_eq!(generator.fill(&mut output), Err(Error::Uninitialized));
        assert_eq!(output, [0; 32]);
    }

    #[test]
    fn initialized_generator_fills_and_advances() {
        let mut generator = Csprng::uninitialized();
        let mut seed = [0x5a; 32];
        generator.initialize(&mut seed);
        assert_eq!(seed, [0; 32]);
        let mut first = [0u8; 32];
        let mut second = [0u8; 32];
        assert_eq!(generator.fill(&mut first), Ok(()));
        assert_eq!(generator.fill(&mut second), Ok(()));
        assert_ne!(first, [0; 32]);
        assert_ne!(first, second);
    }

    #[test]
    fn same_seed_has_deterministic_stream_for_health_testing() {
        let mut left = Csprng::uninitialized();
        let mut right = Csprng::uninitialized();
        let mut left_seed = [7; 32];
        let mut right_seed = [7; 32];
        left.initialize(&mut left_seed);
        right.initialize(&mut right_seed);
        let mut left_output = [0u8; 64];
        let mut right_output = [0u8; 64];
        assert_eq!(left.fill(&mut left_output), Ok(()));
        assert_eq!(right.fill(&mut right_output), Ok(()));
        assert_eq!(left_output, right_output);
    }
}
