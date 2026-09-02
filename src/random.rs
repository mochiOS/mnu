//! Kernel cryptographic random generator.

use mnu_csprng::Csprng;
use sha2::{Digest, Sha256};
use spin::Mutex;

const RDRAND_SEED_WORDS: usize = 8;

static CSPRNG: Mutex<Csprng> = Mutex::new(Csprng::uninitialized());

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RandomError {
    HardwareUnavailable,
    HardwareHealthFailure,
    Uninitialized,
}

pub fn initialize(firmware_seed: &[u8; 32], firmware_seed_valid: bool) -> Result<(), RandomError> {
    let mut hasher = Sha256::new();
    hasher.update(b"mnu kernel CSPRNG seed v1");

    if firmware_seed_valid {
        hasher.update(b"UEFI RNG");
        hasher.update(firmware_seed);
    }

    let mut previous = None;
    let mut hardware_samples = 0usize;
    while hardware_samples < RDRAND_SEED_WORDS {
        let Some(sample) = crate::cpu::hw_random_u64() else {
            break;
        };
        if previous == Some(sample) {
            return Err(RandomError::HardwareHealthFailure);
        }
        previous = Some(sample);
        hasher.update(sample.to_le_bytes());
        hasher.update(crate::cpu::rdtsc().to_le_bytes());
        hardware_samples += 1;
    }
    if !firmware_seed_valid && hardware_samples != RDRAND_SEED_WORDS {
        return Err(RandomError::HardwareUnavailable);
    }

    // RDRAND is not used as the seed verbatim. Independent boot-varying state is
    // mixed through SHA-256 before the ChaCha20 DRBG is initialized.
    hasher.update(crate::cpu::boot_entropy_u64().to_le_bytes());
    hasher.update((core::ptr::addr_of!(CSPRNG) as usize).to_le_bytes());
    let mut seed: [u8; 32] = hasher.finalize().into();
    CSPRNG.lock().initialize(&mut seed);
    Ok(())
}

pub fn fill(destination: &mut [u8]) -> Result<(), RandomError> {
    CSPRNG
        .lock()
        .fill(destination)
        .map_err(|_| RandomError::Uninitialized)
}
