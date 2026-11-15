//! Early native ASLR seed, available before the heap/CSPRNG exists.
use core::sync::atomic::{AtomicU64, Ordering};
use sha2::{Digest, Sha256};

static BOOT_ENTROPY: AtomicU64 = AtomicU64::new(0);

fn initialize() -> Option<u64> {
    let info = crate::smp::boot_info()?;
    if info.validate().is_err() {
        return None;
    }
    let mut hash = Sha256::new();
    hash.update(b"mnu ARM boot entropy v1");
    let firmware = info.entropy_seed_valid == 1 && info.entropy_seed != [0; 32];
    if firmware {
        hash.update(info.entropy_seed);
    }
    let mut samples = 0;
    let mut previous = None;
    for _ in 0..8 {
        let Some(word) = super::hw_random_u64() else {
            break;
        };
        if previous == Some(word) {
            return None;
        }
        previous = Some(word);
        hash.update(word.to_le_bytes());
        samples += 1;
    }
    if !firmware && samples != 8 {
        return None;
    }
    hash.update(crate::arch::counter::timestamp().to_le_bytes());
    let digest = hash.finalize();
    let mut bytes = [0; 8];
    bytes.copy_from_slice(&digest[..8]);
    // Zero is the unpublished sentinel; the digest still supplies the seed.
    Some(u64::from_le_bytes(bytes).max(1))
}

/// Retain a boot-wide seed. A counter, address or fixed constant cannot replace
/// unavailable firmware/hardware entropy. Boot fails closed in that case.
pub fn boot_entropy_u64() -> u64 {
    let cached = BOOT_ENTROPY.load(Ordering::Acquire);
    if cached != 0 {
        return cached;
    }
    let Some(seed) = initialize() else {
        crate::error!("ARM boot requires healthy firmware or hardware entropy");
        crate::arch::halt();
    };
    match BOOT_ENTROPY.compare_exchange(0, seed, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => seed,
        Err(selected) => selected,
    }
}
