//! Relocate real target ELF bytes through the production userspace loader.
//! Tiny independent readers below only inspect fixture/output program headers;
//! they implement no symbol resolution, relocation or native mapping policy.
use crate::{check, emit};
use core::ptr::addr_of_mut;
use mochios_posix_client::{
    elf_launch::Image,
    pie::{
        link_scope::{Object, Scope},
        Pie,
    },
    static_tls::modules::Plan,
};

const SOURCE: &[u8] = include_bytes!(env!("MNU_ARM_ELF_FIXTURE"));
static mut OUTPUT: [u8; 65536] = [0; 65536];
static mut INVALID: [u8; 65536] = [0; 65536];

fn word(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
}
fn symbol(image: &Pie<'_>, name: &[u8]) -> u64 {
    let (_, symbols, strings) = image.inspection();
    for entry in symbols.chunks_exact(24) {
        let at = u32::from_le_bytes(entry[..4].try_into().unwrap()) as usize;
        if strings.get(at..).and_then(|s| s.split(|b| *b == 0).next()) == Some(name) {
            return word(entry, 8);
        }
    }
    crate::fail("fixture symbol absent")
}
fn file_address(bytes: &[u8], address: u64, length: usize) -> usize {
    let count = u16::from_le_bytes(bytes[56..58].try_into().unwrap()) as usize;
    let table = word(bytes, 32) as usize;
    for i in 0..count {
        let ph = &bytes[table + i * 56..table + (i + 1) * 56];
        if u32::from_le_bytes(ph[..4].try_into().unwrap()) == 1 {
            let base = word(ph, 16);
            if address >= base && address - base + length as u64 <= word(ph, 32) {
                return (word(ph, 8) + address - base) as usize;
            }
        }
    }
    crate::fail("fixture address absent")
}

pub fn run() {
    const BIAS: u64 = 0x100_0000;
    let image = Pie::parse_object(SOURCE).unwrap_or_else(|_| crate::fail("ARM ELF parse"));
    let values = symbol(&image, b"values");
    let pointer = symbol(&image, b"pointer");
    let local_pointer = symbol(&image, b"local_pointer");
    let tls_symbol = symbol(&image, b"tls_value");
    let templates = [image
        .tls_template(0)
        .unwrap_or_else(|_| crate::fail("ELF TLS template"))];
    let plan = Plan::new(&templates, 4096).unwrap_or_else(|| crate::fail("ELF TLS plan"));
    let tls_start = plan.modules().next().unwrap().distance as u64;
    let objects = [Object {
        name: b"libarm-probe.so",
        image: &image,
        bias: BIAS,
    }];
    let mut order = [0];
    let scope = Scope::new(&objects, &mut order).unwrap_or_else(|_| crate::fail("ELF scope"));
    let output = unsafe { &mut *addr_of_mut!(OUTPUT) };
    let length = scope
        .write(0, output)
        .unwrap_or_else(|_| crate::fail("ARM ELF relocation"));
    let output = &output[..length];
    check(
        Image::parse(output).is_ok(),
        "relocated native ELF rejected",
    );
    let relocated_pointer = word(output, file_address(output, BIAS + pointer, 8));
    check(
        relocated_pointer == BIAS + values + 8,
        "ARM ABS64 S+A relocation",
    );
    check(
        word(output, file_address(output, relocated_pointer, 8)) == 0x22,
        "ARM relocated data",
    );
    let relocated_local = word(output, file_address(output, BIAS + local_pointer, 8));
    check(
        word(output, file_address(output, relocated_local, 8)) == 0x33,
        "ARM relative relocation",
    );

    // Locate DT_RELA in the compiler's DYNAMIC program header and inspect the
    // actual TPREL record, independently of the loader's relocation decoder.
    let count = u16::from_le_bytes(SOURCE[56..58].try_into().unwrap()) as usize;
    let phdr = word(SOURCE, 32) as usize;
    let mut rela = 0;
    let mut bytes = 0;
    for i in 0..count {
        let ph = &SOURCE[phdr + i * 56..phdr + (i + 1) * 56];
        if u32::from_le_bytes(ph[..4].try_into().unwrap()) == 2 {
            let offset = word(ph, 8) as usize;
            for record in SOURCE[offset..offset + word(ph, 32) as usize].chunks_exact(16) {
                match word(record, 0) {
                    7 => rela = word(record, 8),
                    8 => bytes = word(record, 8),
                    _ => {}
                }
            }
        }
    }
    check(bytes > 0 && bytes % 24 == 0, "fixture RELA table absent");
    let offset = file_address(SOURCE, rela, bytes as usize);
    let mut tls_records = 0;
    for record in SOURCE[offset..offset + bytes as usize].chunks_exact(24) {
        if word(record, 8) as u32 == 1030 {
            let address = BIAS + word(record, 0);
            check(
                word(output, file_address(output, address, 8))
                    == tls_start + tls_symbol + word(record, 16),
                "ARM TPREL relocation",
            );
            tls_records += 1;
        }
    }
    check(tls_records != 0, "fixture has no actual ARM TLS relocation");
    let invalid = unsafe { &mut *addr_of_mut!(INVALID) };
    check(SOURCE.len() <= invalid.len(), "fixture source bounds");
    invalid[..SOURCE.len()].copy_from_slice(SOURCE);
    invalid[18..20].copy_from_slice(&62u16.to_le_bytes());
    check(
        Pie::parse_object(&invalid[..SOURCE.len()]).is_err(),
        "foreign ISA ELF accepted",
    );
    invalid[..SOURCE.len()].copy_from_slice(SOURCE);
    invalid[offset + 8..offset + 12].copy_from_slice(&u32::MAX.to_le_bytes());
    check(
        Pie::parse_object(&invalid[..SOURCE.len()]).is_err(),
        "unknown ARM relocation accepted",
    );
    emit("Real ARM64 ELF relocation and TLS PASS\n");
}
