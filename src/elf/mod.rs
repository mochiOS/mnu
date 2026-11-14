//! Shared ELF64 parsing used by executable and CExt loading.
//!
//! User image construction and relocation live in `syscall::exec::image`.

pub mod loader;

pub use loader::{
    entry_point, parse_elf_header, parse_phdr, Elf64Ehdr, Elf64Phdr, PT_LOAD, PT_NULL,
};
