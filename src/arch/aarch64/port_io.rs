//! AArch64 has no CPU port-address space. Devices use separately owned MMIO;
//! these optional x86 primitives cannot report fabricated reads or writes.
use mnu_abi::status::Error;

/// # Safety
/// The shared caller still checks port authority before selecting a backend.
pub unsafe fn read(_port: u16, _width: u64) -> Result<u64, Error> {
    Err(Error::Unsupported)
}

/// # Safety
/// The shared caller still checks port authority before selecting a backend.
pub unsafe fn write(_port: u16, _value: u64, _width: u64) -> Result<(), Error> {
    Err(Error::Unsupported)
}
