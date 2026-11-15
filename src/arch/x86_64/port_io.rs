//! CPU port instructions. Range and capability admission belong to the caller.
use mnu_abi::status::Error;
use x86_64::instructions::port::Port;

/// # Safety
/// The caller must own the complete port range for the requested width.
pub unsafe fn read(port: u16, width: u64) -> Result<u64, Error> {
    match width {
        1 => Ok(u64::from(unsafe { Port::<u8>::new(port).read() })),
        2 => Ok(u64::from(unsafe { Port::<u16>::new(port).read() })),
        4 => Ok(u64::from(unsafe { Port::<u32>::new(port).read() })),
        _ => Err(Error::InvalidArgument),
    }
}

/// # Safety
/// The caller must own the complete port range for the requested width.
pub unsafe fn write(port: u16, value: u64, width: u64) -> Result<(), Error> {
    match width {
        1 => unsafe { Port::<u8>::new(port).write(value as u8) },
        2 => unsafe { Port::<u16>::new(port).write(value as u16) },
        4 => unsafe { Port::<u32>::new(port).write(value as u32) },
        _ => return Err(Error::InvalidArgument),
    }
    Ok(())
}
