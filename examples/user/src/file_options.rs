/// The sample accepts only the open flags it exercises. POSIX flags are
/// translated here in userspace and never passed to the native kernel ABI.
pub(crate) fn open_options(flags: u64) -> Result<u32, u64> {
    use mochios_posix_protocol as posix;
    if flags & !(3 | 0o100 | 0o200 | 0o1000 | 0o2000) != 0 {
        return Err(mnu_abi::EINVAL);
    }
    let mut options = match flags & 3 {
        0 => posix::OPEN_READ,
        1 => posix::OPEN_WRITE,
        2 => posix::OPEN_READ | posix::OPEN_WRITE,
        _ => return Err(mnu_abi::EINVAL),
    };
    for (flag, option) in [
        (0o100, posix::OPEN_CREATE),
        (0o200, posix::OPEN_EXCLUSIVE),
        (0o1000, posix::OPEN_TRUNCATE),
        (0o2000, posix::OPEN_APPEND),
    ] {
        if flags & flag != 0 {
            options |= option;
        }
    }
    Ok(options)
}
