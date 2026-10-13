//! Software leaf state distinguishes shared private storage from write access.
//! A COW reference may remain attached while native access is read-only/none.
pub(crate) const COPY_ON_WRITE: u64 = 1 << 9;
pub(crate) const WRITE_DISABLED: u64 = 1 << 10;
const WRITABLE: u64 = 1 << 1;
const PRESENT_USER: u64 = 1 | (1 << 2);

pub(crate) const fn may_resolve(flags: u64) -> bool {
    flags & PRESENT_USER == PRESENT_USER
        && flags & COPY_ON_WRITE != 0
        && flags & (WRITE_DISABLED | WRITABLE) == 0
}

pub(crate) const fn with_write_access(flags: u64, writable: bool) -> u64 {
    if flags & COPY_ON_WRITE != 0 && !writable {
        flags | WRITE_DISABLED
    } else {
        flags & !WRITE_DISABLED
    }
}

pub(crate) const fn clone_private(flags: u64, write_authorized: bool) -> u64 {
    let writable = write_authorized || flags & WRITABLE != 0 || may_resolve(flags);
    with_write_access((flags | COPY_ON_WRITE) & !WRITABLE, writable)
}
