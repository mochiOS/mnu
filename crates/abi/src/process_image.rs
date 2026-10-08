//! Architecture-neutral description of a new process image's initial stack.
//!
//! User space owns the stack convention. The kernel only copies an opaque byte
//! image and applies explicitly requested address or ELF-loader relocations.

pub const MAGIC: [u8; 4] = *b"MIMG";
pub const VERSION: u16 = 1;
pub const HEADER_LEN: usize = 32;
pub const RELOCATION_LEN: usize = 8;
pub const MAX_STACK_BYTES: usize = 4096;
pub const MAX_RELOCATIONS: usize = MAX_STACK_BYTES / core::mem::size_of::<u64>();

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum RelocationKind {
    /// Adds the runtime virtual address of the first stack byte to the stored
    /// byte offset.
    StackAddress = 1,
    ElfProgramHeaders = 2,
    ElfProgramHeaderSize = 3,
    ElfProgramHeaderCount = 4,
    ElfEntry = 5,
    PageSize = 6,
}

impl RelocationKind {
    pub const fn from_raw(value: u16) -> Option<Self> {
        match value {
            1 => Some(Self::StackAddress),
            2 => Some(Self::ElfProgramHeaders),
            3 => Some(Self::ElfProgramHeaderSize),
            4 => Some(Self::ElfProgramHeaderCount),
            5 => Some(Self::ElfEntry),
            6 => Some(Self::PageSize),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Relocation {
    pub offset: u32,
    pub kind: RelocationKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    BufferTooSmall,
    InvalidHeader,
    InvalidLength,
    InvalidStackPointer,
    InvalidRelocation,
    DuplicateRelocation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StartupImage<'a> {
    initial_stack_pointer: u32,
    stack: &'a [u8],
    relocations: &'a [u8],
}

impl<'a> StartupImage<'a> {
    pub const fn initial_stack_pointer(self) -> u32 {
        self.initial_stack_pointer
    }

    pub const fn stack(self) -> &'a [u8] {
        self.stack
    }

    pub fn relocations(self) -> Relocations<'a> {
        Relocations {
            bytes: self.relocations,
            offset: 0,
        }
    }
}

pub struct Relocations<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl Iterator for Relocations<'_> {
    type Item = Relocation;

    fn next(&mut self) -> Option<Self::Item> {
        let record = self.bytes.get(self.offset..self.offset + RELOCATION_LEN)?;
        self.offset += RELOCATION_LEN;
        Some(Relocation {
            offset: u32::from_le_bytes(record[0..4].try_into().ok()?),
            kind: RelocationKind::from_raw(u16::from_le_bytes(record[4..6].try_into().ok()?))?,
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = (self.bytes.len() - self.offset) / RELOCATION_LEN;
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for Relocations<'_> {}

fn read_u16(input: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        input.get(offset..offset + 2)?.try_into().ok()?,
    ))
}

fn read_u32(input: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        input.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn read_u64(input: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        input.get(offset..offset + 8)?.try_into().ok()?,
    ))
}

fn relocation_at(bytes: &[u8], index: usize) -> Option<Relocation> {
    let offset = index.checked_mul(RELOCATION_LEN)?;
    let record = bytes.get(offset..offset + RELOCATION_LEN)?;
    Some(Relocation {
        offset: u32::from_le_bytes(record[0..4].try_into().ok()?),
        kind: RelocationKind::from_raw(u16::from_le_bytes(record[4..6].try_into().ok()?))?,
    })
}

pub fn decode(input: &[u8]) -> Result<StartupImage<'_>, Error> {
    if input.len() < HEADER_LEN {
        return Err(Error::BufferTooSmall);
    }
    if input[0..4] != MAGIC
        || read_u16(input, 4) != Some(VERSION)
        || read_u16(input, 6) != Some(HEADER_LEN as u16)
        || read_u32(input, 8) != Some(0)
        || input[24..HEADER_LEN].iter().any(|byte| *byte != 0)
    {
        return Err(Error::InvalidHeader);
    }
    let initial_stack_pointer = read_u32(input, 12).ok_or(Error::InvalidHeader)?;
    let stack_len = read_u32(input, 16).ok_or(Error::InvalidHeader)? as usize;
    let relocation_count = read_u32(input, 20).ok_or(Error::InvalidHeader)? as usize;
    if stack_len == 0
        || stack_len > MAX_STACK_BYTES
        || stack_len & 7 != 0
        || relocation_count > MAX_RELOCATIONS
    {
        return Err(Error::InvalidLength);
    }
    let relocations_len = relocation_count
        .checked_mul(RELOCATION_LEN)
        .ok_or(Error::InvalidLength)?;
    let stack_start = HEADER_LEN
        .checked_add(relocations_len)
        .ok_or(Error::InvalidLength)?;
    let expected_len = stack_start
        .checked_add(stack_len)
        .ok_or(Error::InvalidLength)?;
    if input.len() != expected_len {
        return Err(Error::InvalidLength);
    }
    if initial_stack_pointer as usize >= stack_len || initial_stack_pointer & 7 != 0 {
        return Err(Error::InvalidStackPointer);
    }
    let relocations = &input[HEADER_LEN..stack_start];
    let stack = &input[stack_start..];
    for index in 0..relocation_count {
        let relocation = relocation_at(relocations, index).ok_or(Error::InvalidRelocation)?;
        let offset = relocation.offset as usize;
        if offset & 7 != 0 || offset.checked_add(8).is_none_or(|end| end > stack.len()) {
            return Err(Error::InvalidRelocation);
        }
        if relocation.kind == RelocationKind::StackAddress
            && read_u64(stack, offset).is_none_or(|target| target >= stack.len() as u64)
        {
            return Err(Error::InvalidRelocation);
        }
        for previous in 0..index {
            if relocation_at(relocations, previous)
                .is_some_and(|item| item.offset == relocation.offset)
            {
                return Err(Error::DuplicateRelocation);
            }
        }
    }
    Ok(StartupImage {
        initial_stack_pointer,
        stack,
        relocations,
    })
}

pub fn encode(
    initial_stack_pointer: u32,
    stack: &[u8],
    relocations: &[Relocation],
    output: &mut [u8],
) -> Result<usize, Error> {
    if stack.is_empty()
        || stack.len() > MAX_STACK_BYTES
        || stack.len() & 7 != 0
        || relocations.len() > MAX_RELOCATIONS
        || initial_stack_pointer as usize >= stack.len()
        || initial_stack_pointer & 7 != 0
    {
        return Err(Error::InvalidLength);
    }
    let relocations_len = relocations
        .len()
        .checked_mul(RELOCATION_LEN)
        .ok_or(Error::InvalidLength)?;
    let length = HEADER_LEN
        .checked_add(relocations_len)
        .and_then(|value| value.checked_add(stack.len()))
        .ok_or(Error::InvalidLength)?;
    if output.len() < length {
        return Err(Error::BufferTooSmall);
    }
    output[..length].fill(0);
    output[0..4].copy_from_slice(&MAGIC);
    output[4..6].copy_from_slice(&VERSION.to_le_bytes());
    output[6..8].copy_from_slice(&(HEADER_LEN as u16).to_le_bytes());
    output[12..16].copy_from_slice(&initial_stack_pointer.to_le_bytes());
    output[16..20].copy_from_slice(&(stack.len() as u32).to_le_bytes());
    output[20..24].copy_from_slice(&(relocations.len() as u32).to_le_bytes());
    for (index, relocation) in relocations.iter().enumerate() {
        let offset = HEADER_LEN + index * RELOCATION_LEN;
        output[offset..offset + 4].copy_from_slice(&relocation.offset.to_le_bytes());
        output[offset + 4..offset + 6].copy_from_slice(&(relocation.kind as u16).to_le_bytes());
    }
    output[HEADER_LEN + relocations_len..length].copy_from_slice(stack);
    decode(&output[..length])?;
    Ok(length)
}
