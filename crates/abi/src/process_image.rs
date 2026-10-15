//! Architecture-neutral description of a new process image's initial stack.
//!
//! User space owns the stack convention. The kernel only copies an opaque byte
//! image and applies explicitly requested address or ELF-loader relocations.

pub const MAGIC: [u8; 4] = *b"MIMG";
pub const VERSION: u16 = 1;
pub const MAPPED_VERSION: u16 = 2;
pub const CONTEXT_VERSION: u16 = 3;
pub const CONTEXT_UPDATE_LEN: usize = 24;
pub const MAX_CONTEXT_UPDATES: usize = 1024;
pub const MAPPING_LEN: usize = 48;
pub const MAX_MAPPINGS: usize = 16;
pub const HEADER_LEN: usize = 32;
pub const RELOCATION_LEN: usize = 8;
pub const MAX_STACK_BYTES: usize = 4096;
pub const MAX_RELOCATIONS: usize = MAX_STACK_BYTES / core::mem::size_of::<u64>();
pub const MAX_IMAGE_BYTES: usize = HEADER_LEN
    + MAX_RELOCATIONS * RELOCATION_LEN
    + MAX_MAPPINGS * MAPPING_LEN
    + MAX_CONTEXT_UPDATES * CONTEXT_UPDATE_LEN
    + MAX_STACK_BYTES;

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
    InvalidMapping,
    InvalidContext,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StartupImage<'a> {
    initial_stack_pointer: u32,
    stack: &'a [u8],
    relocations: &'a [u8],
    mappings: &'a [u8],
    context: &'a [u8],
}

impl<'a> StartupImage<'a> {
    pub fn context_updates(self) -> impl Iterator<Item = ContextUpdate> + Clone + 'a {
        self.context
            .chunks_exact(CONTEXT_UPDATE_LEN)
            .map(|record| ContextUpdate {
                kind: read_u32(record, 0).unwrap(),
                key: read_u64(record, 8).unwrap(),
                value: read_u64(record, 16).unwrap(),
            })
    }
    pub fn mappings(self) -> impl Iterator<Item = InitialMapping> + 'a {
        self.mappings
            .chunks_exact(MAPPING_LEN)
            .map(|record| InitialMapping {
                address: read_u64(record, 0).unwrap(),
                length: read_u64(record, 8).unwrap(),
                access: read_u64(record, 16).unwrap(),
                options: read_u64(record, 24).unwrap(),
                backing_handle: read_u64(record, 32).unwrap(),
                backing_offset: read_u64(record, 40).unwrap(),
            })
    }
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
        || !matches!(
            read_u16(input, 4),
            Some(VERSION | MAPPED_VERSION | CONTEXT_VERSION)
        )
        || read_u16(input, 6) != Some(HEADER_LEN as u16)
        || read_u32(input, 8) != Some(0)
    {
        return Err(Error::InvalidHeader);
    }
    let initial_stack_pointer = read_u32(input, 12).ok_or(Error::InvalidHeader)?;
    let stack_len = read_u32(input, 16).ok_or(Error::InvalidHeader)? as usize;
    let relocation_count = read_u32(input, 20).ok_or(Error::InvalidHeader)? as usize;
    let mapping_count = read_u32(input, 24).ok_or(Error::InvalidHeader)? as usize;
    let context_count = read_u32(input, 28).ok_or(Error::InvalidHeader)? as usize;
    if context_count > MAX_CONTEXT_UPDATES
        || (read_u16(input, 4) != Some(CONTEXT_VERSION) && context_count != 0)
    {
        return Err(Error::InvalidHeader);
    }
    if mapping_count > MAX_MAPPINGS || (read_u16(input, 4) == Some(VERSION) && mapping_count != 0) {
        return Err(Error::InvalidHeader);
    }
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
    let mapping_start = HEADER_LEN
        .checked_add(relocations_len)
        .ok_or(Error::InvalidLength)?;
    let context_start = mapping_start
        .checked_add(mapping_count * MAPPING_LEN)
        .ok_or(Error::InvalidLength)?;
    let stack_start = context_start
        .checked_add(context_count * CONTEXT_UPDATE_LEN)
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
    let relocations = &input[HEADER_LEN..mapping_start];
    let mappings = &input[mapping_start..context_start];
    let context = &input[context_start..stack_start];
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
    let image = StartupImage {
        initial_stack_pointer,
        stack,
        relocations,
        mappings,
        context,
    };
    for (index, mapping) in image.mappings().enumerate() {
        mapping.validate()?;
        if image.mappings().take(index).any(|other| {
            mapping.address < other.address + other.length
                && other.address < mapping.address + mapping.length
        }) {
            return Err(Error::InvalidMapping);
        }
    }
    for (index, update) in image.context_updates().enumerate() {
        update.validate()?;
        if read_u32(context, index * CONTEXT_UPDATE_LEN + 4) != Some(0)
            || image.context_updates().take(index).any(|previous| {
                previous.key == update.key && previous.is_handle() == update.is_handle()
            })
        {
            return Err(Error::InvalidContext);
        }
    }
    Ok(image)
}

/// Opaque per-image context edits. Handle edits select an existing reference
/// in this same process; they create no Handle and grant no additional rights.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContextUpdate {
    pub kind: u32,
    pub key: u64,
    pub value: u64,
}

impl ContextUpdate {
    pub const SET_HANDLE: u32 = 1;
    pub const REMOVE_HANDLE: u32 = 2;
    pub const SET_VALUE: u32 = 3;
    pub const REMOVE_VALUE: u32 = 4;

    pub const fn is_handle(self) -> bool {
        matches!(self.kind, Self::SET_HANDLE | Self::REMOVE_HANDLE)
    }

    fn validate(self) -> Result<(), Error> {
        match self.kind {
            Self::SET_HANDLE
                if self.value > 0 && self.value <= crate::PROCESS_MAX_OBJECT_HANDLES as u64 =>
            {
                Ok(())
            }
            Self::SET_VALUE => Ok(()),
            Self::REMOVE_HANDLE | Self::REMOVE_VALUE if self.value == 0 => Ok(()),
            _ => Err(Error::InvalidContext),
        }
    }
}

/// Add a validated context edit set without mutating the source on failure.
/// Call after optional mappings: stack bytes and their relocations stay opaque.
pub fn attach_context(
    output: &mut [u8],
    length: usize,
    updates: &[ContextUpdate],
) -> Result<usize, Error> {
    let image = decode(output.get(..length).ok_or(Error::InvalidLength)?)?;
    if !image.context.is_empty() || updates.len() > MAX_CONTEXT_UPDATES {
        return Err(Error::InvalidContext);
    }
    for (index, update) in updates.iter().enumerate() {
        update.validate()?;
        if updates[..index].iter().any(|previous| {
            previous.key == update.key && previous.is_handle() == update.is_handle()
        }) {
            return Err(Error::InvalidContext);
        }
    }
    let insertion = length - image.stack.len();
    let added = updates.len() * CONTEXT_UPDATE_LEN;
    let end = length.checked_add(added).ok_or(Error::InvalidLength)?;
    if end > output.len() {
        return Err(Error::BufferTooSmall);
    }
    output.copy_within(insertion..length, insertion + added);
    output[4..6].copy_from_slice(&CONTEXT_VERSION.to_le_bytes());
    output[28..32].copy_from_slice(&(updates.len() as u32).to_le_bytes());
    for (index, update) in updates.iter().enumerate() {
        let offset = insertion + index * CONTEXT_UPDATE_LEN;
        output[offset..offset + 4].copy_from_slice(&update.kind.to_le_bytes());
        output[offset + 4..offset + 8].fill(0);
        output[offset + 8..offset + 16].copy_from_slice(&update.key.to_le_bytes());
        output[offset + 16..offset + 24].copy_from_slice(&update.value.to_le_bytes());
    }
    Ok(end)
}

/// Exact, non-replacing VM reservations for ProcessImageReplace. The kernel
/// interprets no purpose or key. Backing zero selects anonymous storage;
/// nonzero backing selects caller-owned RAM with ordinary MAP/READ authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InitialMapping {
    pub address: u64,
    pub length: u64,
    pub access: u64,
    pub options: u64,
    pub backing_handle: u64,
    pub backing_offset: u64,
}

impl InitialMapping {
    fn validate(self) -> Result<(), Error> {
        if self.address == 0
            || self.address & 4095 != 0
            || self.length == 0
            || self.length & 4095 != 0
            || self
                .address
                .checked_add(self.length)
                .is_none_or(|end| end > (1u64 << 47))
            || self.access & !crate::MEMORY_ACCESS_ALL != 0
            || self.access & (crate::MEMORY_ACCESS_WRITE | crate::MEMORY_ACCESS_EXECUTE)
                == crate::MEMORY_ACCESS_WRITE | crate::MEMORY_ACCESS_EXECUTE
            || self.options & !crate::MEMORY_MAP_SHARED != 0
            || self.backing_offset & 4095 != 0
            || self.backing_offset.checked_add(self.length).is_none()
            || (self.backing_handle == 0 && self.backing_offset != 0)
        {
            return Err(Error::InvalidMapping);
        }
        Ok(())
    }
}

/// Extend a validated stack image in place. Addresses stored in opaque stack
/// bytes are unchanged; only the wire envelope grows. Failure leaves it intact.
pub fn attach_mappings(
    output: &mut [u8],
    length: usize,
    mappings: &[InitialMapping],
) -> Result<usize, Error> {
    let source = output.get(..length).ok_or(Error::InvalidLength)?;
    let image = decode(source)?;
    if image.mappings().next().is_some()
        || !image.context.is_empty()
        || mappings.len() > MAX_MAPPINGS
    {
        return Err(Error::InvalidMapping);
    }
    for (index, mapping) in mappings.iter().enumerate() {
        mapping.validate()?;
        if mappings[..index].iter().any(|other| {
            mapping.address < other.address + other.length
                && other.address < mapping.address + mapping.length
        }) {
            return Err(Error::InvalidMapping);
        }
    }
    let insertion = HEADER_LEN + image.relocations.len();
    let added = mappings.len() * MAPPING_LEN;
    let end = length.checked_add(added).ok_or(Error::InvalidLength)?;
    if end > output.len() {
        return Err(Error::BufferTooSmall);
    }
    output.copy_within(insertion..length, insertion + added);
    output[4..6].copy_from_slice(&MAPPED_VERSION.to_le_bytes());
    output[24..28].copy_from_slice(&(mappings.len() as u32).to_le_bytes());
    for (index, mapping) in mappings.iter().enumerate() {
        for (word, value) in [
            mapping.address,
            mapping.length,
            mapping.access,
            mapping.options,
            mapping.backing_handle,
            mapping.backing_offset,
        ]
        .into_iter()
        .enumerate()
        {
            let offset = insertion + index * MAPPING_LEN + word * 8;
            output[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }
    }
    Ok(end)
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
