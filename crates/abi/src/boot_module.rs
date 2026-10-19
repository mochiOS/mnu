//! A boot module selects initial executable bytes independently of filenames.
//!
//! The first HEADER_LEN bytes describe two adjacent ranges. The resources
//! range includes the header; its remaining contents are opaque to this ABI.
//! Selection belongs to the image builder/boot chain, not the kernel. This
//! descriptor is not authentication: the enclosing boot artifact must still
//! pass the normal boot-chain verification and the image the ELF loader.
//!
//! All integers are little-endian: magic at 0, u32 version at 8, u32 header
//! size at 12, u64 resources length at 16, u64 image offset at 24, u64 image
//! length at 32. Bytes 40..64 are reserved and must be zero. The initial image
//! starts exactly at the resources boundary and ends exactly at the module end.

pub const MAGIC: [u8; 8] = *b"MNUBMOD\0";
pub const VERSION: u32 = 1;
pub const HEADER_LEN: usize = 64;
pub const MAX_INITIAL_IMAGE_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Truncated,
    InvalidHeader,
    UnsupportedVersion,
    InvalidRange,
    ImageTooLarge,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Module<'a> {
    pub resources: &'a [u8],
    pub initial_image: &'a [u8],
}

pub fn decode(bytes: &[u8]) -> Result<Module<'_>, Error> {
    let header = bytes.get(..HEADER_LEN).ok_or(Error::Truncated)?;
    if header[..8] != MAGIC
        || header[12..16] != (HEADER_LEN as u32).to_le_bytes()
        || header[40..].iter().any(|byte| *byte != 0)
    {
        return Err(Error::InvalidHeader);
    }
    if header[8..12] != VERSION.to_le_bytes() {
        return Err(Error::UnsupportedVersion);
    }
    let field = |offset| {
        let mut value = [0; 8];
        value.copy_from_slice(&header[offset..offset + 8]);
        u64::from_le_bytes(value)
    };
    let resources_len = field(16);
    let image_offset = field(24);
    let image_len = field(32);
    if image_len > MAX_INITIAL_IMAGE_BYTES {
        return Err(Error::ImageTooLarge);
    }
    if resources_len < HEADER_LEN as u64 || image_offset != resources_len || image_len == 0 {
        return Err(Error::InvalidRange);
    }
    let end = image_offset
        .checked_add(image_len)
        .ok_or(Error::InvalidRange)?;
    if end != bytes.len() as u64 {
        return Err(Error::InvalidRange);
    }
    let boundary = usize::try_from(resources_len).map_err(|_| Error::InvalidRange)?;
    let (resources, initial_image) = bytes.split_at(boundary);
    Ok(Module {
        resources,
        initial_image,
    })
}
