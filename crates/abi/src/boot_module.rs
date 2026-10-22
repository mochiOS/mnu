//! A boot module selects initial executable bytes independently of filenames.
//!
//! The first HEADER_LEN bytes describe three adjacent ranges. The resources
//! range includes the header; its remaining contents are opaque to this ABI.
//! Selection belongs to the image builder/boot chain, not the kernel. This
//! descriptor is not authentication: the enclosing boot artifact must still
//! pass the normal boot-chain verification and the image the ELF loader.
//!
//! All integers are little-endian: magic at 0, u32 version at 8, u32 header
//! size at 12, u64 resources length at 16, u64 image offset at 24, u64 image
//! length at 32, u64 kernel-configuration length at 40. Bytes 48..64 are
//! reserved and must be zero. Configuration bytes follow resources; the
//! initial image follows configuration and ends exactly at the module end.
//! Configuration is optional bounded data, never a pathname. Version 1 is
//! intentionally unsupported; builders must regenerate the complete module.

pub const MAGIC: [u8; 8] = *b"MNUBMOD\0";
pub const VERSION: u32 = 2;
pub const HEADER_LEN: usize = 64;
pub const MAX_INITIAL_IMAGE_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_KERNEL_CONFIGURATION_BYTES: u64 = 64 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Truncated,
    InvalidHeader,
    UnsupportedVersion,
    InvalidRange,
    ImageTooLarge,
    ConfigurationTooLarge,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Module<'a> {
    pub resources: &'a [u8],
    pub kernel_configuration: &'a [u8],
    pub initial_image: &'a [u8],
}

pub fn decode(bytes: &[u8]) -> Result<Module<'_>, Error> {
    let header = bytes.get(..HEADER_LEN).ok_or(Error::Truncated)?;
    if header[..8] != MAGIC
        || header[12..16] != (HEADER_LEN as u32).to_le_bytes()
        || header[48..].iter().any(|byte| *byte != 0)
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
    let configuration_len = field(40);
    if image_len > MAX_INITIAL_IMAGE_BYTES {
        return Err(Error::ImageTooLarge);
    }
    if configuration_len > MAX_KERNEL_CONFIGURATION_BYTES {
        return Err(Error::ConfigurationTooLarge);
    }
    let configuration_end = resources_len
        .checked_add(configuration_len)
        .ok_or(Error::InvalidRange)?;
    if resources_len < HEADER_LEN as u64 || image_offset != configuration_end || image_len == 0 {
        return Err(Error::InvalidRange);
    }
    let end = image_offset
        .checked_add(image_len)
        .ok_or(Error::InvalidRange)?;
    if end != bytes.len() as u64 {
        return Err(Error::InvalidRange);
    }
    let boundary = usize::try_from(resources_len).map_err(|_| Error::InvalidRange)?;
    let image_boundary = usize::try_from(image_offset).map_err(|_| Error::InvalidRange)?;
    let (resources, tail) = bytes.split_at(boundary);
    let (kernel_configuration, initial_image) = tail.split_at(image_boundary - boundary);
    Ok(Module {
        resources,
        kernel_configuration,
        initial_image,
    })
}
