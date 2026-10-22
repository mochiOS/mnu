//! A boot module selects initial executable bytes independently of filenames.
//!
//! The first HEADER_LEN bytes describe four adjacent ranges. The resources
//! range includes the header; its remaining contents are opaque to this ABI.
//! Selection belongs to the image builder/boot chain, not the kernel. This
//! descriptor is not authentication: the enclosing boot artifact must still
//! pass the normal boot-chain verification and the image the ELF loader.
//!
//! All integers are little-endian: magic at 0, u32 version at 8, u32 header
//! size at 12, u64 resources length at 16, u64 image offset at 24, u64 image
//! length at 32, u64 kernel-configuration length at 40, and u64 native-module
//! index length at 48. Bytes 56..64 are reserved and must be zero.
//! Configuration follows resources, the module index follows configuration,
//! and the initial image follows the index and ends exactly at the module end.
//! Configuration is optional bounded data, never a pathname. Older versions are
//! intentionally unsupported; builders must regenerate the complete module.

pub const MAGIC: [u8; 8] = *b"MNUBMOD\0";
pub const VERSION: u32 = 3;
pub const HEADER_LEN: usize = 64;
pub const MAX_INITIAL_IMAGE_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_KERNEL_CONFIGURATION_BYTES: u64 = 64 * 1024;
pub const MAX_NATIVE_MODULE_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Truncated,
    InvalidHeader,
    UnsupportedVersion,
    InvalidRange,
    ImageTooLarge,
    ConfigurationTooLarge,
    ModulesTooLarge,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Module<'a> {
    pub resources: &'a [u8],
    pub kernel_configuration: &'a [u8],
    pub native_modules: &'a [u8],
    pub initial_image: &'a [u8],
}

pub fn decode(bytes: &[u8]) -> Result<Module<'_>, Error> {
    let header = bytes.get(..HEADER_LEN).ok_or(Error::Truncated)?;
    if header[..8] != MAGIC
        || header[12..16] != (HEADER_LEN as u32).to_le_bytes()
        || header[56..].iter().any(|byte| *byte != 0)
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
    let modules_len = field(48);
    if image_len > MAX_INITIAL_IMAGE_BYTES {
        return Err(Error::ImageTooLarge);
    }
    if configuration_len > MAX_KERNEL_CONFIGURATION_BYTES {
        return Err(Error::ConfigurationTooLarge);
    }
    if modules_len > MAX_NATIVE_MODULE_BYTES {
        return Err(Error::ModulesTooLarge);
    }
    let configuration_end = resources_len
        .checked_add(configuration_len)
        .ok_or(Error::InvalidRange)?;
    let modules_end = configuration_end
        .checked_add(modules_len)
        .ok_or(Error::InvalidRange)?;
    if resources_len < HEADER_LEN as u64 || image_offset != modules_end || image_len == 0 {
        return Err(Error::InvalidRange);
    }
    let end = image_offset
        .checked_add(image_len)
        .ok_or(Error::InvalidRange)?;
    if end != bytes.len() as u64 {
        return Err(Error::InvalidRange);
    }
    let boundary = usize::try_from(resources_len).map_err(|_| Error::InvalidRange)?;
    let configuration_len = usize::try_from(configuration_len).map_err(|_| Error::InvalidRange)?;
    let modules_len = usize::try_from(modules_len).map_err(|_| Error::InvalidRange)?;
    let (resources, tail) = bytes.split_at(boundary);
    let (kernel_configuration, tail) = tail.split_at(configuration_len);
    let (native_modules, initial_image) = tail.split_at(modules_len);
    Ok(Module {
        resources,
        kernel_configuration,
        native_modules,
        initial_image,
    })
}
