//! RAM object Handle adapters.
use super::*;

/// Creates backing owned by the caller, not a view into another process.
/// Existing Handle duplication and IPC attachment paths enforce attenuation.
pub fn memory_object_create(length: u64, options: u64) -> u64 {
    use mnu_abi::status::Error;
    if options & !mnu_abi::MEMORY_OBJECT_RESIZABLE != 0 {
        return Error::InvalidArgument.into_raw();
    }
    let process_id = match crate::syscall::security::current_process_id() {
        Some(process) => process,
        None => return Error::NotReady.into_raw(),
    };
    let result = crate::task::with_process_mut(process_id, |process| {
        let maximum_pages = process.resource_limits().max_memory_object_pages as u64;
        let resizable = options & mnu_abi::MEMORY_OBJECT_RESIZABLE != 0;
        let backing = if resizable {
            crate::mem::shared_memory::SharedMemory::new_resizable(length, maximum_pages)
        } else {
            crate::mem::shared_memory::SharedMemory::new(length, maximum_pages)
        };
        let memory = Arc::try_new(backing?).map_err(|_| Error::ResourceUnavailable)?;
        let object = KernelObject::VmObject(
            Arc::try_new(crate::mem::vm_object::VmObject::shared_memory(memory))
                .map_err(|_| Error::ResourceUnavailable)?,
        );
        let mut rights = HandleRights::READ
            .union(HandleRights::WRITE)
            .union(HandleRights::MAP)
            .union(HandleRights::DUPLICATE)
            .union(HandleRights::TRANSFER);
        if resizable {
            rights = rights.union(HandleRights::CONTROL);
        }
        process
            .object_handles_mut()
            .insert(ObjectHandleEntry::new(object, rights))
            .map(|handle| handle.raw() as u64)
            .ok_or(Error::ResourceUnavailable)
    })
    .unwrap_or(Err(Error::NotReady));
    result.unwrap_or_else(Error::into_raw)
}

pub fn memory_object_length(raw: u64) -> u64 {
    use mnu_abi::status::Error;
    // A reader may inspect the extent without receiving mapping authority.
    // Retain the object and its rights together, before inspecting its backing.
    let (object, rights) = match object_with_rights_native(raw, HandleRights::empty()) {
        Ok(reference) => reference,
        Err(error) => return error.into_raw(),
    };
    if !rights.contains(HandleRights::READ) && !rights.contains(HandleRights::MAP) {
        return Error::AccessDenied.into_raw();
    }
    match object {
        KernelObject::VmObject(object) => object
            .memory_length()
            .unwrap_or_else(|| Error::InvalidArgument.into_raw()),
        _ => Error::InvalidArgument.into_raw(),
    }
}

pub fn memory_object_resize(raw: u64, length: u64) -> u64 {
    use mnu_abi::status::Error;
    // Resolve and retain the resource before acquiring the mapping lock. Never
    // use a foreign PID/FD or hold a caller-table guard across global resize.
    match object_native(raw, HandleRights::CONTROL) {
        Ok(KernelObject::VmObject(object)) => object
            .resize_memory(length)
            .err()
            .map(Error::into_raw)
            .unwrap_or(SUCCESS),
        Ok(_) => Error::InvalidArgument.into_raw(),
        Err(error) => error.into_raw(),
    }
}
