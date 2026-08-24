#![no_std]
#![no_main]

use core::mem::size_of;
use core::panic::PanicInfo;

mod domain_hypercall;
mod domain_interrupt;
mod virtio_block;

use domain_hypercall::{halt_forever, invoke, shutdown};
use mnu_abi::hypervisor::{
    DomainBootInfo, HypercallNumber, PciDeviceInfo, PciDeviceResource, ShutdownReason,
    DOMAIN_CAPABILITY_DEVICE_CLAIM, DOMAIN_CAPABILITY_DEVICE_QUERY,
    DOMAIN_FEATURE_DEVICE_ACTIVATION, DOMAIN_FEATURE_DEVICE_OWNERSHIP, DOMAIN_FEATURE_DEVICE_QUERY,
    DOMAIN_FEATURE_DEVICE_RESOURCES, DOMAIN_FEATURE_READY, DOMAIN_FEATURE_WAIT,
    DOMAIN_ROLE_HARDWARE, HYPERCALL_INVALID_ARGUMENT, HYPERCALL_SUCCESS, PCI_DEVICE_FLAG_CLAIMABLE,
    PCI_DEVICE_STATE_ACTIVE, PCI_DEVICE_STATE_CLAIMED_DISABLED, PCI_DEVICE_STATE_QUARANTINED,
};

static START_MESSAGE: &[u8] = b"Hardware Domain bootstrap entered\n";
static VIRTIO_SUCCESS_MESSAGE: &[u8] = b"virtio-blk DMA and MSI-X IRQ verified\n";

#[unsafe(no_mangle)]
#[unsafe(link_section = ".text.domain_entry")]
pub unsafe extern "sysv64" fn domain_entry(boot_info_ptr: *const DomainBootInfo) -> ! {
    let Some(boot_info) = (unsafe { boot_info_ptr.as_ref() }) else {
        halt_forever()
    };
    let required_features = DOMAIN_FEATURE_DEVICE_QUERY
        | DOMAIN_FEATURE_DEVICE_OWNERSHIP
        | DOMAIN_FEATURE_DEVICE_RESOURCES
        | DOMAIN_FEATURE_DEVICE_ACTIVATION
        | DOMAIN_FEATURE_READY
        | DOMAIN_FEATURE_WAIT;
    if boot_info.validate().is_err()
        || boot_info.domain_role != DOMAIN_ROLE_HARDWARE
        || boot_info.feature_flags & required_features != required_features
        || boot_info.capabilities & DOMAIN_CAPABILITY_DEVICE_QUERY == 0
    {
        shutdown(
            boot_info.hypervisor_backend,
            ShutdownReason::InvalidBootInfo,
        )
    }
    console_write(boot_info, START_MESSAGE);
    unsafe { domain_interrupt::install_device_handler(virtio_block::device_irq_vector()) };
    unsafe { domain_interrupt::install() };

    let info_address = boot_info.grant_window_start;
    for index in 0..256_u64 {
        let result = query_device(boot_info, index, info_address);
        if result == HYPERCALL_INVALID_ARGUMENT {
            break;
        }
        let info = unsafe { *(info_address as *const PciDeviceInfo) };
        if result != HYPERCALL_SUCCESS || !info.validate() {
            initialization_failed(boot_info)
        }
        if info.flags & PCI_DEVICE_FLAG_CLAIMABLE != 0 {
            if boot_info.capabilities & DOMAIN_CAPABILITY_DEVICE_CLAIM == 0
                || unsafe {
                    invoke(
                        boot_info.hypervisor_backend,
                        HypercallNumber::DeviceClaim,
                        u64::from(info.requester),
                        0,
                        0,
                    )
                } != HYPERCALL_SUCCESS
            {
                initialization_failed(boot_info)
            }
            if query_device(boot_info, index, info_address) != HYPERCALL_SUCCESS {
                initialization_failed(boot_info)
            }
            let claimed = unsafe { *(info_address as *const PciDeviceInfo) };
            if claimed.state != PCI_DEVICE_STATE_CLAIMED_DISABLED
                || claimed.owner_domain != boot_info.domain_id
            {
                initialization_failed(boot_info)
            }
            let identity = unsafe {
                invoke(
                    boot_info.hypervisor_backend,
                    HypercallNumber::DeviceConfigRead,
                    u64::from(claimed.requester),
                    0,
                    0,
                )
            };
            if identity == HYPERCALL_INVALID_ARGUMENT || identity as u16 == 0xffff {
                initialization_failed(boot_info)
            }
            let identity =
                u32::try_from(identity).unwrap_or_else(|_| initialization_failed(boot_info));
            let mut resource_count = 0;
            let mut resources = [PciDeviceResource {
                requester: 0,
                bar_index: 0,
                kind: 0,
                flags: 0,
                guest_address: 0,
                length: 0,
                _reserved0: 0,
            }; 6];
            for resource_index in 0..6_u64 {
                let result = unsafe {
                    invoke(
                        boot_info.hypervisor_backend,
                        HypercallNumber::DeviceResourceQuery,
                        u64::from(claimed.requester),
                        resource_index,
                        info_address,
                    )
                };
                if result == HYPERCALL_INVALID_ARGUMENT {
                    break;
                }
                let resource = unsafe { *(info_address as *const PciDeviceResource) };
                let window_end = boot_info.device_window_start + boot_info.device_window_size;
                if result != HYPERCALL_SUCCESS
                    || !resource.validate()
                    || resource.requester != claimed.requester
                    || resource.guest_address < boot_info.device_window_start
                    || resource
                        .guest_address
                        .checked_add(resource.length)
                        .is_none_or(|end| end > window_end)
                {
                    initialization_failed(boot_info)
                }
                resources[resource_count] = resource;
                resource_count += 1;
            }
            if resource_count == 0
                || unsafe {
                    invoke(
                        boot_info.hypervisor_backend,
                        HypercallNumber::DeviceActivate,
                        u64::from(claimed.requester),
                        0x42,
                        0,
                    )
                } != HYPERCALL_SUCCESS
                || query_device(boot_info, index, info_address) != HYPERCALL_SUCCESS
                || unsafe { &*(info_address as *const PciDeviceInfo) }.state
                    != PCI_DEVICE_STATE_ACTIVE
            {
                initialization_failed(boot_info)
            }
            let command_status = unsafe {
                invoke(
                    boot_info.hypervisor_backend,
                    HypercallNumber::DeviceConfigRead,
                    u64::from(claimed.requester),
                    4,
                    0,
                )
            };
            if command_status == HYPERCALL_INVALID_ARGUMENT || command_status & (1 << 2) == 0 {
                initialization_failed(boot_info)
            }
            if virtio_block::is_virtio_block(identity) {
                if let Err(error) =
                    virtio_block::verify(boot_info, claimed.requester, &resources[..resource_count])
                {
                    console_write(boot_info, error.message());
                    initialization_failed(boot_info)
                }
                console_write(boot_info, VIRTIO_SUCCESS_MESSAGE);
            }
            if unsafe {
                invoke(
                    boot_info.hypervisor_backend,
                    HypercallNumber::DeviceRelease,
                    u64::from(claimed.requester),
                    0,
                    0,
                )
            } != HYPERCALL_SUCCESS
            {
                initialization_failed(boot_info)
            }
            if query_device(boot_info, index, info_address) != HYPERCALL_SUCCESS
                || unsafe { &*(info_address as *const PciDeviceInfo) }.state
                    != PCI_DEVICE_STATE_QUARANTINED
            {
                initialization_failed(boot_info)
            }
        }
    }

    if unsafe {
        invoke(
            boot_info.hypervisor_backend,
            HypercallNumber::Ready,
            0,
            0,
            0,
        )
    } != HYPERCALL_SUCCESS
    {
        shutdown(
            boot_info.hypervisor_backend,
            ShutdownReason::InitializationFailed,
        )
    }

    loop {
        let _ = unsafe { invoke(boot_info.hypervisor_backend, HypercallNumber::Wait, 0, 0, 0) };
    }
}

fn query_device(boot_info: &DomainBootInfo, index: u64, destination: u64) -> u64 {
    unsafe {
        invoke(
            boot_info.hypervisor_backend,
            HypercallNumber::DeviceQuery,
            index,
            destination,
            size_of::<PciDeviceInfo>() as u64,
        )
    }
}

fn initialization_failed(boot_info: &DomainBootInfo) -> ! {
    shutdown(
        boot_info.hypervisor_backend,
        ShutdownReason::InitializationFailed,
    )
}

fn console_write(boot_info: &DomainBootInfo, message: &[u8]) {
    let _ = unsafe {
        invoke(
            boot_info.hypervisor_backend,
            HypercallNumber::ConsoleWrite,
            message.as_ptr() as u64,
            message.len() as u64,
            0,
        )
    };
}

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    halt_forever()
}
