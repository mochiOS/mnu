extern crate alloc;

use alloc::vec::Vec;

use plugkit_sys::PciConfig;

use super::error::{VirtioError, VirtioResult};
use super::transport::PciBar;

const PCI_VENDOR_DEVICE: u16 = 0x00;
const PCI_COMMAND: u16 = 0x04;
const PCI_HEADER_TYPE: u16 = 0x0c;
const PCI_BAR_START: u16 = 0x10;
const PCI_COMMAND_IO: u16 = 1;
const PCI_COMMAND_MEMORY: u16 = 2;
const PCI_COMMAND_BUS_MASTER: u16 = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PciAddress {
    pub bus: u8,
    pub device: u8,
    pub function: u8,
}

impl PciAddress {
    pub const fn new(bus: u8, device: u8, function: u8) -> Option<Self> {
        if device < 32 && function < 8 {
            Some(Self {
                bus,
                device,
                function,
            })
        } else {
            None
        }
    }
}

pub trait PciConfigIo {
    fn read_u32(&mut self, address: PciAddress, offset: u16) -> VirtioResult<u32>;
    fn write_u32(&mut self, address: PciAddress, offset: u16, value: u32) -> VirtioResult<()>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PciDevice {
    pub address: PciAddress,
    pub vendor_id: u16,
    pub device_id: u16,
}

impl PciDevice {
    pub fn read_config(self, io: &mut impl PciConfigIo) -> VirtioResult<PciConfig> {
        let mut bytes = Vec::with_capacity(256);
        for offset in (0..256u16).step_by(4) {
            bytes.extend_from_slice(&io.read_u32(self.address, offset)?.to_le_bytes());
        }
        Ok(PciConfig::new(bytes))
    }

    pub fn probe_bars(self, io: &mut impl PciConfigIo) -> VirtioResult<Vec<PciBar>> {
        let command_word = io.read_u32(self.address, PCI_COMMAND)?;
        let disabled = command_word & !u32::from(PCI_COMMAND_IO | PCI_COMMAND_MEMORY);
        io.write_u32(self.address, PCI_COMMAND, disabled)?;
        let result = self.probe_bars_while_disabled(io);
        let restore = io.write_u32(self.address, PCI_COMMAND, command_word);
        match (result, restore) {
            (Ok(bars), Ok(())) => Ok(bars),
            (Err(error), _) | (_, Err(error)) => Err(error),
        }
    }

    fn probe_bars_while_disabled(self, io: &mut impl PciConfigIo) -> VirtioResult<Vec<PciBar>> {
        let mut bars = Vec::new();
        let mut index = 0u8;
        while index < 6 {
            let offset = PCI_BAR_START + u16::from(index) * 4;
            let original_low = io.read_u32(self.address, offset)?;
            if original_low == 0 {
                index += 1;
                continue;
            }
            io.write_u32(self.address, offset, u32::MAX)?;
            let mask_low = io.read_u32(self.address, offset)?;
            io.write_u32(self.address, offset, original_low)?;

            if original_low & 1 != 0 {
                let mask = mask_low & !3;
                if mask != 0 {
                    bars.push(PciBar {
                        index,
                        address: u64::from(original_low & !3),
                        size: u64::from((!mask).wrapping_add(1)),
                        is_io: true,
                    });
                }
                index += 1;
                continue;
            }

            let memory_type = (original_low >> 1) & 3;
            if memory_type == 2 {
                if index == 5 {
                    return Err(VirtioError::InvalidBar);
                }
                let high_offset = offset + 4;
                let original_high = io.read_u32(self.address, high_offset)?;
                io.write_u32(self.address, high_offset, u32::MAX)?;
                let mask_high = io.read_u32(self.address, high_offset)?;
                io.write_u32(self.address, high_offset, original_high)?;
                let address = u64::from(original_low & !0xf) | (u64::from(original_high) << 32);
                let mask = u64::from(mask_low & !0xf) | (u64::from(mask_high) << 32);
                if mask != 0 {
                    bars.push(PciBar {
                        index,
                        address,
                        size: (!mask).wrapping_add(1),
                        is_io: false,
                    });
                }
                index += 2;
                continue;
            }

            if memory_type == 0 {
                let mask = mask_low & !0xf;
                if mask != 0 {
                    bars.push(PciBar {
                        index,
                        address: u64::from(original_low & !0xf),
                        size: u64::from((!mask).wrapping_add(1)),
                        is_io: false,
                    });
                }
            }
            index += 1;
        }
        Ok(bars)
    }

    pub fn enable_memory_and_bus_master(self, io: &mut impl PciConfigIo) -> VirtioResult<()> {
        let command = io.read_u32(self.address, PCI_COMMAND)?;
        io.write_u32(
            self.address,
            PCI_COMMAND,
            command | u32::from(PCI_COMMAND_MEMORY | PCI_COMMAND_BUS_MASTER),
        )
    }
}

pub fn find_pci_device(
    io: &mut impl PciConfigIo,
    vendor_id: u16,
    device_id: u16,
) -> VirtioResult<Option<PciDevice>> {
    for bus in 0..=u8::MAX {
        for device in 0..32u8 {
            let function_zero = PciAddress {
                bus,
                device,
                function: 0,
            };
            let identity = io.read_u32(function_zero, PCI_VENDOR_DEVICE)?;
            if identity == u32::MAX || identity & 0xffff == 0xffff {
                continue;
            }
            if let Some(found) = matches_identity(function_zero, identity, vendor_id, device_id) {
                return Ok(Some(found));
            }
            let header = io.read_u32(function_zero, PCI_HEADER_TYPE)?;
            if (header >> 16) as u8 & 0x80 == 0 {
                continue;
            }
            for function in 1..8u8 {
                let address = PciAddress {
                    bus,
                    device,
                    function,
                };
                let identity = io.read_u32(address, PCI_VENDOR_DEVICE)?;
                if identity == u32::MAX || identity & 0xffff == 0xffff {
                    continue;
                }
                if let Some(found) = matches_identity(address, identity, vendor_id, device_id) {
                    return Ok(Some(found));
                }
            }
        }
    }
    Ok(None)
}

fn matches_identity(
    address: PciAddress,
    identity: u32,
    vendor_id: u16,
    device_id: u16,
) -> Option<PciDevice> {
    let actual_vendor = identity as u16;
    let actual_device = (identity >> 16) as u16;
    (actual_vendor == vendor_id && actual_device == device_id).then_some(PciDevice {
        address,
        vendor_id: actual_vendor,
        device_id: actual_device,
    })
}

#[cfg(test)]
mod tests {
    use alloc::collections::BTreeMap;

    use super::*;

    struct MockPci {
        registers: BTreeMap<(u8, u8, u8, u16), u32>,
        bar_masks: BTreeMap<(u8, u8, u8, u16), u32>,
        probing: BTreeMap<(u8, u8, u8, u16), bool>,
    }

    impl MockPci {
        fn new() -> Self {
            Self {
                registers: BTreeMap::new(),
                bar_masks: BTreeMap::new(),
                probing: BTreeMap::new(),
            }
        }

        fn set(&mut self, address: PciAddress, offset: u16, value: u32) {
            self.registers.insert(
                (address.bus, address.device, address.function, offset),
                value,
            );
        }

        fn set_bar(&mut self, address: PciAddress, index: u8, value: u32, mask: u32) {
            let offset = PCI_BAR_START + u16::from(index) * 4;
            self.set(address, offset, value);
            self.bar_masks.insert(
                (address.bus, address.device, address.function, offset),
                mask,
            );
        }
    }

    impl PciConfigIo for MockPci {
        fn read_u32(&mut self, address: PciAddress, offset: u16) -> VirtioResult<u32> {
            let key = (address.bus, address.device, address.function, offset);
            if self.probing.get(&key).copied().unwrap_or(false) {
                return Ok(self.bar_masks.get(&key).copied().unwrap_or(0));
            }
            Ok(self.registers.get(&key).copied().unwrap_or_else(|| {
                if (PCI_BAR_START..PCI_BAR_START + 24).contains(&offset) {
                    0
                } else {
                    u32::MAX
                }
            }))
        }

        fn write_u32(&mut self, address: PciAddress, offset: u16, value: u32) -> VirtioResult<()> {
            let key = (address.bus, address.device, address.function, offset);
            if value == u32::MAX && self.bar_masks.contains_key(&key) {
                self.probing.insert(key, true);
            } else {
                self.probing.remove(&key);
                self.registers.insert(key, value);
            }
            Ok(())
        }
    }

    #[test]
    fn finds_device_on_multifunction_bus() {
        let mut io = MockPci::new();
        let function_zero = PciAddress::new(2, 3, 0).unwrap();
        let function_two = PciAddress::new(2, 3, 2).unwrap();
        io.set(function_zero, PCI_VENDOR_DEVICE, 0x0001_1234);
        io.set(function_zero, PCI_HEADER_TYPE, 0x0080_0000);
        io.set(function_two, PCI_VENDOR_DEVICE, 0x1050_1af4);
        assert_eq!(
            find_pci_device(&mut io, 0x1af4, 0x1050),
            Ok(Some(PciDevice {
                address: function_two,
                vendor_id: 0x1af4,
                device_id: 0x1050,
            }))
        );
    }

    #[test]
    fn probes_32_and_64_bit_memory_bars() {
        let mut io = MockPci::new();
        let address = PciAddress::new(0, 2, 0).unwrap();
        io.set(address, PCI_COMMAND, 3);
        io.set_bar(address, 0, 0x8000_0000, 0xffff_f000);
        io.set_bar(address, 2, 0x0000_0004, 0xffff_0004);
        io.set_bar(address, 3, 0x0000_0001, 0xffff_ffff);
        let device = PciDevice {
            address,
            vendor_id: 0x1af4,
            device_id: 0x1050,
        };
        let bars = match device.probe_bars(&mut io) {
            Ok(bars) => bars,
            Err(error) => panic!("BAR probe failed: {error:?}"),
        };
        assert_eq!(bars.len(), 2);
        assert_eq!(bars[0].address, 0x8000_0000);
        assert_eq!(bars[0].size, 0x1000);
        assert_eq!(bars[1].address, 0x0000_0001_0000_0000);
        assert_eq!(bars[1].size, 0x1_0000);
        assert_eq!(
            io.read_u32(address, PCI_COMMAND),
            Ok(3),
            "command register must be restored"
        );
    }

    #[test]
    fn enables_only_memory_decode_and_bus_master() {
        let mut io = MockPci::new();
        let address = PciAddress::new(0, 1, 0).unwrap();
        io.set(address, PCI_COMMAND, 0x10000);
        let device = PciDevice {
            address,
            vendor_id: 0x1af4,
            device_id: 0x1050,
        };
        assert_eq!(device.enable_memory_and_bus_master(&mut io), Ok(()));
        assert_eq!(io.read_u32(address, PCI_COMMAND), Ok(0x10006));
    }
}
