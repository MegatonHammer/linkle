use byteorder::{LittleEndian, WriteBytesExt};
use crate::format::utils;
use std;
use std::fmt;
use std::fs::File;
use std::io::Write;
use std::collections::HashMap;
use crate::format::utils::HexOrNum;
use serde_derive::{Serialize, Deserialize};
use serde_json;
use bit_field::BitField;
use std::convert::TryFrom;

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type", content = "value")]
#[serde(rename_all = "snake_case")]
pub enum KernelCapability {
    KernelFlags {
        highest_thread_priority: u8,
        lowest_thread_priority: u8,
        highest_cpu_id: u8,
        lowest_cpu_id: u8,
    },
    Syscalls(HashMap<String, HexOrNum>),
    Map {
        address: HexOrNum,
        size: HexOrNum,
        is_ro: bool,
        is_io: bool,
    },
    MapPage(HexOrNum),
    IrqPair([u16; 2]),
    ApplicationType(u16),
    MinKernelVersion(HexOrNum),
    HandleTableSize(u16),
    DebugFlags {
        allow_debug: bool,
        force_debug: bool,
    },
}

impl KernelCapability {
    pub fn encode(&self) -> Vec<u32> {
        match self {
            KernelCapability::KernelFlags {
                highest_thread_priority,
                lowest_thread_priority,
                highest_cpu_id,
                lowest_cpu_id,
            } => {
                vec![*0b111u32
                    .set_bits(04..10, u32::from(*lowest_thread_priority))
                    .set_bits(10..16, u32::from(*highest_thread_priority))
                    .set_bits(16..24, u32::from(*lowest_cpu_id))
                    .set_bits(24..32, u32::from(*highest_cpu_id))]
            },
            KernelCapability::Syscalls(syscalls) => {
                let mut masks = vec![0b1111u32; 6];
                let mut used = [false; 6];
                for (idx, mask) in masks.iter_mut().enumerate() {
                    mask.set_bits(29..32, idx as u32);
                }
                for (syscall_name, syscall_val) in syscalls {
                    masks[syscall_val.0 as usize / 24].set_bit(usize::try_from((syscall_val.0 % 24) + 5).unwrap(), true);
                    used[syscall_val.0 as usize / 24] = true;
                }
                for (idx, used) in used.iter().enumerate().rev() {
                    if !used {
                        masks.remove(idx);
                    }
                }
                masks
            },
            KernelCapability::Map {
                address,
                size,
                is_ro,
                is_io,
            } => {
                let mut val = vec![0b111111u32, 0b111111u32];
                val[0]
                    .set_bits(7..31, u32::try_from(address.0).unwrap())
                    .set_bit(31, *is_ro);
                val[1]
                    .set_bits(7..31, u32::try_from(size.0).unwrap())
                    .set_bit(31, *is_io);
                val
            },
            KernelCapability::MapPage(page) => {
                vec![*0b1111111u32
                    .set_bits(8..32, u32::try_from(page.0).unwrap())]
            },
            KernelCapability::IrqPair(irq_pair) => {
                vec![*0b11111111111u32
                    .set_bits(12..22, u32::from(irq_pair[0]))
                    .set_bits(22..32, u32::from(irq_pair[1]))]
            },
            KernelCapability::ApplicationType(app_type) => {
                vec![*0b1111111111111u32
                    .set_bits(14..17, u32::from(*app_type))]
            },
            KernelCapability::MinKernelVersion(min_kernel) => {
                vec![*0b11111111111111u32
                    .set_bits(15..32, u32::try_from(min_kernel.0).unwrap())]
            },
            KernelCapability::HandleTableSize(handle_table_size) => {
                vec![*0b111111111111111u32
                    .set_bits(16..26, u32::from(*handle_table_size))]
            },
            KernelCapability::DebugFlags {
                allow_debug,
                force_debug,
            } => {
                vec![*0b1111111111111111u32
                    .set_bit(17, *allow_debug)
                    .set_bit(18, *force_debug)]
            },
        }
    }
}
