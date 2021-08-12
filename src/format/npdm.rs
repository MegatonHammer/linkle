use crate::format::utils;
use crate::format::utils::HexOrNum;
use crate::format::utils::Reserved64;
use crate::format::utils::SigOrPubKey;
use crate::error::Error;
use bit_field::BitField;
use bincode::Options;
use serde_derive::{Deserialize, Serialize};
use snafu::GenerateBacktrace;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::path::Path;
use std::mem::size_of;
use std::io::Write;
use snafu::Backtrace;
use rsa::{BigUint, RSAPrivateKey};

pub mod syscalls;

// TODO: Pretty errors if the user messes up.
#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Syscalls {
    /// Accepts the standard svcName: 0xsvc_hex
    KeyValue(HashMap<String, HexOrNum>),
    /// Accepts syscall names. Those must be correctly spelled.
    Name(Vec<syscalls::SyscallNames>),
}

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
    Syscalls(Syscalls),
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

fn encode_syscalls<I: Iterator<Item=u32>>(syscalls: I) -> Vec<u32> {
    let mut masks = vec![0b1111u32; 6];
    let mut used = [false; 6];
    for (idx, mask) in masks.iter_mut().enumerate() {
        mask.set_bits(29..32, idx as u32);
    }
    for syscall_val in syscalls {
        masks[syscall_val as usize / 24].set_bit(usize::try_from((syscall_val % 24) + 5).unwrap(), true);
        used[syscall_val as usize / 24] = true;
    }
    for (idx, used) in used.iter().enumerate().rev() {
        if !used {
            masks.remove(idx);
        }
    }
    masks
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
                    .set_bits(04..10, u32::from(*highest_thread_priority))
                    .set_bits(10..16, u32::from(*lowest_thread_priority))
                    .set_bits(16..24, u32::from(*lowest_cpu_id))
                    .set_bits(24..32, u32::from(*highest_cpu_id))]
            },
            KernelCapability::Syscalls(Syscalls::Name(syscalls)) => {
                encode_syscalls(syscalls.iter().map(|v| *v as u32))
            },
            KernelCapability::Syscalls(Syscalls::KeyValue(syscalls)) => {
                encode_syscalls(syscalls.iter().map(|(_, v)| v.0 as u32))
            },
            KernelCapability::Map {
                address,
                size,
                is_ro,
                is_io,
            } => {
                let mut val = vec![0b11_1111u32, 0b11_1111u32];
                val[0]
                    .set_bits(7..31, u32::try_from(address.0).unwrap())
                    .set_bit(31, *is_ro);
                val[1]
                    .set_bits(7..31, u32::try_from(size.0).unwrap())
                    .set_bit(31, *is_io);
                val
            }
            KernelCapability::MapPage(page) => {
                vec![*0b111_1111u32.set_bits(8..32, u32::try_from(page.0).unwrap())]
            }
            KernelCapability::IrqPair(irq_pair) => vec![*0b111_1111_1111u32
                .set_bits(12..22, u32::from(irq_pair[0]))
                .set_bits(22..32, u32::from(irq_pair[1]))],
            KernelCapability::ApplicationType(app_type) => {
                vec![*0b1_1111_1111_1111u32.set_bits(14..17, u32::from(*app_type))]
            }
            KernelCapability::MinKernelVersion(min_kernel) => {
                vec![*0b11_1111_1111_1111u32.set_bits(15..32, u32::try_from(min_kernel.0).unwrap())]
            }
            KernelCapability::HandleTableSize(handle_table_size) => {
                vec![*0b111_1111_1111_1111u32.set_bits(16..26, u32::from(*handle_table_size))]
            }
            KernelCapability::DebugFlags {
                allow_debug,
                force_debug,
            } => vec![*0b1111_1111_1111_1111u32
                .set_bit(17, *allow_debug)
                .set_bit(18, *force_debug)],
        }
    }
}

fn sac_encoded_len(sacs: &[String]) -> usize {
    sacs.iter().map(|v| 1 + v.len()).sum()
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NPDMFilesystemAccess {
    permissions: HexOrNum,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NpdmJson {
    // META fields.
    name: String,
    main_thread_stack_size: HexOrNum,
    main_thread_priority: u8,
    default_cpu_id: u8,
    // We thought this field was the process_category. We were wrong. 🤦
    #[serde(alias = "process_category")]
    version: u32,
    address_space_type: u8,
    is_64_bit: bool,

    // ACID fields
    is_retail: bool,
    pool_partition: u32,
    title_id_range_min: Option<HexOrNum>,
    title_id_range_max: Option<HexOrNum>,
    developer_key: Option<String>,

    // ACI0
    title_id: HexOrNum,

    // FAC
    filesystem_access: NPDMFilesystemAccess,

    // SAC
    service_access: Vec<String>,
    service_host: Vec<String>,

    // KAC
    kernel_capabilities: Vec<KernelCapability>,
}

pub enum ACIDBehavior<'a> {
    Sign { pem_file_path: &'a Path },
    Empty,
    Use { acid_file_path: &'a Path }
}

impl NpdmJson {
    pub fn from_file(file: &Path) -> Result<NpdmJson, Error> {
        let file = std::fs::File::open(file)?;
        match serde_json::from_reader(file) {
            Ok(res) => Ok(res),
            Err(error) => Err(Error::from(error)),
        }
    }

    // TODO: Optionally pass a (signed) ACID here.
    pub fn into_npdm<W: Write>(&self, mut file: W, acid_behavior: ACIDBehavior) -> Result<(), Error> {
        let mut meta: RawMeta = RawMeta::default();

        meta.magic = *b"META";

        if self.address_space_type & !3 != 0 {
            return Err(Error::InvalidNpdmValue {
                error: "address_space_type".into(),
                backtrace: Backtrace::generate()
            });
        }
        meta.mmu_flags = (self.address_space_type & 3) << 1;
        if self.is_64_bit { meta.mmu_flags |= 1; }

        meta.main_thread_prio = self.main_thread_priority;
        meta.main_thread_core_num = self.default_cpu_id;

        meta.system_resources = 0;
        meta.version = 0;

        meta.main_thread_stack_size = self.main_thread_stack_size.0 as _;

        let title_name_len = std::cmp::min(self.name.as_bytes().len(), 12);
        meta.title_name = [0; 16];
        meta.title_name[..title_name_len].copy_from_slice(&self.name.as_bytes()[..title_name_len]);

        meta.product_code = [0; 0x10];

        meta.acid_offset = size_of::<RawMeta>() as u32;
        meta.acid_size = match acid_behavior {
            ACIDBehavior::Sign { .. } | ACIDBehavior::Empty => {
                (0x100 + size_of::<RawAcid>() + size_of::<RawFileSystemAccessControl>() +
                    sac_encoded_len(&self.service_host) + sac_encoded_len(&self.service_access) +
                    self.kernel_capabilities.iter().map(|v| v.encode().len() * 4).sum::<usize>()) as u32
            },
            ACIDBehavior::Use { acid_file_path } => std::fs::metadata(acid_file_path)?.len() as u32,
        };

        meta.aci_offset = meta.acid_offset + meta.acid_size;
        meta.aci_size = (size_of::<RawAci>() + size_of::<RawFileSystemAccessHeader>() +
            sac_encoded_len(&self.service_host) + sac_encoded_len(&self.service_access) +
            self.kernel_capabilities.iter().map(|v| v.encode().len() * 4).sum::<usize>()) as u32;

            bincode::DefaultOptions::new().with_fixint_encoding().allow_trailing_bytes().with_no_limit().with_little_endian().serialize_into(&mut file, &meta)?;

        match acid_behavior {
            ACIDBehavior::Sign { pem_file_path } => {
                // Parse PEM file
                let pkey = get_pkey_from_pem(pem_file_path)?;

                let mut v = Vec::new();
                write_acid(&mut v, self, &meta)?;
                println!("Signing over {:02x?}", v);

                // calculate signature.
                let hash = utils::calculate_sha256(v.as_slice())?;
                println!("Signing over {:02x?}", hash);
                let sig = pkey.sign(rsa::PaddingScheme::new_pss::<sha2::Sha256, _>(rand::thread_rng()), &hash)?;
                assert_eq!(sig.len(), 0x100, "Signature of wrong length generated");
                file.write_all(&sig)?;

                write_acid(&mut file, self, &meta)?;
            },
            ACIDBehavior::Empty => {
                file.write_all(&[0; 0x100])?;
                write_acid(&mut file, self, &meta)?;
            }
            ACIDBehavior::Use { acid_file_path } => {
                let mut acid_file = std::fs::File::open(acid_file_path)?;
                std::io::copy(&mut acid_file, &mut file)?;
            }
        }

        // ACI0
        let mut aci0 = RawAci::default();
        aci0.magic = *b"ACI0";
        aci0.titleid = self.title_id.0;
        aci0.fs_access_header_offset = size_of::<RawAci>() as u32;
        aci0.fs_access_header_size = size_of::<RawFileSystemAccessHeader>() as u32;
        aci0.service_access_control_offset = aci0.fs_access_header_offset + aci0.fs_access_header_size;
        aci0.service_access_control_size = (sac_encoded_len(&self.service_host) + sac_encoded_len(&self.service_access)) as u32;
        aci0.kernel_access_control_offset = aci0.service_access_control_offset + aci0.service_access_control_size;
        aci0.kernel_access_control_size = self.kernel_capabilities.iter().map(|v| v.encode().len() * 4).sum::<usize>() as u32;

        bincode::DefaultOptions::new().with_fixint_encoding().allow_trailing_bytes().with_no_limit().with_little_endian().serialize_into(&mut file, &aci0)?;

        let mut fah = RawFileSystemAccessHeader::default();
        fah.version = 1;
        fah.padding = [0; 3];
        fah.permissions_bitmask.copy_from_slice(&self.filesystem_access.permissions.0.to_le_bytes());
        fah.data_size = 0x1C; // Always 0x1C
        fah.size_of_content_owner_id = 0;
        fah.data_size_plus_content_owner_size = 0x1C;
        fah.size_of_save_data_owners = 0;

        bincode::DefaultOptions::new().with_fixint_encoding().allow_trailing_bytes().with_no_limit().with_little_endian().serialize_into(&mut file, &fah)?;

        for elem in &self.service_access {
            if elem.len() & !7 != 0 || elem.len() == 0 {
                return Err(Error::InvalidNpdmValue{
                    error: format!("service_access.{}", elem).into(),
                    backtrace: Backtrace::generate()
                });
            }
            file.write_all(&[elem.len() as u8 - 1])?;
            file.write_all(elem.as_bytes())?;
        }

        for elem in &self.service_host {
            if elem.len() & !7 != 0 || elem.len() == 0 {
                return Err(Error::InvalidNpdmValue{
                    error: format!("service_host.{}", elem).into(),
                    backtrace: Backtrace::generate()
                });
            }
            file.write_all(&[0x80 | (elem.len() as u8 - 1)])?;
            file.write_all(elem.as_bytes())?;
        }

        for elem in &self.kernel_capabilities {
            let encoded = elem.encode().iter().map(|v| v.to_le_bytes().to_vec()).flatten().collect::<Vec<u8>>();
            file.write_all(&encoded)?;
        }

        Ok(())
    }
}

fn get_pkey_from_pem(path: &Path) -> Result<RSAPrivateKey, Error> {
    let data = std::fs::read_to_string(path)?;
    let data = pem::parse(data)?.contents;

    let (n, e, d, prime1, prime2) = yasna::parse_der(&data, |reader| {
        reader.read_sequence(|reader| {
            let _v = reader.next().read_i64()?;
            let _oid = reader.next().read_sequence(|reader| {
                reader.next().read_oid()
            })?;
            let bytes = reader.next().read_bytes()?;
            yasna::parse_der(&bytes, |reader| reader.read_sequence(|reader| {
                let _v = reader.next().read_i64()?;
                let modulus = reader.next().read_biguint()?;
                let pubexp = reader.next().read_biguint()?;
                let privexp = reader.next().read_biguint()?;
                let prime1 = reader.next().read_biguint()?;
                let prime2 = reader.next().read_biguint()?;
                let _exp1 = reader.next().read_biguint()?;
                let _exp2 = reader.next().read_biguint()?;
                let _coeff = reader.next().read_biguint()?;
                Ok((modulus, pubexp, privexp, prime1, prime2))
            }))
        })
    })?;

    let pkey = rsa::RSAPrivateKey::from_components(
        BigUint::from_bytes_be(&n.to_bytes_be()),
        BigUint::from_bytes_be(&e.to_bytes_be()),
        BigUint::from_bytes_be(&d.to_bytes_be()),
        vec![
            BigUint::from_bytes_be(&prime1.to_bytes_be()),
            BigUint::from_bytes_be(&prime2.to_bytes_be()),
        ]
    );
    pkey.validate()?;

    Ok(pkey)
}

fn write_acid<T: Write>(mut writer: &mut T, npdm: &NpdmJson, meta: &RawMeta) -> Result<(), Error> {
    let mut acid = RawAcid::default();

    if let Some(devkey) = &npdm.developer_key {
        acid.rsa_nca_pubkey.0.copy_from_slice(&hex::decode(devkey).unwrap());
    }

    acid.magic = *b"ACID";
    acid.signed_size = meta.acid_size - 0x100;

    acid.flags = 0u32;
    if npdm.is_retail { acid.flags |= 1; }

    if npdm.pool_partition & !3 != 0 {
        return Err(Error::InvalidNpdmValue{
            error: format!("pool_partition").into(),
            backtrace: Backtrace::generate()
        });
    }
    acid.flags |= (npdm.pool_partition & 3) << 2;
    // TODO: Unqualified approval. Zefuk is this?

    acid.titleid_range_min = npdm.title_id_range_min.as_ref().unwrap_or(&npdm.title_id).0;
    acid.titleid_range_max = npdm.title_id_range_max.as_ref().unwrap_or(&npdm.title_id).0;

    acid.fs_access_control_offset = 0x100 + size_of::<RawAcid>() as u32;
    acid.fs_access_control_size = size_of::<RawFileSystemAccessControl>() as u32;

    acid.service_access_control_offset = acid.fs_access_control_offset + acid.fs_access_control_size;
    acid.service_access_control_size = (sac_encoded_len(&npdm.service_host) + sac_encoded_len(&npdm.service_access)) as u32;

    acid.kernel_access_control_offset = acid.service_access_control_offset + acid.service_access_control_size;
    acid.kernel_access_control_size = npdm.kernel_capabilities.iter().map(|v| v.encode().len() * 4).sum::<usize>() as u32;

    let mut fac = RawFileSystemAccessControl::default();
    fac.version = 1;
    fac.padding = [0; 3];
    fac.permissions_bitmask.copy_from_slice(&npdm.filesystem_access.permissions.0.to_le_bytes());

    let mut final_size = bincode::DefaultOptions::new().with_fixint_encoding().allow_trailing_bytes().with_no_limit().with_little_endian().serialized_size(&acid)?;
    assert_eq!(final_size as usize, size_of::<RawAcid>(), "Serialized ACID has wrong size");
    bincode::DefaultOptions::new().with_fixint_encoding().allow_trailing_bytes().with_no_limit().with_little_endian().serialize_into(&mut writer, &acid)?;

    final_size += bincode::DefaultOptions::new().with_fixint_encoding().allow_trailing_bytes().with_no_limit().with_little_endian().serialized_size(&fac)?;
    assert_eq!(final_size as usize, size_of::<RawAcid>() + size_of::<RawFileSystemAccessControl>(), "Serialized FAC has wrong size");
    bincode::DefaultOptions::new().with_fixint_encoding().allow_trailing_bytes().with_no_limit().with_little_endian().serialize_into(&mut writer, &fac)?;

    for elem in &npdm.service_access {
        if elem.len() & !7 != 0 || elem.len() == 0 {
            return Err(Error::InvalidNpdmValue{
                error: format!("service_access.{}", elem).into(),
                backtrace: Backtrace::generate()
            });
        }
        final_size += 1;
        writer.write_all(&[elem.len() as u8 - 1])?;
        final_size += elem.as_bytes().len() as u64;
        writer.write_all(elem.as_bytes())?;
    }

    for elem in &npdm.service_host {
        if elem.len() & !7 != 0 || elem.len() == 0 {
            return Err(Error::InvalidNpdmValue{
                error: format!("service_host.{}", elem).into(),
                backtrace: Backtrace::generate()
            });
        }
        final_size += 1;
        writer.write_all(&[0x80 | (elem.len() as u8 - 1)])?;
        final_size += elem.as_bytes().len() as u64;
        writer.write_all(elem.as_bytes())?;
    }

    assert_eq!(final_size as usize, size_of::<RawAcid>() + size_of::<RawFileSystemAccessControl>()
        + sac_encoded_len(&npdm.service_access) + sac_encoded_len(&npdm.service_host), "Serialized SAC has wrong size");

    for elem in &npdm.kernel_capabilities {
        let encoded = elem.encode().iter().map(|v| v.to_le_bytes().to_vec()).flatten().collect::<Vec<u8>>();
        final_size += encoded.len() as u64;
        writer.write_all(&encoded)?;
    }

    assert_eq!(final_size as usize, size_of::<RawAcid>() + size_of::<RawFileSystemAccessControl>()
        + sac_encoded_len(&npdm.service_access) + sac_encoded_len(&npdm.service_host)
        + npdm.kernel_capabilities.iter().map(|v| v.encode().len() * 4).sum::<usize>(), "Serialized KAC has wrong size");

    Ok(())
}

#[repr(C)]
#[derive(Default, Clone, Copy, Serialize)]
struct RawFileSystemAccessControl {
    version: u8,
    padding: [u8; 3],
    // Work around broken alignment. It sucks.
    permissions_bitmask: [u8; 8],
    reserved: [u8; 0x20]
}

#[repr(C)]
#[derive(Default, Clone, Copy, Serialize)]
struct RawFileSystemAccessHeader {
    version: u8,
    padding: [u8; 3],
    // Work around broken alignment. It sucks.
    permissions_bitmask: [u8; 8],
    data_size: u32, // Always 0x1C
    size_of_content_owner_id: u32,
    data_size_plus_content_owner_size: u32,
    size_of_save_data_owners: u32,
    // TODO: there's more optional stuff afterwards.
}

#[repr(C)]
#[derive(Default, Clone, Copy, Serialize)]
struct RawMeta {
    magic: [u8; 4],
    #[doc(hidden)]
    reserved4: u32,
    reserved8: u32,
    mmu_flags: u8,
    #[doc(hidden)]
    reserved13: u8,
    main_thread_prio: u8,
    main_thread_core_num: u8,
    #[doc(hidden)]
    reserved16: u32,
    system_resources: u32,
    version: u32,
    main_thread_stack_size: u32,
    title_name: [u8; 16],
    product_code: [u8; 16],
    #[doc(hidden)]
    reserved64: Reserved64,
    aci_offset: u32,
    aci_size: u32,
    acid_offset: u32,
    acid_size: u32,
}

/// Restriced Access Controls, signed by Nintendo.
#[repr(C)]
#[derive(Default, Clone, Copy, Serialize)]
struct RawAcid {
    // RSA-2048 Signature starting from `rsa_nca_pubkey` and spanning
    // `signed_size` bytes, using a fixed key owned by Nintendo. The pubkey
    // part can be found in hactool, `acid_fixed_key_modulus`.
    //
    // Written separately.
    // rsa_acid_sig: SigOrPubKey, // [u8; 0x100],
    /// RSA-2048 public key for the second NCA signature
    rsa_nca_pubkey: SigOrPubKey, // [u8; 0x100],
    /// Magic identifying a valid ACID. Should be `b"ACID"`.
    magic: [u8; 4],
    signed_size: u32,
    #[doc(hidden)]
    reserved: u32,
    flags: u32,
    titleid_range_min: u64,
    titleid_range_max: u64,
    fs_access_control_offset: u32,
    fs_access_control_size: u32,
    service_access_control_offset: u32,
    service_access_control_size: u32,
    kernel_access_control_offset: u32,
    kernel_access_control_size: u32,
    #[doc(hidden)]
    reserved38: u64
}

/// Access Control Information.
///
/// Protected by the NCA signature, which devs control via their pubkey.
#[repr(C)]
#[derive(Default, Clone, Copy, Serialize)]
struct RawAci {
    /// Magic identifying a valid ACI. Should be `ACI0`.
    magic: [u8; 4],
    #[doc(hidden)]
    reserved4: [u8; 0xC],
    titleid: u64,
    #[doc(hidden)]
    reserved24: u64,
    fs_access_header_offset: u32,
    fs_access_header_size: u32,
    service_access_control_offset: u32,
    service_access_control_size: u32,
    kernel_access_control_offset: u32,
    kernel_access_control_size: u32,
    #[doc(hidden)]
    reserved38: u64
}