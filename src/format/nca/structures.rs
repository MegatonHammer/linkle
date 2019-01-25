//! Raw NCA structures
//!
//! Those are used by the NCA parsing code, basically casting the byte slices
//! to those types through the plain crate. This only works on Little Endian
//! hosts! Ideally, we would have a derive macro that generates an
//! appropriate parser based on the machine's endianness.

use std::fmt;
use plain::Plain;

#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct SigDebug(pub [u8; 0x100]);
#[derive(Clone, Copy)]
pub struct SkipDebug<T>(pub T);

impl<T> fmt::Debug for SkipDebug<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "SkipDebug")?;
        Ok(())
    }
}

impl_debug_deserialize_serialize_hexstring!(SigDebug);

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct RawNca {
    pub fixed_key_sig: SigDebug,
    pub npdm_sig: SigDebug,
    pub magic: [u8; 4],
    pub is_gamecard: u8,
    pub content_type: u8,
    pub crypto_type: u8,
    pub key_index: u8,
    pub nca_size: u64,
    pub title_id: u64,
    pub _padding0: SkipDebug<u32>,
    pub sdk_version: u32,
    pub crypto_type2: u8,
    pub _padding1: SkipDebug<[u8; 0xF]>,
    pub rights_id: [u8; 0x10],
    pub section_entries: [RawSectionTableEntry; 4],
    pub section_hashes: [[u8; 0x20]; 4],
    pub encrypted_xts_key: [u8; 0x20],
    pub encrypted_ctr_key: [u8; 0x10],
    pub unknown_new_key: [u8; 0x10],
    pub _padding2: SkipDebug<[u8; 0xC0]>,
    pub fs_headers: [RawNcaFsHeader; 4]
}
assert_eq_size!(assert_nca_size; RawNca, [u8; 0xC00]);

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct RawPfs0Superblock {
    pub master_hash: [u8; 0x20],
    pub block_size: u32,
    pub always_2: u32,
    pub hash_table_offset: u64,
    pub hash_table_size: u64,
    pub pfs0_offset: u64,
    pub pfs0_size: u64,
    pub _0x48: SkipDebug<[u8; 0xF0]>,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union RawSuperblock {
    pub pfs0: RawPfs0Superblock,
    //romfs_superblock: RomfsSuperblock,
    //bktrs_superblock: BktrSuperblock,
    //nca0_romfs_superblock: Nca0RomfsSuperblock,
}
assert_eq_size!(assert_superblock_size; RawSuperblock, [u8; 0x138]);

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RawNcaFsHeader {
    pub version: u16,
    pub partition_type: RawPartitionType,
    pub fs_type: RawFsType,
    pub crypt_type: RawCryptType,
    pub _0x5: [u8; 0x3],
    pub superblock: RawSuperblock,
    pub section_ctr: u64,
    pub _0x148: [u8; 0xB8]
}
assert_eq_size!(assert_nca_fs_header_size; RawNcaFsHeader, [u8; 0x148 + 0xB8]);

enum_with_val! {
    #[derive(Clone, Copy)]
    pub struct RawPartitionType(u8) {
        RomFs = 0, Pfs0 = 1
    }
}

enum_with_val! {
    #[derive(Clone, Copy)]
    pub struct RawFsType(u8) {
        Pfs0 = 2, RomFs = 3
    }
}

enum_with_val! {
    #[derive(Clone, Copy)]
    pub struct RawCryptType(u8) {
        None = 1, Xts = 2, Ctr = 3, Bktr = 4
    }
}

pub struct RawSuperblockWithTag(RawPartitionType, RawCryptType, RawSuperblock);
impl fmt::Debug for RawSuperblockWithTag {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match (self.0, self.1) {
            (RawPartitionType::RomFs, RawCryptType::Bktr) => f.debug_struct("RawSuperblock::Bktr").finish(),
            (RawPartitionType::RomFs, _) => f.debug_struct("RawSuperblock::RomFs").finish(),
            (RawPartitionType::Pfs0, _) => unsafe { f.debug_struct("RawSuperblock::Pfs0").field("inner", &self.2.pfs0).finish() },
            _ => unreachable!()
        }
    }
}

impl fmt::Debug for RawNcaFsHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("RawNcaFsHeader")
            .field("version", &self.version)
            .field("partition_type", &self.partition_type)
            .field("fs_type", &self.fs_type)
            .field("crypt_type", &self.crypt_type)
            .field("_0x5", &self._0x5)
            .field("superblock", &RawSuperblockWithTag(self.partition_type, self.crypt_type, self.superblock))
            .field("section_ctr", &self.section_ctr)
            .finish()
    }
}

// Safety: RawNca is a repr(C) that only contains Pods itself.
unsafe impl Plain for RawNca {}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RawSectionTableEntry {
    pub media_start_offset: u32,
    pub media_end_offset: u32,
    pub unknown1: u32,
    pub unknown2: u32
}
