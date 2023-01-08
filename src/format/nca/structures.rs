//! Raw NCA structures
//!
//! Those are used by the NCA parsing code, basically casting the byte slices
//! to those types through the plain crate. This only works on Little Endian
//! hosts! Ideally, we would have a derive macro that generates an
//! appropriate parser based on the machine's endianness.

use crate::impl_debug_deserialize_serialize_hexstring;
use binrw::{BinRead, BinResult, BinWrite, ReadOptions};
use serde_derive::{Deserialize, Serialize};
use std::fmt;
use std::io::{Read, Seek};

#[repr(transparent)]
#[derive(Clone, Copy, BinRead, BinWrite)]
pub struct SigDebug(pub [u8; 0x100]);

impl_debug_deserialize_serialize_hexstring!(SigDebug);

#[derive(Clone, Copy, BinRead, BinWrite)]
pub struct SkipDebug<T: BinRead<Args = ()> + BinWrite<Args = ()> + 'static>(pub T);

impl<T: BinRead<Args = ()> + BinWrite<Args = ()> + 'static> fmt::Debug for SkipDebug<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "SkipDebug")?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, BinRead, BinWrite)]
#[brw(repr = u8)]
pub enum KeyType {
    Application = 0,
    Ocean = 1,
    System = 2,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, BinRead, BinWrite)]
#[brw(repr = u8)]
pub enum ContentType {
    Program = 0,
    Meta = 1,
    Control = 2,
    Manual = 3,
    Data = 4,
    PublicData = 5,
}

#[derive(Debug, Clone, Copy, BinRead, BinWrite)]
pub struct RawNca {
    pub fixed_key_sig: SigDebug,
    pub npdm_sig: SigDebug,
    pub magic: [u8; 4],
    pub is_gamecard: u8,
    pub content_type: ContentType,
    pub crypto_type: u8,
    pub key_type: KeyType,
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
    #[br(parse_with = read_fs_headers(section_entries))]
    // #[bw(write_with = "binrw::io::write_zeroes")] // TODO: we need to write zeroes in case of None here!
    pub fs_headers: [Option<RawNcaFsHeader>; 4],
}
// assert_eq_size!(assert_nca_size; RawNca, [u8; 0xC00]);

fn read_fs_headers<R: Read + Seek>(
    section_entries: [RawSectionTableEntry; 4],
) -> impl FnOnce(&mut R, &ReadOptions, ()) -> BinResult<[Option<RawNcaFsHeader>; 4]> {
    move |reader, options, _| {
        let mut res = [None, None, None, None];

        for i in 0..4 {
            res[i] = if section_entries[i].media_start_offset != 0 {
                Some(RawNcaFsHeader::read_options(reader, options, ())?)
            } else {
                <[u8; 0x200]>::read_options(reader, options, ())?;
                None
            }
        }

        Ok(res)
    }
}

#[derive(Debug, Clone, Copy, BinRead, BinWrite)]
pub struct RawPfs0Superblock {
    pub master_hash: [u8; 0x20],
    pub block_size: u32,
    pub always_2: u32,
    pub hash_table_offset: u64,
    pub hash_table_size: u64,
    pub pfs0_offset: u64,
    // #[brw(align_after = 0x138)]
    pub pfs0_size: u64,
    pub _0x48: SkipDebug<[u8; 0xF0]>,
}

#[derive(Clone, Copy, Debug, BinRead, BinWrite)]
#[br(import(partition_type: RawPartitionType, crypt_type: CryptoType))]
pub enum RawSuperblock {
    #[br(pre_assert(partition_type == RawPartitionType::Pfs0))]
    Pfs0(RawPfs0Superblock),
    // Romfs(RomfsSuperblock),
    // Bktr(BktrSuperblock),
    // Nca0Romfs(Nca0RomfsSuperblock),
    Raw([u8; 0x138]),
}
// assert_eq_size!(assert_superblock_size; RawSuperblock, [u8; 0x138]);

#[derive(Clone, Copy, Debug, BinRead, BinWrite)]
pub struct RawNcaFsHeader {
    pub version: u16,
    pub partition_type: RawPartitionType,
    pub fs_type: RawFsType,
    pub crypt_type: CryptoType,
    pub _0x5: [u8; 0x3],
    #[br(args(partition_type, crypt_type))]
    pub superblock: RawSuperblock,
    pub section_ctr: u64,
    pub _0x148: [u8; 0xB8],
}
// assert_eq_size!(assert_nca_fs_header_size; RawNcaFsHeader, [u8; 0x148 + 0xB8]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, BinRead, BinWrite)]
#[brw(repr = u8)]
pub enum RawPartitionType {
    RomFs = 0,
    Pfs0 = 1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, BinRead, BinWrite)]
#[brw(repr = u8)]
pub enum RawFsType {
    Pfs0 = 2,
    RomFs = 3,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, BinRead, BinWrite)]
#[brw(repr = u8)]
pub enum CryptoType {
    None = 1,
    Xts = 2,
    Ctr = 3,
    Bktr = 4,
}

#[derive(Debug, Clone, Copy, BinRead, BinWrite)]
pub struct RawSectionTableEntry {
    pub media_start_offset: u32,
    pub media_end_offset: u32,
    pub unknown1: u32,
    pub unknown2: u32,
}
