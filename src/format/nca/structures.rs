//! Raw NCA structures
//!
//! Those are used by the NCA parsing code, basically casting the byte slices
//! to those types through the plain crate. This only works on Little Endian
//! hosts! Ideally, we would have a derive macro that generates an
//! appropriate parser based on the machine's endianness.

use crate::impl_debug_deserialize_serialize_hexstring;
use crate::pki::AesXtsKey;
use binrw::{BinRead, BinResult, BinWrite, BinrwNamedArgs, ReadOptions};
use serde_derive::{Deserialize, Serialize};
use std::fmt;
use std::io::{Read, Seek, Write};
use std::ops::Deref;

#[repr(transparent)]
#[derive(Clone, Copy, BinRead, BinWrite)]
pub struct SigDebug(pub [u8; 0x100]);

impl_debug_deserialize_serialize_hexstring!(SigDebug);

const XTS_SECTOR_SIZE: usize = 0x200;

#[derive(Debug, Clone, Copy)]
pub struct XtsCryptSector<T, const Size: usize = XTS_SECTOR_SIZE>(pub T);

impl<T> Deref for XtsCryptSector<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Copy, Clone, BinrwNamedArgs)]
pub struct XtsCryptArgs {
    pub key: AesXtsKey,
    pub sector: usize,
}

impl<T: BinRead<Args = ()>, const Size: usize> BinRead for XtsCryptSector<T, Size> {
    type Args = XtsCryptArgs;

    fn read_options<R: Read + Seek>(
        reader: &mut R,
        options: &ReadOptions,
        args: Self::Args,
    ) -> BinResult<Self> {
        let mut buf = [0u8; Size];
        reader.read_exact(&mut buf)?;

        args.key
            .decrypt(&mut buf, args.sector, Size)
            .map_err(|e| binrw::Error::Custom {
                pos: 0,
                err: Box::new(e),
            })?;

        let mut buf = std::io::Cursor::new(buf);
        T::read_options(&mut buf, options, ()).map(XtsCryptSector)
    }
}

impl<T: BinWrite<Args = ()>, const Size: usize> BinWrite for XtsCryptSector<T, Size> {
    type Args = XtsCryptArgs;

    fn write_options<W: Write + Seek>(
        &self,
        writer: &mut W,
        options: &binrw::WriteOptions,
        args: Self::Args,
    ) -> BinResult<()> {
        let mut buf = [0u8; Size];
        let mut buf = std::io::Cursor::new(&mut buf[..]);
        self.0.write_options(&mut buf, options, ())?;

        assert_eq!(buf.position() as usize, Size, "Buffer not fully written");

        let buf = buf.into_inner();

        args.key
            .encrypt(buf, args.sector, Size)
            .map_err(|e| binrw::Error::Custom {
                pos: 0,
                err: Box::new(e),
            })?;
        writer.write_all(buf)?;
        Ok(())
    }
}

#[derive(Clone, Copy, BinRead, BinWrite)]
pub struct SkipDebug<T: BinRead<Args = ()> + BinWrite<Args = ()> + 'static>(pub T);

impl<T: BinRead<Args = ()> + BinWrite<Args = ()> + 'static> fmt::Debug for SkipDebug<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "SkipDebug")?;
        Ok(())
    }
}

#[repr(transparent)]
#[derive(Clone, Copy, BinRead, BinWrite)]
pub struct Hash([u8; 0x20]);
impl_debug_deserialize_serialize_hexstring!(Hash);

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

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize, BinRead, BinWrite)]
pub enum NcaMagic {
    #[brw(magic = b"NCA0")]
    Nca0,
    #[brw(magic = b"NCA1")]
    Nca1,
    #[brw(magic = b"NCA2")]
    Nca2,
    #[brw(magic = b"NCA3")]
    Nca3,
}

#[derive(Debug, Clone, Copy, BinRead, BinWrite)]
pub struct NcaSigs {
    pub fixed_key_sig: SigDebug,
    pub npdm_sig: SigDebug,
}

#[derive(Clone, Copy, BinRead, BinWrite)]
pub struct RightsId(pub [u8; 0x10]);

impl RightsId {
    pub fn is_empty(&self) -> bool {
        self.0.iter().all(|&b| b == 0)
    }
}

impl_debug_deserialize_serialize_hexstring!(RightsId);

#[derive(Debug, Clone, Copy, BinRead, BinWrite)]
pub struct RawNcaHeader {
    pub magic: NcaMagic,
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
    pub rights_id: RightsId,
    pub section_entries: [RawSectionTableEntry; 4],
    pub section_hashes: [Hash; 4],
    pub encrypted_xts_key: [u8; 0x20],
    pub encrypted_ctr_key: [u8; 0x10],
    pub unknown_new_key: [u8; 0x10],
    pub _padding2: SkipDebug<[u8; 0xC0]>,
}

#[derive(Debug, Clone, Copy, BinRead, BinWrite)]
#[brw(import(key: AesXtsKey))]
pub struct RawNca {
    #[brw(args { key, sector: 0 })]
    pub sigs: XtsCryptSector<NcaSigs>,
    #[brw(args { key, sector: 1 })]
    pub header: XtsCryptSector<RawNcaHeader>,
    #[br(parse_with = read_fs_headers(&header.0, key))]
    // #[bw(write_with = "binrw::io::write_zeroes")] // TODO: we need to write zeroes in case of None here!
    pub fs_headers: [Option<RawNcaFsHeader>; 4],
}
// assert_eq_size!(assert_nca_size; RawNca, [u8; 0xC00]);

fn read_fs_headers<R: Read + Seek>(
    header: &RawNcaHeader,
    key: AesXtsKey,
) -> impl FnOnce(&mut R, &ReadOptions, ()) -> BinResult<[Option<RawNcaFsHeader>; 4]> {
    let magic = header.magic;
    let section_entries = header.section_entries;

    move |reader, options, _| {
        let mut res = [None, None, None, None];

        for i in 0..4 {
            res[i] = if section_entries[i].media_start_offset != 0 {
                let section_header = <XtsCryptSector<RawNcaFsHeader>>::read_options(
                    reader,
                    options,
                    XtsCryptArgs {
                        key,
                        sector: match magic {
                            // For pre-1.0.0 "NCA2" NCAs, the first 0x400 byte are encrypted the same way as in NCA3.
                            // However, each section header is individually encrypted as though it were sector 0, instead of the appropriate sector as in NCA3.
                            NcaMagic::Nca3 => 2 + i,
                            NcaMagic::Nca2 => 0,
                            _ => todo!("{:?}", magic),
                        },
                    },
                )?;

                Some(section_header.0)
            } else {
                <[u8; 0x200]>::read_options(reader, options, ())?;
                None
            }
        }

        Ok(res)
    }
}

#[derive(Debug, Clone, Copy, BinRead, BinWrite)]
pub struct Pfs0Superblock {
    pub master_hash: Hash,
    pub block_size: u32,
    pub always_2: u32,
    pub hash_table_offset: u64,
    pub hash_table_size: u64,
    pub pfs0_offset: u64,
    // #[brw(align_after = 0x138)]
    pub pfs0_size: u64,
    pub _0x48: SkipDebug<[u8; 0xF0]>,
}

pub const IVFC_MAX_LEVEL: usize = 6;

#[derive(Debug, Clone, Copy, BinRead, BinWrite)]
pub struct BktrHeader {
    pub offset: u64,
    pub size: u64,
    pub magic: [u8; 4], /* "BKTR" */
    pub _0x14: u32,     /* Version? */
    pub num_entries: u32,
    pub _0x1c: u32, /* Reserved? */
}

#[derive(Debug, Clone, Copy, BinRead, BinWrite)]
pub struct IvfcLevelHeader {
    pub logical_offset: u64,
    pub hash_data_size: u64,
    pub block_size: u32,
    pub reserved: u32,
}

#[derive(Debug, Clone, Copy, BinRead, BinWrite)]
#[brw(magic = b"IVFC")]
pub struct IvfcHeader {
    pub id: u32,
    pub master_hash_size: u32,
    pub num_levels: u32,
    pub level_headers: [IvfcLevelHeader; IVFC_MAX_LEVEL],
    pub _0xa0: [u8; 0x20],
    pub master_hash: Hash,
}

#[derive(Debug, Clone, Copy, BinRead, BinWrite)]
pub struct BktrSuperblock {
    pub ivfc_header: IvfcHeader,
    pub _0xe0: [u8; 0x18],
    pub relocation_header: BktrHeader,
    pub subsection_header: BktrHeader,
}

#[derive(Debug, Clone, Copy, BinRead, BinWrite)]
pub struct RomfsSuperblock {
    pub ivfc_header: IvfcHeader,
    pub _0xe0: [u8; 0x58],
}

#[derive(Clone, Copy, Debug, BinRead, BinWrite)]
#[br(import(partition_type: RawPartitionType, fs_type: RawFsType, crypto_type: CryptoType))]
pub enum RawSuperblock {
    #[br(pre_assert(partition_type == RawPartitionType::Pfs0 && fs_type == RawFsType::Pfs0))]
    Pfs0(Pfs0Superblock),
    #[br(pre_assert(partition_type == RawPartitionType::RomFs && fs_type == RawFsType::RomFs && crypto_type == CryptoType::Bktr))]
    Bktr(BktrSuperblock),
    #[br(pre_assert(partition_type == RawPartitionType::RomFs && fs_type == RawFsType::RomFs))]
    RomFs(RomfsSuperblock),
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
    #[br(args(partition_type, fs_type, crypt_type))]
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
    pub padding: [u8; 0x8],
}
