//! Raw NCA structures
//!
//! Those are used by the NCA parsing code, some of them exposed to the user.
//!
//! The parsing is implemented declaratively using `binrw`

use crate::impl_debug_deserialize_serialize_hexstring;
use crate::pki::AesXtsKey;
use binrw::{BinRead, BinResult, BinWrite, BinrwNamedArgs, ReadOptions, WriteOptions};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fmt::Debug;
use std::io::{Read, Seek, Write};
use std::ops::Deref;

#[repr(transparent)]
#[derive(Clone, Copy, BinRead, BinWrite)]
pub struct SigDebug(pub [u8; 0x100]);

impl_debug_deserialize_serialize_hexstring!(SigDebug);

const XTS_SECTOR_SIZE: usize = 0x200;

#[derive(Debug, Clone, Copy)]
pub struct XtsCryptSector<T, const SIZE: usize = XTS_SECTOR_SIZE>(pub T);

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

impl<T: BinRead<Args = ()>, const SIZE: usize> BinRead for XtsCryptSector<T, SIZE> {
    type Args = XtsCryptArgs;

    fn read_options<R: Read + Seek>(
        reader: &mut R,
        options: &ReadOptions,
        args: Self::Args,
    ) -> BinResult<Self> {
        let mut buf = [0u8; SIZE];
        reader.read_exact(&mut buf)?;

        args.key
            .decrypt(&mut buf, args.sector, SIZE)
            .map_err(|e| binrw::Error::Custom {
                pos: 0,
                err: Box::new(e),
            })?;

        let mut buf = std::io::Cursor::new(buf);
        T::read_options(&mut buf, options, ()).map(XtsCryptSector)
    }
}

impl<T: BinWrite<Args = ()>, const SIZE: usize> BinWrite for XtsCryptSector<T, SIZE> {
    type Args = XtsCryptArgs;

    fn write_options<W: Write + Seek>(
        &self,
        writer: &mut W,
        options: &binrw::WriteOptions,
        args: Self::Args,
    ) -> BinResult<()> {
        let mut buf = [0u8; SIZE];
        let mut buf = std::io::Cursor::new(&mut buf[..]);
        self.0.write_options(&mut buf, options, ())?;

        assert_eq!(buf.position() as usize, SIZE, "Buffer not fully written");

        let buf = buf.into_inner();

        args.key
            .encrypt(buf, args.sector, SIZE)
            .map_err(|e| binrw::Error::Custom {
                pos: 0,
                err: Box::new(e),
            })?;
        writer.write_all(buf)?;
        Ok(())
    }
}

#[repr(transparent)]
#[derive(Clone, Copy, BinRead, BinWrite)]
pub struct Hash([u8; 0x20]);
impl_debug_deserialize_serialize_hexstring!(Hash);

#[repr(transparent)]
#[derive(Clone, Copy, Serialize, Deserialize, BinRead, BinWrite)]
pub struct TitleId(u64);

impl Debug for TitleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:016x}", self.0)
    }
}

#[derive(Clone, Copy, BinRead, BinWrite)]
pub struct RightsId(pub [u8; 0x10]);

impl RightsId {
    pub fn is_empty(&self) -> bool {
        self.0.iter().all(|&b| b == 0)
    }
}

impl_debug_deserialize_serialize_hexstring!(RightsId);

#[derive(Clone, Copy, BinRead, BinWrite)]
pub struct SdkVersion {
    pub revision: u8,
    pub micro: u8,
    pub minor: u8,
    pub major: u8,
}

impl Debug for SdkVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // it's in little endian, so the major version is the last byte
        write!(
            f,
            "{}.{}.{}.{}",
            self.major, self.minor, self.micro, self.revision
        )
    }
}

impl Serialize for SdkVersion {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&format!("{:?}", self))
    }
}

impl<'de> Deserialize<'de> for SdkVersion {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        let mut parts = s.split('.');
        // TODO: make this fallible
        let major = parts.next().unwrap().parse::<u8>().unwrap();
        let minor = parts.next().unwrap().parse::<u8>().unwrap();
        let micro = parts.next().unwrap().parse::<u8>().unwrap();
        let revision = parts.next().unwrap().parse::<u8>().unwrap();

        Ok(SdkVersion {
            revision,
            micro,
            minor,
            major,
        })
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

#[derive(Debug, Clone, Copy, BinRead, BinWrite)]
pub struct RawNcaHeader {
    pub magic: NcaMagic,
    #[br(parse_with = read_bool)]
    #[bw(write_with = write_bool)]
    pub is_gamecard: bool,
    pub content_type: ContentType,
    pub crypto_type: u8,
    pub key_type: KeyType,
    pub nca_size: u64,
    #[brw(pad_after = 4)]
    pub title_id: TitleId,
    pub sdk_version: SdkVersion,
    pub crypto_type2: u8,
    #[brw(pad_after = 0xf)]
    pub rights_id: RightsId,
    pub section_entries: [RawSectionTableEntry; 4],
    pub section_hashes: [Hash; 4],
    pub encrypted_xts_key: [u8; 0x20],
    pub encrypted_ctr_key: [u8; 0x10],
    #[brw(pad_after = 0xc0)]
    pub unknown_new_key: [u8; 0x10],
}

fn read_bool<R: Read>(reader: &mut R, _options: &ReadOptions, _args: ()) -> BinResult<bool> {
    let mut buf = [0u8; 1];
    reader.read_exact(&mut buf)?;
    Ok(buf[0] != 0)
}

fn write_bool<W: Write>(
    value: &bool,
    writer: &mut W,
    _options: &WriteOptions,
    _args: (),
) -> BinResult<()> {
    writer.write_all(&[u8::from(*value)])?;
    Ok(())
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
                            // switchbrew: For pre-1.0.0 "NCA2" NCAs, the first 0x400 byte are encrypted the same way as in NCA3.
                            //             However, each section header is individually encrypted as though it were sector 0, instead of the appropriate sector as in NCA3.
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

#[derive(Debug, Clone, Copy, Serialize, Deserialize, BinRead, BinWrite)]
pub struct Pfs0Superblock {
    pub master_hash: Hash,
    pub block_size: u32,
    #[br(assert(always_2 == 0x2))]
    #[bw(assert(*always_2 == 0x2))]
    pub always_2: u32,
    pub hash_table_offset: u64,
    pub hash_table_size: u64,
    pub pfs0_offset: u64,
    #[brw(pad_after = 0xF0)]
    pub pfs0_size: u64,
}

pub const IVFC_MAX_LEVEL: usize = 6;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, BinRead, BinWrite)]
pub struct BktrHeader {
    pub offset: u64,
    pub size: u64,
    #[brw(magic = b"BKTR")] // why the magic is in the middle of the struct???
    pub version: u32, /* Version? */
    #[brw(pad_after = 0x4)] // reserved
    pub num_entries: u32,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, BinRead, BinWrite)]
pub struct IvfcLevelHeader {
    pub logical_offset: u64,
    pub hash_data_size: u64,
    pub block_size: u32,
    pub reserved: u32,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, BinRead, BinWrite)]
#[brw(magic = b"IVFC")]
pub struct IvfcHeader {
    pub id: u32,
    pub master_hash_size: u32,
    pub num_levels: u32,
    pub level_headers: [IvfcLevelHeader; IVFC_MAX_LEVEL],
    #[brw(pad_before = 0x20)]
    pub master_hash: Hash,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, BinRead, BinWrite)]
pub struct BktrSuperblock {
    pub ivfc_header: IvfcHeader,
    #[brw(pad_before = 0x18)]
    pub relocation_header: BktrHeader,
    pub subsection_header: BktrHeader,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, BinRead, BinWrite)]
pub struct RomfsSuperblock {
    #[brw(pad_after = 0x58)]
    pub ivfc_header: IvfcHeader,
}
#[derive(Clone, Copy, BinRead, BinWrite)]
pub struct UnknownSuperblock([u8; 0x138]);
impl_debug_deserialize_serialize_hexstring!(UnknownSuperblock);

#[derive(Clone, Copy, Debug, Serialize, Deserialize, BinRead, BinWrite)]
#[br(import(partition_type: RawPartitionType, fs_type: RawFsType, crypto_type: CryptoType))]
#[serde(tag = "type")]
pub enum Superblock {
    #[br(pre_assert(partition_type == RawPartitionType::Pfs0 && fs_type == RawFsType::Pfs0))]
    Pfs0(Pfs0Superblock),
    #[br(pre_assert(partition_type == RawPartitionType::RomFs && fs_type == RawFsType::RomFs && crypto_type == CryptoType::Bktr))]
    Bktr(BktrSuperblock),
    #[br(pre_assert(partition_type == RawPartitionType::RomFs && fs_type == RawFsType::RomFs))]
    RomFs(RomfsSuperblock),
    // no NCA0 support for now
    // Nca0Romfs(Nca0RomfsSuperblock),
    /// Catchall for all unknown superblocks or weird header combinations
    Unknown(UnknownSuperblock),
}

#[derive(Clone, Copy, Debug, BinRead, BinWrite)]
#[br(assert(version == 2))]
#[bw(assert(*version == 2))]
pub struct RawNcaFsHeader {
    pub version: u16,
    pub partition_type: RawPartitionType,
    pub fs_type: RawFsType,
    #[brw(pad_after = 0x3)]
    pub crypt_type: CryptoType,
    #[br(args(partition_type, fs_type, crypt_type))]
    pub superblock: Superblock,
    #[brw(pad_after = 0xB8)]
    pub section_ctr: u64,
}

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
    // note: these offsets are divided by 0x200
    pub media_start_offset: u32,
    #[brw(pad_after = 0x8)]
    pub media_end_offset: u32,
}
