//! NCA Parsing
//!
//! Nintendo Container Archives (NCAs) are signed and encrypted archives that
//! contain software and other content Nintendo provides. Almost every file on
//! the Horizon/NX OS are stored in this container, as it guarantees its
//! authenticity, preventing tempering.
//!
//! For more information about the NCA file format, see the [switchbrew page].
//!
//! In order to parse an NCA, you may use the `from_file` method:
//!
//! ```
//! # fn get_nca_file() -> std::io::Result<std::fs::File> {
//! #   std::fs::File::open("tests/fixtures/test.nca")
//! # }
//! let f = get_nca_file()?;
//! let nca = Nca::from_file(nca)?;
//! let section = nca.section(0);
//! ```
//!
//! [switchbrew page]: https://switchbrew.org/w/index.php?title=NCA_Format

mod structures;

use self::structures::*;
use crate::error::Error;
use failure::Backtrace;
use crate::pki::{Keys, Aes128Key, AesXtsKey};
use std::io::{self, Seek, Read, Write};
use std::cmp::{min, max};
use plain::Plain;
use serde_derive::{Deserialize, Serialize};
use byteorder::{BE, ByteOrder};
use crate::utils::{align_down, TryClone, ReadRange};

#[derive(Debug, Serialize, Deserialize)]
enum KeyType {
    Application, Ocean, System
}

impl From<u8> for KeyType {
    fn from(from: u8) -> KeyType {
        match from {
            0 => KeyType::Application,
            1 => KeyType::Ocean,
            2 => KeyType::System,
            unk => panic!("Unknown key type {}", unk)
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
enum CryptoType {
    None, Xts, Ctr, Bktr
}

impl From<RawCryptType> for CryptoType {
    fn from(from: RawCryptType) -> CryptoType {
        match from {
            RawCryptType::None => CryptoType::None,
            RawCryptType::Xts => CryptoType::Xts,
            RawCryptType::Ctr => CryptoType::Ctr,
            RawCryptType::Bktr => CryptoType::Bktr,
            unk => panic!("Unknown raw crypt type {:?}", unk)
        }
    }
}

#[repr(transparent)]
#[derive(Clone, Copy)]
struct Hash([u8; 0x20]);
impl_debug_deserialize_serialize_hexstring!(Hash);

#[derive(Debug, Serialize, Deserialize, Clone)]
enum FsType {
    Pfs0 {
        master_hash: Hash,
        block_size: u32,
        hash_table_offset: u64,
        hash_table_size: u64,
        pfs0_offset: u64,
        pfs0_size: u64,
    },
    RomFs,
}

#[derive(Debug, Serialize, Deserialize)]
enum ContentType {
    Program, Meta, Control, Manual, Data, PublicData
}

impl From<u8> for ContentType {
    fn from(from: u8) -> ContentType {
        match from {
            0 => ContentType::Program,
            1 => ContentType::Meta,
            2 => ContentType::Control,
            3 => ContentType::Manual,
            4 => ContentType::Data,
            5 => ContentType::PublicData,
            unk => panic!("Unknown content type {}", unk)
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
enum NcaFormat {
    Nca3, Nca2, Nca0
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SectionJson {
    media_start_offset: u32,
    media_end_offset: u32,
    crypto: CryptoType,
    fstype: FsType,
    nounce: u64,
}

#[derive(Serialize, Deserialize)]
#[repr(transparent)]
pub struct TitleId(u64);

impl std::fmt::Debug for TitleId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:016x}", self.0)
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct NcaJson {
    format: NcaFormat,
    sig: structures::SigDebug,
    npdm_sig: structures::SigDebug,
    is_gamecard: bool,
    content_type: ContentType,
    key_revision1: u8,
    key_revision2: u8,
    key_type: KeyType,
    title_id: TitleId,
    sdk_version: u32, // TODO: Better format
    xts_key: AesXtsKey,
    ctr_key: Aes128Key,
    rights_id: Option<[u8; 0x10]>,
    sections: [Option<SectionJson>; 4]
}

#[derive(Debug)]
pub struct Nca<R> {
    stream: R,
    json: NcaJson
}

fn get_key_area_key(pki: &Keys, key_version: usize, key_type: KeyType) -> Result<Aes128Key, Error> {
    let key = match key_type {
        KeyType::Application => pki.key_area_key_application()[key_version],
        KeyType::Ocean => pki.key_area_key_ocean()[key_version],
        KeyType::System => pki.key_area_key_system()[key_version],
    };
    key.ok_or(Error::MissingKey(Box::leak(format!("key_area_key_application_{:02x}", key_version).into_boxed_str()), Backtrace::new()))
}

fn decrypt_header(pki: &Keys, file: &mut Read) -> Result<RawNca, Error> {
    // Decrypt header.
    let mut header = [0; 0xC00];
    let mut decrypted_header = [0; 0xC00];

    file.read_exact(&mut header)?;

    // TODO: Check if NCA is already decrypted

    let header_key = pki.header_key().as_ref().ok_or(Error::MissingKey("header_key", Backtrace::new()))?;
    header_key.decrypt(&header[..0x400], &mut decrypted_header[..0x400], 0, 0x200)?;

    let raw_nca = *RawNca::from_bytes(&decrypted_header).expect("RawNca to be of the right size");
    match &raw_nca.magic {
        b"NCA3" => {
            header_key.decrypt(&header, &mut decrypted_header, 0, 0x200)?;
        },
        b"NCA2" => {
            for (i, fsheader) in raw_nca.fs_headers.iter().enumerate() {
                let offset = 0x400 + i * 0x200;
                if fsheader._0x148[0] != 0 || fsheader._0x148[..0xB7] != fsheader._0x148[1..] {
                    header_key.decrypt(&header[offset..offset + 0x200], &mut decrypted_header[offset..offset + 0x200], 0, 0x200)?;
                } else {
                    decrypted_header[offset..offset + 0x200].copy_from_slice(&[0; 0x200]);
                }
            }
        },
        b"NCA0" => unimplemented!("NCA0 parsing is not implemented yet"),
        _ => return Err(Error::NcaParse("header_key", Backtrace::new()))
    }
    Ok(*RawNca::from_bytes(&decrypted_header).expect("RawNca to be of the right size"))
}

impl<R: Read> Nca<R> {
    pub fn from_file(pki: &Keys, mut file: R) -> Result<Nca<R>, Error> {
        let header = decrypt_header(pki, &mut file)?;
        let format = match &header.magic {
            b"NCA3" => NcaFormat::Nca3,
            b"NCA2" => NcaFormat::Nca2,
            b"NCA0" => NcaFormat::Nca0,
            _ => unreachable!()
        };

        // TODO: NCA: Verify header with RSA2048 PSS
        // BODY: We want to make sure the NCAs have a valid signature before
        // BODY: decrypting. Maybe put it behind a flag that accepts invalidly
        // BODY: signed NCAs?

        // Crypto is stupid. First, we need to get the max of crypto_type and crypto_type2.
        // Then, nintendo uses both 0 and 1 as master key 0, and then everything is shifted by one.
        // So we sub by 1.
        let master_key_revision = max(header.crypto_type2, header.crypto_type).saturating_sub(1);

        // Handle Rights ID.
        let has_rights_id = header.rights_id != [0; 0x10];

        let key_area_key = get_key_area_key(pki, master_key_revision as _, KeyType::from(header.key_index))?;

        let decrypted_keys = if !has_rights_id {
            // TODO: NCA0 => return
            (
                key_area_key.derive_xts_key(&header.encrypted_xts_key)?,
                key_area_key.derive_key(&header.encrypted_ctr_key)?,
            )
        } else {
            // TODO: Implement RightsID crypto.
            unimplemented!("Rights ID");
        };

        // Parse sections
        let mut sections = [None, None, None, None];
        for (idx, (section, fs)) in header.section_entries.iter().zip(header.fs_headers.iter()).enumerate() {
            // Check if section is present
            if section.media_start_offset != 0 {
                if has_rights_id {
                    unimplemented!("Rights ID");
                } else {
                    assert_eq!(fs.version, 2, "Invalid NCA FS Header version");
                    unsafe {
                        sections[idx] = Some(SectionJson {
                            crypto: fs.crypt_type.into(),
                            fstype: match fs.fs_type {
                                RawFsType::Pfs0 => FsType::Pfs0 {
                                    master_hash: Hash(fs.superblock.pfs0.master_hash),
                                    block_size: fs.superblock.pfs0.block_size,
                                    hash_table_offset: fs.superblock.pfs0.hash_table_offset,
                                    hash_table_size: fs.superblock.pfs0.hash_table_size,
                                    pfs0_offset: fs.superblock.pfs0.pfs0_offset,
                                    pfs0_size: fs.superblock.pfs0.pfs0_size,
                                },
                                RawFsType::RomFs => FsType::RomFs,
                                _ => unreachable!()
                            },
                            nounce: fs.section_ctr,
                            media_start_offset: section.media_start_offset,
                            media_end_offset: section.media_end_offset,
                        });
                    }
                }
            }
        }

        let nca = Nca {
            stream: file,
            json: NcaJson {
                format,
                sig: header.fixed_key_sig,
                npdm_sig: header.npdm_sig,
                is_gamecard: header.is_gamecard != 0,
                content_type: ContentType::from(header.content_type),
                key_revision1: header.crypto_type,
                key_revision2: header.crypto_type2,
                key_type: KeyType::from(header.key_index),
                title_id: TitleId(header.titleid),
                // TODO: Store the SDK version in a more human readable format.
                sdk_version: header.sdk_version,
                xts_key: decrypted_keys.0,
                ctr_key: decrypted_keys.1,
                // TODO: Implement rights id.
                rights_id: None,
                sections: sections,
            }
        };

        Ok(nca)
    }
}

impl<R: Read + TryClone + Seek> Nca<R> {
    pub fn raw_section(&self, id: usize) -> Result<CryptoStream<ReadRange<R>>, Error> {
        if let Some(section) = &self.json.sections[id] {
            // TODO: Nca::raw_section should reopen the file, not dup2 the handle.
            let mut stream = self.stream.try_clone()?;
            stream.seek(std::io::SeekFrom::Start(section.start_offset()))?;

            Ok(CryptoStream {
                stream: ReadRange::new(stream, section.start_offset(), section.size()),
                // Keep a 1-block large buffer of data in case of partial reads.
                buffer: [0; 0x10],
                state: CryptoStreamState {
                    ctr_key: self.json.ctr_key,
                    xts_key: self.json.xts_key,
                    json: section.clone(),
                    offset: section.start_offset(),
                }
            })
        } else {
            return Err(Error::MissingSection(id, Backtrace::new()))
        }
    }

    pub fn section(&self, id: usize) -> Result<VerificationStream<CryptoStream<ReadRange<R>>>, Error> {
        let mut raw_section = self.raw_section(id)?;
        let start_offset = match raw_section.state.json.fstype {
            FsType::Pfs0 { pfs0_offset, .. } => pfs0_offset,
            _ => 0
        };
        raw_section.seek(io::SeekFrom::Start(start_offset))?;
        Ok(VerificationStream {
            stream: raw_section,
            start_at: start_offset,
        })
    }
}

impl<R> Nca<R> {
    pub fn write_header(&self, file: &mut Write) -> Result<(), Error> {
        unimplemented!()
    }

    pub fn write_json(&self, file: &mut Write) -> Result<(), Error> {
        serde_json::to_writer_pretty(file, &self.json).unwrap();
        Ok(())
    }
}

impl SectionJson {
    fn start_offset(&self) -> u64 {
        self.media_start_offset as u64 * 0x200
    }
    fn size(&self) -> u64 {
        (self.media_end_offset - self.media_start_offset) as u64 * 0x200
    }
}

/// A wrapper around a Read/Seek stream, decrypting its contents based of an
/// NCA Section.
#[derive(Debug)]
pub struct CryptoStream<R> {
    stream: R,
    // Hello borrowck my old friend. We need to keep the state separate from the
    // buffer, otherwise we get borrow problems.
    state: CryptoStreamState,
    // Keep a 1-block large buffer of data in case of partial reads.
    buffer: [u8; 0x10],
}

#[derive(Debug)]
struct CryptoStreamState {
    ctr_key: Aes128Key,
    xts_key: AesXtsKey,
    offset: u64,
    json: SectionJson,
}

impl CryptoStreamState {
    fn get_ctr(&self) -> [u8; 0x10] {
        println!("{:x} {:x}", self.json.start_offset(), self.offset);
        let offset = (self.json.start_offset() + self.offset) / 16;
        let mut ctr = [0; 0x10];
        // Write section nounce in Big Endian.
        BE::write_u64(&mut ctr[..8], self.json.nounce);
        // Set ctr to offset / BLOCK_SIZE, in big endian.
        BE::write_u64(&mut ctr[8..], offset);
        ctr
    }

    fn decrypt(&mut self, buf: &mut [u8]) {
        match self.json.crypto {
            CryptoType::Ctr => {
                self.ctr_key.decrypt_ctr(buf, &self.get_ctr());
            },
            CryptoType::Xts => {
                unimplemented!("XTS crypto")
            },
            CryptoType::Bktr => {
                unimplemented!("Bktr crypto")
            }
            CryptoType::None => ()
        }
    }
}

/// Read implementation for CryptoStream.
impl<R: Read> Read for CryptoStream<R> {
    fn read(&mut self, mut buf: &mut [u8]) -> io::Result<usize> {
        let previous_leftovers = (self.state.offset % 16) as usize;
        if previous_leftovers != 0 {
            // First, handle leftovers from a previous read call, so we go back
            // to a properly block-aligned read.
            let to = min(previous_leftovers + buf.len(), 16);
            let size = to - previous_leftovers;
            buf[..size].copy_from_slice(&self.buffer[previous_leftovers..to]);
            self.state.offset += size as u64;

            buf = &mut buf[size..];
        }

        let read = self.stream.read(buf)?;
        buf = &mut buf[..read];

        // Decrypt all the non-leftover bytes.
        let len_no_leftovers = align_down(buf.len(), 16);
        self.state.decrypt(&mut buf[..len_no_leftovers]);
        self.state.offset += len_no_leftovers as u64;
        let leftovers = buf.len() % 16;
        if leftovers != 0 {
            // We got some leftover, save them in the internal buffer, finish
            // reading it, decrypt it, and copy the part we want back.
            //
            // Why not delay decryption until we have a full block? Well, that's
            // because the read interface is **stupid**. If we ever return 0,
            // the file is assumed to be finished - instead of signaling "herp,
            // needs more bytes". So we play greedy.
            let from = align_down(buf.len(), 16);
            self.buffer[..leftovers].copy_from_slice(&buf[from..buf.len()]);
            self.stream.read_exact(&mut self.buffer[leftovers..])?;
            self.state.decrypt(&mut self.buffer);
            buf[from..].copy_from_slice(&self.buffer[..leftovers]);
            self.state.offset += leftovers as u64;
        }

        Ok(buf.len() + if previous_leftovers != 0 { (16 - previous_leftovers) } else { 0 })
    }
}

impl<Stream: Read + Seek> Seek for CryptoStream<Stream> {
    fn seek(&mut self, from: io::SeekFrom) -> io::Result<u64> {
        self.state.offset = match from {
            io::SeekFrom::Start(cur) => cur,
            io::SeekFrom::Current(val) => (self.state.offset as i64 + val) as u64,
            io::SeekFrom::End(val) => (self.state.json.size() as i64 + val) as u64,
        };

        let aligned_offset = align_down(self.state.offset, 16);
        self.stream.seek(io::SeekFrom::Start(aligned_offset));
        if self.state.offset % 16 != 0 {
            self.stream.read_exact(&mut self.buffer)?;
            self.state.decrypt(&mut self.buffer);
        }
        Ok(self.state.offset)
    }
}

// TODO: Make VerificationStream actually verify the data it reads.
// BODY: VerificationStream should verify the body based on the hash table
// BODY: located with the help of the superblock. It will need a different
// BODY: implementation for PFS0 and RomFs (and maybe Bktr?).
pub struct VerificationStream<R> {
    stream: R,
    start_at: u64,
}

impl<R: Read + Seek> Read for VerificationStream<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.stream.read(buf)
    }
}
/*
impl<R: Read + Seek> Seek for VerificationStream<R> {
    fn seek(&mut self, from: io::SeekFrom) -> io::Result<u64> {
        let from = match from {
            io::SeekFrom::Start(cur) => io::SeekFrom::Start(self.start_at + cur),
            io::SeekFrom::Current(val) => io::SeekFrom::Start(self.pos + val),
            io::SeekFrom::End(val) => io::SeekFrom::Start(val),
        }
        self.stream.seek(self.start_at + from)
    }
}
*/
