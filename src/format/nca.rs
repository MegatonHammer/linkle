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

#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
#[repr(u8)]
enum KeyType {
    Application = 0, Ocean = 1, System = 2
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

#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
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

#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
#[repr(u8)]
enum ContentType {
    Program = 0, Meta = 1, Control = 2, Manual = 3, Data = 4, PublicData = 5
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

#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
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

#[derive(Serialize, Deserialize, Clone, Copy)]
#[repr(transparent)]
pub struct TitleId(u64);

impl std::fmt::Debug for TitleId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:016x}", self.0)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NcaJson {
    format: NcaFormat,
    sig: structures::SigDebug,
    npdm_sig: structures::SigDebug,
    is_gamecard: bool,
    content_type: ContentType,
    key_revision: u8,
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

// Crypto is stupid. First, we need to get the max of crypto_type and crypto_type2.
// Then, nintendo uses both 0 and 1 as master key 0, and then everything is shifted by one.
// So we sub by 1.
fn get_master_key_revision(crypto_type: u8, crypto_type2: u8) -> u8 {
    max(crypto_type2, crypto_type).saturating_sub(1)
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

        let master_key_revision = get_master_key_revision(header.crypto_type, header.crypto_type2);

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
                key_revision: master_key_revision,
                key_type: KeyType::from(header.key_index),
                title_id: TitleId(header.title_id),
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

impl<R: TryClone + Seek> Nca<R> {
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

    pub fn section(&self, id: usize) -> Result<ReadRange<CryptoStream<ReadRange<R>>>, Error> {
        let mut raw_section = self.raw_section(id)?;
        let (start_offset, size) = match raw_section.state.json.fstype {
            FsType::Pfs0 { pfs0_offset, pfs0_size, .. } => (pfs0_offset, pfs0_size),
            _ => (0, raw_section.state.json.size())
        };
        raw_section.seek_aligned(io::SeekFrom::Start(start_offset));
        Ok(ReadRange::new(raw_section, start_offset, size))
    }
}

impl<R> Nca<R> {
    pub fn write_json(&self, file: &mut Write) -> Result<(), Error> {
        serde_json::to_writer_pretty(file, &self.json).unwrap();
        Ok(())
    }
}

impl<W: Write + Seek + TryClone> Nca<W> {
    pub fn nca_writer(nca_json: NcaJson, output: W) -> Nca<W> {
        Nca {
            stream: output,
            json: nca_json,
        }
    }

    pub fn write_nca(&self, pki: &Keys, mut sections: [Option<&mut Read>; 4]) -> Result<(), Error> {
        let key_area_key = get_key_area_key(pki, self.json.key_revision as _, self.json.key_type)?;

        let mut header = RawNca {
            fixed_key_sig: self.json.sig,
            npdm_sig: self.json.npdm_sig,
            magic: match self.json.format {
                NcaFormat::Nca3 => *b"NCA3",
                NcaFormat::Nca2 => *b"NCA2",
                NcaFormat::Nca0 => *b"NCA0",
            },
            is_gamecard: self.json.is_gamecard as u8,
            content_type: self.json.content_type as u8,
            crypto_type: if self.json.key_revision == 0 { 0 } else { 2 },
            key_index: self.json.key_type as u8,
            nca_size: 0,
            title_id: self.json.title_id.0,
            _padding0: SkipDebug(0),
            sdk_version: self.json.sdk_version,
            crypto_type2: if self.json.key_revision == 0 { 0 } else { self.json.key_revision + 1 },
            _padding1: SkipDebug([0; 0xF]),
            rights_id: self.json.rights_id.unwrap_or([0; 0x10]),
            section_entries: [RawSectionTableEntry {
                media_start_offset: 0,
                media_end_offset: 0,
                unknown1: 0,
                unknown2: 0,
            }; 4],
            section_hashes: [[0; 0x20]; 4],
            encrypted_xts_key: key_area_key.encrypt_xts_key(&self.json.xts_key),
            encrypted_ctr_key: key_area_key.encrypt_key(&self.json.ctr_key),
            unknown_new_key: [0; 0x10],
            _padding2: SkipDebug([0; 0xC0]),
            fs_headers: [RawNcaFsHeader {
                version: 0,
                partition_type: RawPartitionType::RomFs,
                fs_type: RawFsType::RomFs,
                crypt_type: RawCryptType::Ctr,
                _0x5: [0; 0x3],
                superblock: RawSuperblock {
                    pfs0: RawPfs0Superblock {
                        master_hash: [0; 0x20],
                        block_size: 0,
                        always_2: 2,
                        hash_table_offset: 0,
                        hash_table_size: 0,
                        pfs0_offset: 0,
                        pfs0_size: 0,
                        _0x48: SkipDebug([0; 0xF0]),
                    }
                },
                section_ctr: 0,
                _0x148: [0; 0xB8]
            }; 4]
        };

        for (idx, section) in sections.iter_mut().enumerate() {
            if let Some(section) = section {
                let mut section_writer = self.section(idx)?;
                std::io::copy(section, &mut section_writer)?;
            }
        }

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

impl<R> CryptoStream<R> {
    fn seek_aligned(&mut self, from: io::SeekFrom) {
        let new_offset = match from {
            io::SeekFrom::Start(cur) => cur,
            io::SeekFrom::Current(val) => (self.state.offset as i64 + val) as u64,
            io::SeekFrom::End(val) => (self.state.json.size() as i64 + val) as u64,
        };
        if new_offset % 16 != 0 {
            panic!("Seek not aligned");
        }
        self.state.offset = new_offset;
    }
}

impl CryptoStreamState {
    fn get_ctr(&self) -> [u8; 0x10] {
        let offset = self.json.start_offset() / 16 + self.offset / 16;
        let mut ctr = [0; 0x10];
        // Write section nounce in Big Endian.
        BE::write_u64(&mut ctr[..8], self.json.nounce);
        // Set ctr to offset / BLOCK_SIZE, in big endian.
        BE::write_u64(&mut ctr[8..], offset);
        ctr
    }

    fn decrypt(&mut self, buf: &mut [u8]) -> Result<(), Error> {
        match self.json.crypto {
            CryptoType::Ctr => {
                self.ctr_key.decrypt_ctr(buf, &self.get_ctr())
            },
            CryptoType::Xts => {
                unimplemented!("XTS crypto")
            },
            CryptoType::Bktr => {
                unimplemented!("Bktr crypto")
            }
            CryptoType::None => Ok(())
        }
    }

    fn encrypt(&mut self, buf: &mut [u8]) -> Result<(), Error> {
        match self.json.crypto {
            CryptoType::Ctr => {
                self.ctr_key.encrypt_ctr(buf, &self.get_ctr())
            },
            CryptoType::Xts => {
                unimplemented!("XTS crypto")
            },
            CryptoType::Bktr => {
                unimplemented!("Bktr crypto")
            }
            CryptoType::None => Ok(())
        }
    }
}

/// Read implementation for CryptoStream.
impl<R: Read> Read for CryptoStream<R> {
    fn read(&mut self, mut buf: &mut [u8]) -> io::Result<usize> {
        let previous_leftovers = (self.state.offset % 16) as usize;
        let previous_leftovers_written = if previous_leftovers != 0 {
            // First, handle leftovers from a previous read call, so we go back
            // to a properly block-aligned read.
            let to = min(previous_leftovers + buf.len(), 16);
            let size = to - previous_leftovers;
            buf[..size].copy_from_slice(&self.buffer[previous_leftovers..to]);
            self.state.offset += size as u64;

            buf = &mut buf[size..];
            size
        } else { 0 };

        let read = self.stream.read(buf)?;
        buf = &mut buf[..read];

        // Decrypt all the non-leftover bytes.
        let len_no_leftovers = align_down(buf.len(), 16);
        self.state.decrypt(&mut buf[..len_no_leftovers]).unwrap();
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
            // TODO: Bubble up the error.
            self.state.decrypt(&mut self.buffer).unwrap();
            buf[from..].copy_from_slice(&self.buffer[..leftovers]);
            self.state.offset += leftovers as u64;
        }

        Ok(previous_leftovers_written + read)
    }
}

impl<W: Write> Write for CryptoStream<W> {
    fn write(&mut self, mut buf: &[u8]) -> io::Result<usize> {
        let previous_leftovers = (self.state.offset % 16) as usize;
        let previous_leftovers_written = if previous_leftovers != 0 {
            // We need to do two things: Rewrite the block on disk with the
            // encrypted data, and update the leftover buffer with the decrypted
            // data.
            let to = min(previous_leftovers + buf.len(), 16);
            let size = to - previous_leftovers;
            self.buffer[previous_leftovers..to].copy_from_slice(&buf[..size]);

            if to == 16 {
                // We are done handling this block. Write it to disk.
                // TODO: Bubble up the error.
                self.state.encrypt(&mut self.buffer).unwrap();
                self.stream.write_all(&self.buffer)?;
            }

            self.state.offset += size as u64;

            buf = &buf[size..];
            size
        } else { 0 };

        // Encrypt chunk by chunk
        for chunk in buf.chunks_exact(16) {
            self.buffer.copy_from_slice(chunk);
            self.state.encrypt(&mut self.buffer).unwrap();
            self.stream.write_all(&self.buffer)?;
            self.state.offset += 16
        }

        // Store all leftover bytes.
        let leftovers = buf.len() % 16;
        if leftovers != 0 {
            // We got some leftover, save them in the internal buffer so they can
            // be processed in a subsequent write. Note that this will not work
            // at all if you mix reads and writes...
            let from = align_down(buf.len(), 16);
            self.buffer[..leftovers].copy_from_slice(&buf[from..buf.len()]);
            self.state.offset += leftovers as u64;
        }

        Ok(previous_leftovers + buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
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
        self.stream.seek(io::SeekFrom::Start(aligned_offset))?;
        if self.state.offset % 16 != 0 {
            self.stream.read_exact(&mut self.buffer)?;
            self.state.decrypt(&mut self.buffer).unwrap();
        }
        Ok(self.state.offset)
    }
}

/*pub struct VerificationStream<R> {
    stream: R,
    hashes_start: u64,
    data_off: u64,
    data_size: u64,
}

impl<R> VerificationStream<R> {
    fn new(stream: R, hashes_start: u64, data_start: u64, data_size: u64) -> Self {
        VerificationStream {
            stream,
            hashes_start,
            data_off: data_start,
            data_size
        }
    }
}

impl<R: Read + Seek> Read for VerificationStream<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.stream.seek(SeekFrom::Start(data_off))?;
        self.stream.read(buf);
    }
}

impl<R: Read + Seek> Seek for VerificationStream<R> {
    fn seek(&mut self, from: io::SeekFrom) -> io::Result<u64> {
        let from = match from {
            io::SeekFrom::Start(cur) => io::SeekFrom::Start(self.start_at + cur),
            io::SeekFrom::Current(val) => io::SeekFrom::Start(self.pos + val),
            io::SeekFrom::End(val) => io::SeekFrom::Start(val),
        };
        self.stream.seek(self.start_at + from)
    }
}

impl<W: Write + Seek> 
*/
