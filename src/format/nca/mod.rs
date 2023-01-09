//! NCA Parsing
//!
//! Nintendo Container Archives (NCAs) are signed and encrypted archives that
//! contain software and other content Nintendo provides. Almost every file on
//! the Horizon/NX OS are stored in this container, as it guarantees its
//! authenticity, preventing tampering.
//!
//! NCAs consist of up to 4 sections, each containing some kind of file system.
//!
//! Generally, you can find three types of sections:
//! - PartitionFs (aka pfs0) - A file system used mostly to contain exefs and metadata
//! - RomFs - A file system used to contain game assets
//! - RomFs patch - used to patch the RomFs when distributing updates
//!
//! For more information about the NCA file format, see the [switchbrew page].
//!
//! In order to parse an NCA, you may use the `from_file` method:
//!
//! ```
//! use std::fs::File;
//! use linkle::format::nca::Nca;
//! use linkle::pki::Keys;
//!
//! let pki = Keys::new(None, false)?;
//! let f = File::open("tests/fixtures/test.nca")?;
//! let nca = Nca::from_file(&pki, nca, None)?;
//! let section = nca.raw_section(0);
//! ```
//!
//! Writing NCA files is not yet implemented.
//!
//! [switchbrew page]: https://switchbrew.org/w/index.php?title=NCA_Format

use crate::error::Error;
use crate::format::nca::structures::{ContentType, CryptoType, KeyType, RawNca};
use crate::pki::{Aes128Key, AesXtsKey, KeyName, Keys, TitleKey};
use binrw::BinRead;
use serde::{Deserialize, Serialize};
use snafu::{Backtrace, GenerateImplicitData};
use std::cmp::max;
use std::io::{Read, Seek};

mod crypto_stream;
mod structures;

pub use crate::format::nca::crypto_stream::CryptoStream;
use crate::format::nca::crypto_stream::CryptoStreamState;
use crate::utils::{ReadRange, TryClone};
pub use structures::{
    BktrSuperblock, NcaMagic, Pfs0Superblock, RightsId, RomfsSuperblock, SdkVersion, SigDebug,
    Superblock, TitleId,
};

/// Contains information about NCA section collected from the header.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NcaSectionInfo {
    /// Offset of the section in the NCA file.
    pub media_start_offset: u64,
    /// Offset of the end of the section in the NCA file.
    pub media_end_offset: u64,
    /// Cryptographic algorithm & key used to decrypt the section.
    pub crypto: NcaCrypto,
    /// Nonce used to decrypt the section.
    pub nonce: u64,
    /// Superblock of the section filesystem.
    pub superblock: Superblock,
}

impl NcaSectionInfo {
    /// Get size of the section.
    fn size(&self) -> u64 {
        self.media_end_offset - self.media_start_offset
    }
}

/// Contains information about NCA collected from the header.
#[derive(Debug, Serialize, Deserialize)]
pub struct NcaInfo {
    pub format: NcaMagic,
    pub sig: SigDebug,
    pub npdm_sig: SigDebug,
    pub is_gamecard: bool,
    pub content_type: ContentType,
    pub key_revision: u8,
    pub key_type: KeyType,
    pub nca_size: u64,
    pub title_id: TitleId,
    pub sdk_version: SdkVersion,
    pub rights_id: RightsId,
    pub sections: [Option<NcaSectionInfo>; 4],
}

/// Represents an open NCA file available for reading.
#[derive(Debug)]
pub struct Nca<R> {
    stream: R,
    info: NcaInfo,
}

fn get_key_area_key(pki: &Keys, key_version: u8, key_type: KeyType) -> Result<Aes128Key, Error> {
    let key_name = match key_type {
        KeyType::Application => KeyName::KeyAreaKeyApplication(key_version),
        KeyType::Ocean => KeyName::KeyAreaKeyOcean(key_version),
        KeyType::System => KeyName::KeyAreaKeySystem(key_version),
    };
    pki.get_key(key_name)
}

// Crypto is stupid. First, we need to get the max of crypto_type and crypto_type2.
// Then, nintendo uses both 0 and 1 as master key 0, and then everything is shifted by one.
// So we sub by 1.
fn get_master_key_revision(crypto_type: u8, crypto_type2: u8) -> u8 {
    max(crypto_type2, crypto_type).saturating_sub(1)
}

fn decrypt_header(pki: &Keys, file: &mut dyn Read) -> Result<RawNca, Error> {
    // Decrypt header.
    let mut header = [0; 0xC00];

    file.read_exact(&mut header)?;

    // NOTE: no support for decrypted NCAs

    let header_key = pki.get_xts_key(KeyName::HeaderKey)?;

    let mut raw_nca = std::io::Cursor::new(header);
    let raw_nca =
        RawNca::read_le_args(&mut raw_nca, (header_key,)).expect("RawNca to be of the right size");
    Ok(raw_nca)
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum NcaCrypto {
    /// No ecryption, the section is in plaintext.
    None,
    /// AES-128-CTR encryption
    Ctr(Aes128Key),
    /// Special variation of AES-128-CTR used for RomFs patching in updates
    Bktr(Aes128Key),
    /// AES-128-XTS encryption (TODO: where is it used?)
    Xts(AesXtsKey),
}

impl<R: Read> Nca<R> {
    pub fn from_file(
        pki: &Keys,
        mut file: R,
        title_key: Option<TitleKey>, // TODO: get titlekey from a DB?
    ) -> Result<Nca<R>, Error> {
        let RawNca {
            sigs,
            header,
            fs_headers,
        } = decrypt_header(pki, &mut file)?;

        // TODO: NCA: Verify header with RSA2048 PSS
        // BODY: We want to make sure the NCAs have a valid signature before
        // BODY: decrypting. Maybe put it behind a flag that accepts invalidly
        // BODY: signed NCAs?

        let master_key_revision = get_master_key_revision(header.crypto_type, header.crypto_type2);

        // Handle Rights ID.
        let has_rights_id = !header.rights_id.is_empty();

        let key_area_key = get_key_area_key(pki, master_key_revision, header.key_type)?;

        let ctr_crypto_key = key_area_key.derive_key(&header.encrypted_ctr_key)?;
        let xts_crypto_key = key_area_key.derive_xts_key(&header.encrypted_xts_key)?;
        let title_key = if has_rights_id {
            let titlekek = pki.get_key(KeyName::Titlekek(master_key_revision))?;

            Some(
                titlekek.derive_key(
                    &title_key
                        .ok_or_else(|| Error::MissingTitleKey {
                            rights_id: header.rights_id,
                            backtrace: Backtrace::generate(),
                        })?
                        .0,
                )?,
            )
        } else {
            None
        };

        // Parse sections
        let mut sections = [None, None, None, None];
        for (idx, (section, fs)) in header
            .section_entries
            .iter()
            .zip(fs_headers.iter())
            .enumerate()
        {
            // Check if section is present
            if let Some(fs) = fs {
                let crypto = if has_rights_id {
                    match fs.crypt_type {
                        CryptoType::Ctr => NcaCrypto::Ctr(title_key.unwrap()),
                        CryptoType::Bktr => NcaCrypto::Bktr(title_key.unwrap()),
                        CryptoType::None => NcaCrypto::None,
                        CryptoType::Xts => unreachable!("Xts is not supported for RightsId crypto"),
                    }
                } else {
                    match fs.crypt_type {
                        CryptoType::None => NcaCrypto::None,
                        CryptoType::Xts => NcaCrypto::Xts(xts_crypto_key),
                        CryptoType::Ctr => NcaCrypto::Ctr(ctr_crypto_key),
                        CryptoType::Bktr => NcaCrypto::Bktr(ctr_crypto_key),
                    }
                };

                sections[idx] = Some(NcaSectionInfo {
                    crypto,
                    superblock: fs.superblock,
                    nonce: fs.section_ctr,
                    media_start_offset: section.media_start_offset as u64 * 0x200,
                    media_end_offset: section.media_end_offset as u64 * 0x200,
                });
            }
        }

        let nca = Nca {
            stream: file,
            info: NcaInfo {
                format: header.magic,
                sig: sigs.fixed_key_sig,
                npdm_sig: sigs.npdm_sig,
                is_gamecard: header.is_gamecard,
                content_type: header.content_type,
                key_revision: master_key_revision,
                key_type: header.key_type,
                nca_size: header.nca_size,
                title_id: header.title_id,
                sdk_version: header.sdk_version,
                rights_id: header.rights_id,
                sections,
            },
        };

        Ok(nca)
    }
}

impl<R: TryClone + Seek> Nca<R> {
    /// Get access to raw reader for a specific section.
    ///
    /// Note: this provides access to the raw NCA section data, doing just the decryption.
    /// It does not perform any hash verification, or any other checks
    ///     (as these are dependent on the FS inside the section).
    pub fn raw_section(&self, id: usize) -> Result<CryptoStream<ReadRange<R>>, Error> {
        if let Some(section) = &self.info.sections[id] {
            // TODO: Nca::raw_section should reopen the file, not dup2 the handle.
            // (why though?)
            let mut stream = self.stream.try_clone()?;
            stream.seek(std::io::SeekFrom::Start(section.media_start_offset))?;

            Ok(CryptoStream {
                stream: ReadRange::new(stream, section.media_start_offset, section.size()),
                // Keep a 1-block large buffer of data in case of partial reads.
                buffer: [0; 0x10],
                state: CryptoStreamState {
                    json: section.clone(),
                    offset: 0, // the offset is relative to the start of the section
                },
            })
        } else {
            Err(Error::MissingSection {
                index: id,
                backtrace: Backtrace::generate(),
            })
        }
    }
}

impl<R> Nca<R> {
    pub fn info(&self) -> &NcaInfo {
        &self.info
    }
}
