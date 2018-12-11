use std::fmt;
use ini::{self, ini::Properties};
use failure::Backtrace;
use std::fs::File;
use std::io::{self, ErrorKind};
use std::path::Path;
use error::Error;
use aes::Aes128;
use block_modes::{Ctr128, BlockModeIv, BlockMode};
use block_modes::block_padding::ZeroPadding;
use aes::block_cipher_trait::generic_array::GenericArray;
use aes::block_cipher_trait::BlockCipher;

struct Aes128Key([u8; 0x10]);
struct AesXtsKey([u8; 0x20]);
struct EncryptedKeyblob([u8; 0xB0]);
struct Keyblob([u8; 0x90]);
struct Modulus([u8; 0x100]);

macro_rules! impl_debug {
    ($for:ident) => {
        impl fmt::Debug for $for {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                for byte in &self.0[..] {
                    write!(f, "{:02X}", byte)?;
                }
                Ok(())
            }
        }
    }
}

impl_debug!(Aes128Key);
impl_debug!(AesXtsKey);
impl_debug!(EncryptedKeyblob);
impl_debug!(Keyblob);
impl_debug!(Modulus);

impl EncryptedKeyblob {
    fn decrypt(&self, key: &Aes128Key) -> Result<Keyblob, Error> {
        let mut keyblob = [0; 0x90];
        keyblob.copy_from_slice(&self.0[0x20..]);

        let mut crypter = Ctr128::<Aes128, ZeroPadding>::new_fixkey(GenericArray::from_slice(&key.0), GenericArray::from_slice(&self.0[0x10..0x20]));
        crypter.decrypt_nopad(&mut keyblob)?;

        Ok(Keyblob(keyblob))
    }
}

impl Aes128Key {
    fn derive_key(&self, source: &[u8; 0x10]) -> Result<Aes128Key, Error> {
        let mut newkey = *source;

        let crypter = Aes128::new(GenericArray::from_slice(&self.0));
        crypter.decrypt_block(GenericArray::from_mut_slice(&mut newkey));

        Ok(Aes128Key(newkey))
    }

    fn derive_xts_key(&self, source: &[u8; 0x20]) -> Result<AesXtsKey, Error> {
        let mut newkey = *source;

        let crypter = Aes128::new(GenericArray::from_slice(&self.0));
        crypter.decrypt_block(GenericArray::from_mut_slice(&mut newkey[0x00..0x10]));
        crypter.decrypt_block(GenericArray::from_mut_slice(&mut newkey[0x10..0x20]));

        Ok(AesXtsKey(newkey))

    }
}

fn key_to_aes(keys: &Properties, name: &str, key: &mut [u8]) -> Result<Option<()>, Error> {
    let value = keys.get(name);
    if let Some(value) = value {
        if value.len() != key.len() * 2 {
            return Err(Error::Crypto(format!("Key {} is not of the right size. It should be a {} byte hexstring", name, key.len() * 2), Backtrace::new()));
        }
        for (idx, c) in value.bytes().enumerate() {
            let c = match c {
                b'a'..=b'z' => c - b'a' + 10,
                b'A'..=b'Z' => c - b'A' + 10,
                b'0'..=b'9' => c - b'0',
                c => return Err(Error::Crypto(format!("Key {} contains invalid character {}. Each character should be a hexadecimal digit.", name, c as char), Backtrace::new()))
            };
            key[idx / 2] |= c << if idx % 2 == 0 { 4 } else { 0 };
        }
        Ok(Some(()))
    } else {
        Ok(None)
    }
}

fn key_to_aes_array(keys: &Properties, name: &str, idx: usize, key: &mut [u8]) -> Result<Option<()>, Error> {
    key_to_aes(keys, &format!("{}_{:02x}", name, idx), key)
}

trait OptionExt {
    fn or_in(&mut self, other: Self) -> &mut Self;
}

impl<T> OptionExt for Option<T> {
    fn or_in(&mut self, other: Self) -> &mut Self {
        let new = self.take().or(other);
        *self = new;
        self
    }
}

#[derive(Default, Debug)]
pub struct Keys {
    secure_boot_key: Option<Aes128Key>,
    tsec_key: Option<Aes128Key>,
    keyblob_keys: [Option<Aes128Key>; 0x20],
    keyblob_mac_keys: [Option<Aes128Key>; 0x20],
    encrypted_keyblobs: [Option<EncryptedKeyblob>; 0x20],
    keyblobs: [Option<Keyblob>; 0x20],
    keyblob_key_sources: [Option<Aes128Key>; 0x20],
    keyblob_mac_key_source: Option<Aes128Key>,
    tsec_root_key: Option<Aes128Key>,
    master_kek_sources: [Option<Aes128Key>; 0x20],
    master_keks: [Option<Aes128Key>; 0x20],
    master_key_source: Option<Aes128Key>,
    master_keys: [Option<Aes128Key>; 0x20],
    package1_keys: [Option<Aes128Key>; 0x20],
    package2_keys: [Option<Aes128Key>; 0x20],
    package2_key_source: Option<Aes128Key>,
    aes_kek_generation_source: Option<Aes128Key>,
    aes_key_generation_source: Option<Aes128Key>,
    key_area_key_application_source: Option<Aes128Key>,
    key_area_key_ocean_source: Option<Aes128Key>,
    key_area_key_system_source: Option<Aes128Key>,
    titlekek_source: Option<Aes128Key>,
    header_kek_source: Option<Aes128Key>,
    sd_card_kek_source: Option<Aes128Key>,
    sd_card_save_key_source: Option<AesXtsKey>,
    sd_card_nca_key_source: Option<AesXtsKey>,
    save_mac_kek_source: Option<Aes128Key>,
    save_mac_key_source: Option<Aes128Key>,
    header_key_source: Option<AesXtsKey>,
    header_key: Option<AesXtsKey>,
    titlekeks: [Option<Aes128Key>; 0x20],
    key_area_key_application: [Option<Aes128Key>; 0x20],
    key_area_key_ocean: [Option<Aes128Key>; 0x20],
    key_area_key_system: [Option<Aes128Key>; 0x20],
    sd_card_save_key: Option<AesXtsKey>,
    sd_card_nca_key: Option<AesXtsKey>,
    nca_hdr_fixed_key_modulus: Option<Modulus>,
    acid_fixed_key_modulus: Option<Modulus>,
    package2_fixed_key_modulus: Option<Modulus>,
}

macro_rules! make_key_macros {
    ($self:ident, $section:ident) => {
        macro_rules! single_key {
            ($keyname:tt) => {
                let mut key = [0; 0x10];
                $self.$keyname.or_in(key_to_aes($section, stringify!($keyname), &mut key)?.map(|()| Aes128Key(key)));
            }
        }

        macro_rules! single_key_xts {
            ($keyname:tt) => {
                let mut key = [0; 0x20];
                $self.$keyname.or_in(key_to_aes($section, stringify!($keyname), &mut key)?.map(|()| AesXtsKey(key)));
            }
        }

        macro_rules! multi_key {
            ($keyname:tt) => {
                for (idx, v) in $self.$keyname.iter_mut().enumerate() {
                    let mut key = [0; 0x10];
                    // remove trailing s
                    let mut name = String::from(stringify!($keyname));
                    name.pop();
                    v.or_in(key_to_aes_array($section, &name, idx, &mut key)?.map(|()| Aes128Key(key)));
                }
            }
        }

        macro_rules! multi_keyblob {
            ($keyname:tt) => {
                for (idx, v) in $self.$keyname.iter_mut().enumerate() {
                    let mut key = [0; 0x90];
                    // remove trailing s
                    let mut name = String::from(stringify!($keyname));
                    if name.bytes().last() == Some(b's') {
                        name.pop();
                    }
                    v.or_in(key_to_aes_array($section, &name, idx, &mut key)?.map(|()| Keyblob(key)));
                }
            }
        }

        macro_rules! multi_encrypted_keyblob {
            ($keyname:tt) => {
                for (idx, v) in $self.$keyname.iter_mut().enumerate() {
                    let mut key = [0; 0xB0];
                    // remove trailing s
                    let mut name = String::from(stringify!($keyname));
                    name.pop();
                    v.or_in(key_to_aes_array($section, &name, idx, &mut key)?.map(|()| EncryptedKeyblob(key)));
                }
            }
        }
    }
}

fn generate_kek(src: &Aes128Key, master_key: &Aes128Key, kek_seed: &Aes128Key, key_seed: &Aes128Key) -> Result<Aes128Key, Error> {
    let kek = master_key.derive_key(&kek_seed.0)?;
    let src_kek = kek.derive_key(&src.0)?;
    src_kek.derive_key(&key_seed.0)
}

impl Keys {
    fn new(key_path: Option<&Path>, default_key_name: &Path, modulus: (Modulus, Modulus, Modulus)) -> Result<Keys, Error> {
        let (modulus0, modulus1, modulus2) = modulus;
        let mut keys = Keys {
            nca_hdr_fixed_key_modulus: Some(modulus0),
            acid_fixed_key_modulus: Some(modulus1),
            package2_fixed_key_modulus: Some(modulus2),
            ..Default::default()
        };


        let paths = if let Some(key_path) = key_path {
            vec![Some(key_path.into())]
        } else {
            vec![
                dirs::config_dir().map(|mut v| { v.push("switch"); v.push(default_key_name); v }),
                dirs::home_dir().map(|mut v| { v.push(".switch"); v.push(default_key_name); v }),
            ]
        };

        let mut succeed = false;
        for path in paths {
            if let Some(path) = path {
                match File::open(&path) {
                    Ok(file) => {
                        keys.read_from_ini(file)?;
                        succeed = true;
                        break;
                    },
                    Err(ref err) if err.kind() == ErrorKind::NotFound => (),
                    Err(err) => println!("Failed to open {}: {}", path.display(), err),
                }
            }
        }

        if !succeed {
            Err(io::Error::new(ErrorKind::NotFound, "Keyfile not found."))?;
        }

        keys.derive_keys()?;
        Ok(keys)
    }

    pub fn new_retail(key_path: Option<&Path>) -> Result<Keys, Error> {
        Keys::new(key_path, Path::new("prod.keys"), (
            /* nca_hdr_fixed_key_modulus: */ Modulus([
                0xBF, 0xBE, 0x40, 0x6C, 0xF4, 0xA7, 0x80, 0xE9, 0xF0, 0x7D, 0x0C, 0x99, 0x61, 0x1D, 0x77, 0x2F,
                0x96, 0xBC, 0x4B, 0x9E, 0x58, 0x38, 0x1B, 0x03, 0xAB, 0xB1, 0x75, 0x49, 0x9F, 0x2B, 0x4D, 0x58,
                0x34, 0xB0, 0x05, 0xA3, 0x75, 0x22, 0xBE, 0x1A, 0x3F, 0x03, 0x73, 0xAC, 0x70, 0x68, 0xD1, 0x16,
                0xB9, 0x04, 0x46, 0x5E, 0xB7, 0x07, 0x91, 0x2F, 0x07, 0x8B, 0x26, 0xDE, 0xF6, 0x00, 0x07, 0xB2,
                0xB4, 0x51, 0xF8, 0x0D, 0x0A, 0x5E, 0x58, 0xAD, 0xEB, 0xBC, 0x9A, 0xD6, 0x49, 0xB9, 0x64, 0xEF,
                0xA7, 0x82, 0xB5, 0xCF, 0x6D, 0x70, 0x13, 0xB0, 0x0F, 0x85, 0xF6, 0xA9, 0x08, 0xAA, 0x4D, 0x67,
                0x66, 0x87, 0xFA, 0x89, 0xFF, 0x75, 0x90, 0x18, 0x1E, 0x6B, 0x3D, 0xE9, 0x8A, 0x68, 0xC9, 0x26,
                0x04, 0xD9, 0x80, 0xCE, 0x3F, 0x5E, 0x92, 0xCE, 0x01, 0xFF, 0x06, 0x3B, 0xF2, 0xC1, 0xA9, 0x0C,
                0xCE, 0x02, 0x6F, 0x16, 0xBC, 0x92, 0x42, 0x0A, 0x41, 0x64, 0xCD, 0x52, 0xB6, 0x34, 0x4D, 0xAE,
                0xC0, 0x2E, 0xDE, 0xA4, 0xDF, 0x27, 0x68, 0x3C, 0xC1, 0xA0, 0x60, 0xAD, 0x43, 0xF3, 0xFC, 0x86,
                0xC1, 0x3E, 0x6C, 0x46, 0xF7, 0x7C, 0x29, 0x9F, 0xFA, 0xFD, 0xF0, 0xE3, 0xCE, 0x64, 0xE7, 0x35,
                0xF2, 0xF6, 0x56, 0x56, 0x6F, 0x6D, 0xF1, 0xE2, 0x42, 0xB0, 0x83, 0x40, 0xA5, 0xC3, 0x20, 0x2B,
                0xCC, 0x9A, 0xAE, 0xCA, 0xED, 0x4D, 0x70, 0x30, 0xA8, 0x70, 0x1C, 0x70, 0xFD, 0x13, 0x63, 0x29,
                0x02, 0x79, 0xEA, 0xD2, 0xA7, 0xAF, 0x35, 0x28, 0x32, 0x1C, 0x7B, 0xE6, 0x2F, 0x1A, 0xAA, 0x40,
                0x7E, 0x32, 0x8C, 0x27, 0x42, 0xFE, 0x82, 0x78, 0xEC, 0x0D, 0xEB, 0xE6, 0x83, 0x4B, 0x6D, 0x81,
                0x04, 0x40, 0x1A, 0x9E, 0x9A, 0x67, 0xF6, 0x72, 0x29, 0xFA, 0x04, 0xF0, 0x9D, 0xE4, 0xF4, 0x03
            ]),
            /* acid_fixed_key_modulus: */ Modulus([
                0xDD, 0xC8, 0xDD, 0xF2, 0x4E, 0x6D, 0xF0, 0xCA, 0x9E, 0xC7, 0x5D, 0xC7, 0x7B, 0xAD, 0xFE, 0x7D,
                0x23, 0x89, 0x69, 0xB6, 0xF2, 0x06, 0xA2, 0x02, 0x88, 0xE1, 0x55, 0x91, 0xAB, 0xCB, 0x4D, 0x50,
                0x2E, 0xFC, 0x9D, 0x94, 0x76, 0xD6, 0x4C, 0xD8, 0xFF, 0x10, 0xFA, 0x5E, 0x93, 0x0A, 0xB4, 0x57,
                0xAC, 0x51, 0xC7, 0x16, 0x66, 0xF4, 0x1A, 0x54, 0xC2, 0xC5, 0x04, 0x3D, 0x1B, 0xFE, 0x30, 0x20,
                0x8A, 0xAC, 0x6F, 0x6F, 0xF5, 0xC7, 0xB6, 0x68, 0xB8, 0xC9, 0x40, 0x6B, 0x42, 0xAD, 0x11, 0x21,
                0xE7, 0x8B, 0xE9, 0x75, 0x01, 0x86, 0xE4, 0x48, 0x9B, 0x0A, 0x0A, 0xF8, 0x7F, 0xE8, 0x87, 0xF2,
                0x82, 0x01, 0xE6, 0xA3, 0x0F, 0xE4, 0x66, 0xAE, 0x83, 0x3F, 0x4E, 0x9F, 0x5E, 0x01, 0x30, 0xA4,
                0x00, 0xB9, 0x9A, 0xAE, 0x5F, 0x03, 0xCC, 0x18, 0x60, 0xE5, 0xEF, 0x3B, 0x5E, 0x15, 0x16, 0xFE,
                0x1C, 0x82, 0x78, 0xB5, 0x2F, 0x47, 0x7C, 0x06, 0x66, 0x88, 0x5D, 0x35, 0xA2, 0x67, 0x20, 0x10,
                0xE7, 0x6C, 0x43, 0x68, 0xD3, 0xE4, 0x5A, 0x68, 0x2A, 0x5A, 0xE2, 0x6D, 0x73, 0xB0, 0x31, 0x53,
                0x1C, 0x20, 0x09, 0x44, 0xF5, 0x1A, 0x9D, 0x22, 0xBE, 0x12, 0xA1, 0x77, 0x11, 0xE2, 0xA1, 0xCD,
                0x40, 0x9A, 0xA2, 0x8B, 0x60, 0x9B, 0xEF, 0xA0, 0xD3, 0x48, 0x63, 0xA2, 0xF8, 0xA3, 0x2C, 0x08,
                0x56, 0x52, 0x2E, 0x60, 0x19, 0x67, 0x5A, 0xA7, 0x9F, 0xDC, 0x3F, 0x3F, 0x69, 0x2B, 0x31, 0x6A,
                0xB7, 0x88, 0x4A, 0x14, 0x84, 0x80, 0x33, 0x3C, 0x9D, 0x44, 0xB7, 0x3F, 0x4C, 0xE1, 0x75, 0xEA,
                0x37, 0xEA, 0xE8, 0x1E, 0x7C, 0x77, 0xB7, 0xC6, 0x1A, 0xA2, 0xF0, 0x9F, 0x10, 0x61, 0xCD, 0x7B,
                0x5B, 0x32, 0x4C, 0x37, 0xEF, 0xB1, 0x71, 0x68, 0x53, 0x0A, 0xED, 0x51, 0x7D, 0x35, 0x22, 0xFD
            ]),
            /* package2_fixed_key_modulus: */ Modulus([
                0x8D, 0x13, 0xA7, 0x77, 0x6A, 0xE5, 0xDC, 0xC0, 0x3B, 0x25, 0xD0, 0x58, 0xE4, 0x20, 0x69, 0x59,
                0x55, 0x4B, 0xAB, 0x70, 0x40, 0x08, 0x28, 0x07, 0xA8, 0xA7, 0xFD, 0x0F, 0x31, 0x2E, 0x11, 0xFE,
                0x47, 0xA0, 0xF9, 0x9D, 0xDF, 0x80, 0xDB, 0x86, 0x5A, 0x27, 0x89, 0xCD, 0x97, 0x6C, 0x85, 0xC5,
                0x6C, 0x39, 0x7F, 0x41, 0xF2, 0xFF, 0x24, 0x20, 0xC3, 0x95, 0xA6, 0xF7, 0x9D, 0x4A, 0x45, 0x74,
                0x8B, 0x5D, 0x28, 0x8A, 0xC6, 0x99, 0x35, 0x68, 0x85, 0xA5, 0x64, 0x32, 0x80, 0x9F, 0xD3, 0x48,
                0x39, 0xA2, 0x1D, 0x24, 0x67, 0x69, 0xDF, 0x75, 0xAC, 0x12, 0xB5, 0xBD, 0xC3, 0x29, 0x90, 0xBE,
                0x37, 0xE4, 0xA0, 0x80, 0x9A, 0xBE, 0x36, 0xBF, 0x1F, 0x2C, 0xAB, 0x2B, 0xAD, 0xF5, 0x97, 0x32,
                0x9A, 0x42, 0x9D, 0x09, 0x8B, 0x08, 0xF0, 0x63, 0x47, 0xA3, 0xE9, 0x1B, 0x36, 0xD8, 0x2D, 0x8A,
                0xD7, 0xE1, 0x54, 0x11, 0x95, 0xE4, 0x45, 0x88, 0x69, 0x8A, 0x2B, 0x35, 0xCE, 0xD0, 0xA5, 0x0B,
                0xD5, 0x5D, 0xAC, 0xDB, 0xAF, 0x11, 0x4D, 0xCA, 0xB8, 0x1E, 0xE7, 0x01, 0x9E, 0xF4, 0x46, 0xA3,
                0x8A, 0x94, 0x6D, 0x76, 0xBD, 0x8A, 0xC8, 0x3B, 0xD2, 0x31, 0x58, 0x0C, 0x79, 0xA8, 0x26, 0xE9,
                0xD1, 0x79, 0x9C, 0xCB, 0xD4, 0x2B, 0x6A, 0x4F, 0xC6, 0xCC, 0xCF, 0x90, 0xA7, 0xB9, 0x98, 0x47,
                0xFD, 0xFA, 0x4C, 0x6C, 0x6F, 0x81, 0x87, 0x3B, 0xCA, 0xB8, 0x50, 0xF6, 0x3E, 0x39, 0x5D, 0x4D,
                0x97, 0x3F, 0x0F, 0x35, 0x39, 0x53, 0xFB, 0xFA, 0xCD, 0xAB, 0xA8, 0x7A, 0x62, 0x9A, 0x3F, 0xF2,
                0x09, 0x27, 0x96, 0x3F, 0x07, 0x9A, 0x91, 0xF7, 0x16, 0xBF, 0xC6, 0x3A, 0x82, 0x5A, 0x4B, 0xCF,
                0x49, 0x50, 0x95, 0x8C, 0x55, 0x80, 0x7E, 0x39, 0xB1, 0x48, 0x05, 0x1E, 0x21, 0xC7, 0x24, 0x4F
            ])
        ))
    }

    fn read_from_ini(&mut self, mut file: File) -> Result<(), Error> {
        let config = ini::Ini::read_from(&mut file)?;
        let section = config.general_section();

        make_key_macros!(self, section);
        single_key!(secure_boot_key);
        single_key!(tsec_key);
        multi_key!(keyblob_keys);
        multi_key!(keyblob_mac_keys);
        multi_key!(keyblob_key_sources);
        multi_encrypted_keyblob!(encrypted_keyblobs);
        multi_keyblob!(keyblobs);
        single_key!(keyblob_mac_key_source);
        single_key!(tsec_root_key);
        multi_key!(master_kek_sources);
        multi_key!(master_keks);
        single_key!(master_key_source);
        multi_key!(master_keys);
        multi_key!(package1_keys);
        multi_key!(package2_keys);
        single_key!(package2_key_source);
        single_key!(aes_kek_generation_source);
        single_key!(aes_key_generation_source);
        single_key!(key_area_key_application_source);
        single_key!(key_area_key_ocean_source);
        single_key!(key_area_key_system_source);
        single_key!(titlekek_source);
        single_key!(header_kek_source);
        single_key!(sd_card_kek_source);
        single_key_xts!(sd_card_save_key_source);
        single_key_xts!(sd_card_nca_key_source);
        single_key!(save_mac_kek_source);
        single_key!(save_mac_key_source);
        single_key_xts!(header_key_source);
        single_key_xts!(header_key);
        multi_key!(titlekeks);
        multi_key!(key_area_key_application);
        multi_key!(key_area_key_ocean);
        multi_key!(key_area_key_system);
        single_key_xts!(sd_card_save_key);
        single_key_xts!(sd_card_nca_key);
        Ok(())
    }

    pub fn derive_keys(&mut self) -> Result<(), Error> {
        for i in 0..6 {
            /* Derive the keyblob_keys */
            match (&self.secure_boot_key, &self.tsec_key, &self.keyblob_key_sources[i]) {
                (Some(sbk), Some(tsec_key), Some(keyblob_key_source)) => {
                    let tmp = tsec_key.derive_key(&keyblob_key_source.0)?;
                    self.keyblob_keys[i] = Some(sbk.derive_key(&tmp.0)?);
                },
                _ => continue
            }
        }
        for i in 0..6 {
            /* Derive the keyblob mac keys */
            match (&self.keyblob_keys[i], &self.keyblob_mac_key_source) {
                (Some(keyblob_key), Some(keyblob_mac_key_source)) => {
                    self.keyblob_mac_keys[i] = Some(keyblob_key.derive_key(&keyblob_mac_key_source.0)?);
                },
                _ => continue
            }
        }
        for i in 0..6 {
            match (&self.keyblob_keys[i], &self.keyblob_mac_keys[i], &self.encrypted_keyblobs[i]) {
                (Some(keyblob_key), Some(_keyblob_mac_key), Some(encrypted_keyblob)) => {
                    // TODO: Calculate cmac
                    self.keyblobs[i] = Some(encrypted_keyblob.decrypt(keyblob_key)?);
                },
                _ => continue
            }
        }
        for i in 0..6 {
            /* set package1_key and master_kek as relevant */
            if let Some(keyblob) = &self.keyblobs[i] {
                let mut keysource = [0; 0x10];
                keysource.copy_from_slice(&keyblob.0[0x80..0x90]);
                self.package1_keys[i] = Some(Aes128Key(keysource));
                let mut keysource = [0; 0x10];
                keysource.copy_from_slice(&keyblob.0[0x00..0x10]);
                self.master_keks[i] = Some(Aes128Key(keysource));
            }
        }
        for i in 6..0x20 {
            /* Do keygen for 6.2.0+ */
            match (&self.tsec_root_key, &self.master_kek_sources[i]) {
                (Some(tsec_root_key), Some(master_kek_source)) => {
                    self.master_keks[i] = Some(tsec_root_key.derive_key(&master_kek_source.0)?);
                },
                _ => continue
            }
        }
        for i in 0..0x20 {
            /* Derive the master keys! */
            match (&self.master_key_source, &self.master_keks[i]) {
                (Some(master_key_source), Some(master_kek)) => {
                    self.master_keys[i] = Some(master_kek.derive_key(&master_key_source.0)?);
                },
                _ => continue
            }
        }
        for i in 0..0x20 {
            if let Some(master_key) = &self.master_keys[i] {
                /* Derive key area encryption key */
                match (&self.key_area_key_application_source, &self.aes_kek_generation_source, &self.aes_key_generation_source) {
                    (Some(key_area_key_application_source), Some(aes_kek_generation_source), Some(aes_key_generation_source)) => {
                        self.key_area_key_application[i] = Some(generate_kek(key_area_key_application_source, master_key, aes_kek_generation_source, aes_key_generation_source)?);
                    },
                    _ => continue
                }
                match (&self.key_area_key_ocean_source, &self.aes_kek_generation_source, &self.aes_key_generation_source) {
                    (Some(key_area_key_ocean_source), Some(aes_kek_generation_source), Some(aes_key_generation_source)) => {
                        self.key_area_key_ocean[i] = Some(generate_kek(key_area_key_ocean_source, master_key, aes_kek_generation_source, aes_key_generation_source)?);
                    },
                    _ => continue
                }
                match (&self.key_area_key_system_source, &self.aes_kek_generation_source, &self.aes_key_generation_source) {
                    (Some(key_area_key_system_source), Some(aes_kek_generation_source), Some(aes_key_generation_source)) => {
                        self.key_area_key_system[i] = Some(generate_kek(key_area_key_system_source, master_key, aes_kek_generation_source, aes_key_generation_source)?);
                    },
                    _ => continue
                }
                /* Derive titlekek */
                if let Some(titlekek_source) = &self.titlekek_source {
                    self.titlekeks[i] = Some(master_key.derive_key(&titlekek_source.0)?);
                }

                /* Derive Package2 key */
                if let Some(package2_key_source) = &self.package2_key_source {
                    self.package2_keys[i] = Some(master_key.derive_key(&package2_key_source.0)?);
                }

                /* Derive Header Key */
                match (i, &self.header_kek_source, &self.header_key_source, &self.aes_kek_generation_source, &self.aes_key_generation_source) {
                    (0, Some(header_kek_source), Some(header_key_source), Some(aes_kek_generation_source), Some(aes_key_generation_source)) => {
                        let header_kek = generate_kek(&header_kek_source, master_key, &aes_kek_generation_source, &aes_key_generation_source)?;
                        self.header_key = Some(header_kek.derive_xts_key(&header_key_source.0)?);
                    },
                    _ => ()
                }
                /* Derive SD Card key */
                match (&self.sd_card_kek_source, &self.aes_kek_generation_source, &self.aes_key_generation_source) {
                    (Some(sd_card_kek_source), Some(aes_kek_generation_source), Some(aes_key_generation_source)) => {
                        let sd_kek = generate_kek(sd_card_kek_source, master_key, aes_kek_generation_source, aes_key_generation_source)?;
                        if let Some(sd_card_save_key_source) = &self.sd_card_save_key_source {
                            self.sd_card_save_key = Some(sd_kek.derive_xts_key(&sd_card_save_key_source.0)?);
                        }
                        if let Some(sd_card_nca_key_source) = &self.sd_card_nca_key_source {
                            self.sd_card_nca_key = Some(sd_kek.derive_xts_key(&sd_card_nca_key_source.0)?);
                        }
                    },
                    _ => continue
                }
            }
        }
        Ok(())
    }
}
