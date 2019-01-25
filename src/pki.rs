use std::fmt;
use ini::{self, ini::Properties};
use failure::Backtrace;
use std::fs::File;
use std::io::{self, ErrorKind};
use std::path::Path;
use crate::error::Error;
use aes::Aes128;
use cmac::Cmac;
use block_modes::{Ctr128, Xts128, BlockModeIv, BlockMode};
use block_modes::block_padding::ZeroPadding;
use aes::block_cipher_trait::generic_array::GenericArray;
use aes::block_cipher_trait::BlockCipher;
use getset::Getters;
use cmac::crypto_mac::Mac;

#[derive(Clone, Copy)]
pub struct Aes128Key([u8; 0x10]);
#[derive(Clone, Copy)]
pub struct AesXtsKey([u8; 0x20]);
pub struct EncryptedKeyblob([u8; 0xB0]);
pub struct Keyblob([u8; 0x90]);
pub struct Modulus([u8; 0x100]);

impl_debug_deserialize_serialize_hexstring!(Aes128Key);
impl_debug_deserialize_serialize_hexstring!(AesXtsKey);
impl_debug_deserialize_serialize_hexstring!(EncryptedKeyblob);
impl_debug_deserialize_serialize_hexstring!(Keyblob);
impl_debug_deserialize_serialize_hexstring!(Modulus);

impl Keyblob {
    fn encrypt(&self, key: &Aes128Key, mac_key: &Aes128Key, keyblob_id: usize) -> Result<EncryptedKeyblob, Error> {
        let mut encrypted_keyblob = [0; 0xB0];
        encrypted_keyblob[0x20..].copy_from_slice(&self.0);

        let mut crypter = Ctr128::<Aes128, ZeroPadding>::new_fixkey(GenericArray::from_slice(&key.0), GenericArray::from_slice(&encrypted_keyblob[0x10..0x20]));
        crypter.encrypt_nopad(&mut encrypted_keyblob[0x20..])?;

        let mut cmac = Cmac::<Aes128>::new_varkey(&mac_key.0[..]).unwrap();
        cmac.input(&encrypted_keyblob[0x10..]);
        encrypted_keyblob[..0x10].copy_from_slice(cmac.result().code().as_slice());
        Ok(EncryptedKeyblob(encrypted_keyblob))
    }
}

impl EncryptedKeyblob {
    fn decrypt(&self, key: &Aes128Key, mac_key: &Aes128Key, keyblob_id: usize) -> Result<Keyblob, Error> {
        let mut keyblob = [0; 0x90];
        keyblob.copy_from_slice(&self.0[0x20..]);

        let mut cmac = Cmac::<Aes128>::new_varkey(&mac_key.0[..]).unwrap();
        cmac.input(&self.0[0x10..]);
        cmac.verify(&self.0[..0x10]).map_err(|err| (keyblob_id, err))?;

        let mut crypter = Ctr128::<Aes128, ZeroPadding>::new_fixkey(GenericArray::from_slice(&key.0), GenericArray::from_slice(&self.0[0x10..0x20]));
        crypter.decrypt_nopad(&mut keyblob)?;

        Ok(Keyblob(keyblob))
    }
}

impl Aes128Key {
    /// Decrypt blocks in CTR mode.
    pub fn decrypt_ctr(&self, buf: &mut [u8], ctr: &[u8; 0x10]) -> Result<(), Error> {
        if buf.len() % 16 != 0 {
            return Err(Error::Crypto(String::from("buf length should be a multiple of 16, the size of an AES block."), Backtrace::new()));
        }

        let key = GenericArray::from_slice(&self.0);
        let iv = GenericArray::from_slice(ctr);
        let mut crypter = Ctr128::<Aes128, ZeroPadding>::new_fixkey(key, iv);
        crypter.decrypt_nopad(buf)?;
        Ok(())
    }

    pub fn encrypt_ctr(&self, buf: &mut [u8], ctr: &[u8; 0x10]) -> Result<(), Error> {
        if buf.len() % 16 != 0 {
            return Err(Error::Crypto(String::from("buf length should be a multiple of 16, the size of an AES block."), Backtrace::new()));
        }

        let key = GenericArray::from_slice(&self.0);
        let iv = GenericArray::from_slice(ctr);
        let mut crypter = Ctr128::<Aes128, ZeroPadding>::new_fixkey(key, iv);
        crypter.encrypt_nopad(buf)?;
        Ok(())
    }

    pub fn derive_key(&self, source: &[u8; 0x10]) -> Result<Aes128Key, Error> {
        let mut newkey = *source;

        let crypter = Aes128::new(GenericArray::from_slice(&self.0));
        crypter.decrypt_block(GenericArray::from_mut_slice(&mut newkey));

        Ok(Aes128Key(newkey))
    }

    pub fn encrypt_key(&self, key: &Aes128Key) -> [u8; 0x10] {
        let mut newkey = key.0;

        let crypter = Aes128::new(GenericArray::from_slice(&self.0));
        crypter.encrypt_block(GenericArray::from_mut_slice(&mut newkey));

        newkey
    }

    pub fn derive_xts_key(&self, source: &[u8; 0x20]) -> Result<AesXtsKey, Error> {
        let mut newkey = *source;

        let crypter = Aes128::new(GenericArray::from_slice(&self.0));
        crypter.decrypt_block(GenericArray::from_mut_slice(&mut newkey[0x00..0x10]));
        crypter.decrypt_block(GenericArray::from_mut_slice(&mut newkey[0x10..0x20]));

        Ok(AesXtsKey(newkey))
    }

    pub fn encrypt_xts_key(&self, source: &AesXtsKey) -> [u8; 0x20] {
        let mut newkey = source.0;

        let crypter = Aes128::new(GenericArray::from_slice(&self.0));
        crypter.encrypt_block(GenericArray::from_mut_slice(&mut newkey[0x00..0x10]));
        crypter.encrypt_block(GenericArray::from_mut_slice(&mut newkey[0x10..0x20]));

        newkey
    }
}

fn get_tweak(mut sector: usize) -> [u8; 0x10] {
    let mut tweak = [0; 0x10];
    for tweak in tweak.iter_mut().rev() { /* Nintendo LE custom tweak... */
        *tweak = (sector & 0xFF) as u8;
        sector >>= 8;
    }
    tweak
}

impl AesXtsKey {
    pub fn decrypt(&self, src: &[u8], dst: &mut [u8], mut sector: usize, sector_size: usize) -> Result<(), Error> {
        if src.len() != dst.len() {
            return Err(Error::Crypto(String::from("Src len different from dst len"), Backtrace::new()));
        }
        if src.len() % sector_size != 0 {
            return Err(Error::Crypto(String::from("Length must be multiple of sectors!"), Backtrace::new()));
        }

        dst.copy_from_slice(src);
        for i in (0..src.len()).step_by(sector_size){
            let tweak = get_tweak(sector);

            let key1 = Aes128::new(GenericArray::from_slice(&self.0[0x00..0x10]));
            let key2 = Aes128::new(GenericArray::from_slice(&self.0[0x10..0x20]));
            let mut crypter = Xts128::<Aes128, ZeroPadding>::new(key1, key2, GenericArray::from_slice(&tweak));
            crypter.decrypt_nopad(&mut dst[i..i + sector_size])?;
            sector += 1;
        }
        Ok(())
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

#[derive(Default, Debug, Getters)]
pub struct Keys {
    #[get = "pub"] secure_boot_key: Option<Aes128Key>,
    #[get = "pub"] tsec_key: Option<Aes128Key>,
    #[get = "pub"] keyblob_keys: [Option<Aes128Key>; 0x20],
    #[get = "pub"] keyblob_mac_keys: [Option<Aes128Key>; 0x20],
    #[get = "pub"] encrypted_keyblobs: [Option<EncryptedKeyblob>; 0x20],
    #[get = "pub"] keyblobs: [Option<Keyblob>; 0x20],
    #[get = "pub"] keyblob_key_sources: [Option<Aes128Key>; 0x20],
    #[get = "pub"] keyblob_mac_key_source: Option<Aes128Key>,
    #[get = "pub"] tsec_root_key: Option<Aes128Key>,
    #[get = "pub"] master_kek_sources: [Option<Aes128Key>; 0x20],
    #[get = "pub"] master_keks: [Option<Aes128Key>; 0x20],
    #[get = "pub"] master_key_source: Option<Aes128Key>,
    #[get = "pub"] master_keys: [Option<Aes128Key>; 0x20],
    #[get = "pub"] package1_keys: [Option<Aes128Key>; 0x20],
    #[get = "pub"] package2_keys: [Option<Aes128Key>; 0x20],
    #[get = "pub"] package2_key_source: Option<Aes128Key>,
    #[get = "pub"] aes_kek_generation_source: Option<Aes128Key>,
    #[get = "pub"] aes_key_generation_source: Option<Aes128Key>,
    #[get = "pub"] key_area_key_application_source: Option<Aes128Key>,
    #[get = "pub"] key_area_key_ocean_source: Option<Aes128Key>,
    #[get = "pub"] key_area_key_system_source: Option<Aes128Key>,
    #[get = "pub"] titlekek_source: Option<Aes128Key>,
    #[get = "pub"] header_kek_source: Option<Aes128Key>,
    #[get = "pub"] sd_card_kek_source: Option<Aes128Key>,
    #[get = "pub"] sd_card_save_key_source: Option<AesXtsKey>,
    #[get = "pub"] sd_card_nca_key_source: Option<AesXtsKey>,
    #[get = "pub"] save_mac_kek_source: Option<Aes128Key>,
    #[get = "pub"] save_mac_key_source: Option<Aes128Key>,
    #[get = "pub"] header_key_source: Option<AesXtsKey>,
    #[get = "pub"] header_key: Option<AesXtsKey>,
    #[get = "pub"] titlekeks: [Option<Aes128Key>; 0x20],
    #[get = "pub"] key_area_key_application: [Option<Aes128Key>; 0x20],
    #[get = "pub"] key_area_key_ocean: [Option<Aes128Key>; 0x20],
    #[get = "pub"] key_area_key_system: [Option<Aes128Key>; 0x20],
    #[get = "pub"] sd_card_save_key: Option<AesXtsKey>,
    #[get = "pub"] sd_card_nca_key: Option<AesXtsKey>,
    #[get = "pub"] nca_hdr_fixed_key_modulus: Option<Modulus>,
    #[get = "pub"] acid_fixed_key_modulus: Option<Modulus>,
    #[get = "pub"] package2_fixed_key_modulus: Option<Modulus>,
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
    #[allow(clippy::new_ret_no_self)]
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

    pub fn new_dev(key_path: Option<&Path>) -> Result<Keys, Error> {
        Keys::new(key_path, Path::new("dev.keys"), (
            /* nca_hdr_fixed_key_modulus: */ Modulus([
                0xD8, 0xF1, 0x18, 0xEF, 0x32, 0x72, 0x4C, 0xA7, 0x47, 0x4C, 0xB9, 0xEA, 0xB3, 0x04, 0xA8, 0xA4,
                0xAC, 0x99, 0x08, 0x08, 0x04, 0xBF, 0x68, 0x57, 0xB8, 0x43, 0x94, 0x2B, 0xC7, 0xB9, 0x66, 0x49,
                0x85, 0xE5, 0x8A, 0x9B, 0xC1, 0x00, 0x9A, 0x6A, 0x8D, 0xD0, 0xEF, 0xCE, 0xFF, 0x86, 0xC8, 0x5C,
                0x5D, 0xE9, 0x53, 0x7B, 0x19, 0x2A, 0xA8, 0xC0, 0x22, 0xD1, 0xF3, 0x22, 0x0A, 0x50, 0xF2, 0x2B,
                0x65, 0x05, 0x1B, 0x9E, 0xEC, 0x61, 0xB5, 0x63, 0xA3, 0x6F, 0x3B, 0xBA, 0x63, 0x3A, 0x53, 0xF4,
                0x49, 0x2F, 0xCF, 0x03, 0xCC, 0xD7, 0x50, 0x82, 0x1B, 0x29, 0x4F, 0x08, 0xDE, 0x1B, 0x6D, 0x47,
                0x4F, 0xA8, 0xB6, 0x6A, 0x26, 0xA0, 0x83, 0x3F, 0x1A, 0xAF, 0x83, 0x8F, 0x0E, 0x17, 0x3F, 0xFE,
                0x44, 0x1C, 0x56, 0x94, 0x2E, 0x49, 0x83, 0x83, 0x03, 0xE9, 0xB6, 0xAD, 0xD5, 0xDE, 0xE3, 0x2D,
                0xA1, 0xD9, 0x66, 0x20, 0x5D, 0x1F, 0x5E, 0x96, 0x5D, 0x5B, 0x55, 0x0D, 0xD4, 0xB4, 0x77, 0x6E,
                0xAE, 0x1B, 0x69, 0xF3, 0xA6, 0x61, 0x0E, 0x51, 0x62, 0x39, 0x28, 0x63, 0x75, 0x76, 0xBF, 0xB0,
                0xD2, 0x22, 0xEF, 0x98, 0x25, 0x02, 0x05, 0xC0, 0xD7, 0x6A, 0x06, 0x2C, 0xA5, 0xD8, 0x5A, 0x9D,
                0x7A, 0xA4, 0x21, 0x55, 0x9F, 0xF9, 0x3E, 0xBF, 0x16, 0xF6, 0x07, 0xC2, 0xB9, 0x6E, 0x87, 0x9E,
                0xB5, 0x1C, 0xBE, 0x97, 0xFA, 0x82, 0x7E, 0xED, 0x30, 0xD4, 0x66, 0x3F, 0xDE, 0xD8, 0x1B, 0x4B,
                0x15, 0xD9, 0xFB, 0x2F, 0x50, 0xF0, 0x9D, 0x1D, 0x52, 0x4C, 0x1C, 0x4D, 0x8D, 0xAE, 0x85, 0x1E,
                0xEA, 0x7F, 0x86, 0xF3, 0x0B, 0x7B, 0x87, 0x81, 0x98, 0x23, 0x80, 0x63, 0x4F, 0x2F, 0xB0, 0x62,
                0xCC, 0x6E, 0xD2, 0x46, 0x13, 0x65, 0x2B, 0xD6, 0x44, 0x33, 0x59, 0xB5, 0x8F, 0xB9, 0x4A, 0xA9
            ]),
            /* acid_fixed_key_modulus: */ Modulus([
                0xD6, 0x34, 0xA5, 0x78, 0x6C, 0x68, 0xCE, 0x5A, 0xC2, 0x37, 0x17, 0xF3, 0x82, 0x45, 0xC6, 0x89,
                0xE1, 0x2D, 0x06, 0x67, 0xBF, 0xB4, 0x06, 0x19, 0x55, 0x6B, 0x27, 0x66, 0x0C, 0xA4, 0xB5, 0x87,
                0x81, 0x25, 0xF4, 0x30, 0xBC, 0x53, 0x08, 0x68, 0xA2, 0x48, 0x49, 0x8C, 0x3F, 0x38, 0x40, 0x9C,
                0xC4, 0x26, 0xF4, 0x79, 0xE2, 0xA1, 0x85, 0xF5, 0x5C, 0x7F, 0x58, 0xBA, 0xA6, 0x1C, 0xA0, 0x8B,
                0x84, 0x16, 0x14, 0x6F, 0x85, 0xD9, 0x7C, 0xE1, 0x3C, 0x67, 0x22, 0x1E, 0xFB, 0xD8, 0xA7, 0xA5,
                0x9A, 0xBF, 0xEC, 0x0E, 0xCF, 0x96, 0x7E, 0x85, 0xC2, 0x1D, 0x49, 0x5D, 0x54, 0x26, 0xCB, 0x32,
                0x7C, 0xF6, 0xBB, 0x58, 0x03, 0x80, 0x2B, 0x5D, 0xF7, 0xFB, 0xD1, 0x9D, 0xC7, 0xC6, 0x2E, 0x53,
                0xC0, 0x6F, 0x39, 0x2C, 0x1F, 0xA9, 0x92, 0xF2, 0x4D, 0x7D, 0x4E, 0x74, 0xFF, 0xE4, 0xEF, 0xE4,
                0x7C, 0x3D, 0x34, 0x2A, 0x71, 0xA4, 0x97, 0x59, 0xFF, 0x4F, 0xA2, 0xF4, 0x66, 0x78, 0xD8, 0xBA,
                0x99, 0xE3, 0xE6, 0xDB, 0x54, 0xB9, 0xE9, 0x54, 0xA1, 0x70, 0xFC, 0x05, 0x1F, 0x11, 0x67, 0x4B,
                0x26, 0x8C, 0x0C, 0x3E, 0x03, 0xD2, 0xA3, 0x55, 0x5C, 0x7D, 0xC0, 0x5D, 0x9D, 0xFF, 0x13, 0x2F,
                0xFD, 0x19, 0xBF, 0xED, 0x44, 0xC3, 0x8C, 0xA7, 0x28, 0xCB, 0xE5, 0xE0, 0xB1, 0xA7, 0x9C, 0x33,
                0x8D, 0xB8, 0x6E, 0xDE, 0x87, 0x18, 0x22, 0x60, 0xC4, 0xAE, 0xF2, 0x87, 0x9F, 0xCE, 0x09, 0x5C,
                0xB5, 0x99, 0xA5, 0x9F, 0x49, 0xF2, 0xD7, 0x58, 0xFA, 0xF9, 0xC0, 0x25, 0x7D, 0xD6, 0xCB, 0xF3,
                0xD8, 0x6C, 0xA2, 0x69, 0x91, 0x68, 0x73, 0xB1, 0x94, 0x6F, 0xA3, 0xF3, 0xB9, 0x7D, 0xF8, 0xE0,
                0x72, 0x9E, 0x93, 0x7B, 0x7A, 0xA2, 0x57, 0x60, 0xB7, 0x5B, 0xA9, 0x84, 0xAE, 0x64, 0x88, 0x69
            ]),
            /* package2_fixed_key_modulus: */ Modulus([
                0xB3, 0x65, 0x54, 0xFB, 0x0A, 0xB0, 0x1E, 0x85, 0xA7, 0xF6, 0xCF, 0x91, 0x8E, 0xBA, 0x96, 0x99,
                0x0D, 0x8B, 0x91, 0x69, 0x2A, 0xEE, 0x01, 0x20, 0x4F, 0x34, 0x5C, 0x2C, 0x4F, 0x4E, 0x37, 0xC7,
                0xF1, 0x0B, 0xD4, 0xCD, 0xA1, 0x7F, 0x93, 0xF1, 0x33, 0x59, 0xCE, 0xB1, 0xE9, 0xDD, 0x26, 0xE6,
                0xF3, 0xBB, 0x77, 0x87, 0x46, 0x7A, 0xD6, 0x4E, 0x47, 0x4A, 0xD1, 0x41, 0xB7, 0x79, 0x4A, 0x38,
                0x06, 0x6E, 0xCF, 0x61, 0x8F, 0xCD, 0xC1, 0x40, 0x0B, 0xFA, 0x26, 0xDC, 0xC0, 0x34, 0x51, 0x83,
                0xD9, 0x3B, 0x11, 0x54, 0x3B, 0x96, 0x27, 0x32, 0x9A, 0x95, 0xBE, 0x1E, 0x68, 0x11, 0x50, 0xA0,
                0x6B, 0x10, 0xA8, 0x83, 0x8B, 0xF5, 0xFC, 0xBC, 0x90, 0x84, 0x7A, 0x5A, 0x5C, 0x43, 0x52, 0xE6,
                0xC8, 0x26, 0xE9, 0xFE, 0x06, 0xA0, 0x8B, 0x53, 0x0F, 0xAF, 0x1E, 0xC4, 0x1C, 0x0B, 0xCF, 0x50,
                0x1A, 0xA4, 0xF3, 0x5C, 0xFB, 0xF0, 0x97, 0xE4, 0xDE, 0x32, 0x0A, 0x9F, 0xE3, 0x5A, 0xAA, 0xB7,
                0x44, 0x7F, 0x5C, 0x33, 0x60, 0xB9, 0x0F, 0x22, 0x2D, 0x33, 0x2A, 0xE9, 0x69, 0x79, 0x31, 0x42,
                0x8F, 0xE4, 0x3A, 0x13, 0x8B, 0xE7, 0x26, 0xBD, 0x08, 0x87, 0x6C, 0xA6, 0xF2, 0x73, 0xF6, 0x8E,
                0xA7, 0xF2, 0xFE, 0xFB, 0x6C, 0x28, 0x66, 0x0D, 0xBD, 0xD7, 0xEB, 0x42, 0xA8, 0x78, 0xE6, 0xB8,
                0x6B, 0xAE, 0xC7, 0xA9, 0xE2, 0x40, 0x6E, 0x89, 0x20, 0x82, 0x25, 0x8E, 0x3C, 0x6A, 0x60, 0xD7,
                0xF3, 0x56, 0x8E, 0xEC, 0x8D, 0x51, 0x8A, 0x63, 0x3C, 0x04, 0x78, 0x23, 0x0E, 0x90, 0x0C, 0xB4,
                0xE7, 0x86, 0x3B, 0x4F, 0x8E, 0x13, 0x09, 0x47, 0x32, 0x0E, 0x04, 0xB8, 0x4D, 0x5B, 0xB0, 0x46,
                0x71, 0xB0, 0x5C, 0xF4, 0xAD, 0x63, 0x4F, 0xC5, 0xE2, 0xAC, 0x1E, 0xC4, 0x33, 0x96, 0x09, 0x7B
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
            match (&self.keyblob_keys[i], &self.keyblob_mac_keys[i], &mut self.encrypted_keyblobs[i], &mut self.keyblobs[i]) {
                (Some(keyblob_key), Some(keyblob_mac_key), Some(encrypted_keyblob), ref mut keyblob @ None) => {
                    **keyblob = Some(encrypted_keyblob.decrypt(keyblob_key, keyblob_mac_key, i)?);
                },
                (Some(keyblob_key), Some(keyblob_mac_key), ref mut encrypted_keyblob @ None, Some(keyblob)) => {
                    **encrypted_keyblob = Some(keyblob.encrypt(keyblob_key, keyblob_mac_key, i)?);
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
                #[allow(clippy::single_match)]
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
