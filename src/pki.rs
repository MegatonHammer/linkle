use crate::error::Error;
use crate::impl_debug_deserialize_serialize_hexstring;
use aes::Aes128;
use cipher::{
    generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit, KeyIvInit, StreamCipher,
};
use cmac::{Cmac, Mac};
use ctr::Ctr128BE;
use getset::Getters;
use ini::{self, Properties};
use snafu::{Backtrace, GenerateImplicitData};
use std::fs::File;
use std::io::{self, ErrorKind, Write};
use std::path::Path;
use xts_mode::Xts128;

#[derive(Clone, Copy)]
pub struct Aes128Key(pub [u8; 0x10]);
#[derive(Clone, Copy)]
pub struct AesXtsKey(pub [u8; 0x20]);
pub struct EncryptedKeyblob(pub [u8; 0xB0]);
pub struct Keyblob(pub [u8; 0x90]);
pub struct Modulus(pub [u8; 0x100]);

impl_debug_deserialize_serialize_hexstring!(Aes128Key);
impl_debug_deserialize_serialize_hexstring!(AesXtsKey);
impl_debug_deserialize_serialize_hexstring!(EncryptedKeyblob);
impl_debug_deserialize_serialize_hexstring!(Keyblob);
impl_debug_deserialize_serialize_hexstring!(Modulus);

impl Keyblob {
    fn encrypt(
        &self,
        key: &Aes128Key,
        mac_key: &Aes128Key,
        _keyblob_id: usize,
    ) -> Result<EncryptedKeyblob, Error> {
        let mut encrypted_keyblob = [0; 0xB0];
        encrypted_keyblob[0x20..].copy_from_slice(&self.0);

        let mut crypter = <Ctr128BE<Aes128> as KeyIvInit>::new(
            GenericArray::from_slice(&key.0),
            GenericArray::from_slice(&encrypted_keyblob[0x10..0x20]),
        );
        crypter.apply_keystream(&mut encrypted_keyblob[0x20..]);

        let mut cmac = <Cmac<Aes128> as KeyInit>::new_from_slice(&mac_key.0[..]).unwrap();
        cmac.update(&encrypted_keyblob[0x10..]);
        encrypted_keyblob[..0x10].copy_from_slice(cmac.finalize().into_bytes().as_slice());
        Ok(EncryptedKeyblob(encrypted_keyblob))
    }
}

impl EncryptedKeyblob {
    fn decrypt(
        &self,
        key: &Aes128Key,
        mac_key: &Aes128Key,
        keyblob_id: usize,
    ) -> Result<Keyblob, Error> {
        let mut keyblob = [0; 0x90];
        keyblob.copy_from_slice(&self.0[0x20..]);

        let mut cmac = <Cmac<Aes128> as KeyInit>::new_from_slice(&mac_key.0[..]).unwrap();
        cmac.update(&self.0[0x10..]);
        cmac.verify(GenericArray::from_slice(&self.0[..0x10]))
            .map_err(|err| (keyblob_id, err))?;

        let mut crypter = Ctr128BE::<Aes128>::new(
            GenericArray::from_slice(&key.0),
            GenericArray::from_slice(&self.0[0x10..0x20]),
        );
        crypter.apply_keystream(&mut keyblob);

        Ok(Keyblob(keyblob))
    }
}

impl Aes128Key {
    pub fn derive_key(&self, source: &[u8; 0x10]) -> Result<Aes128Key, Error> {
        let mut newkey = *source;

        let crypter = Aes128::new(GenericArray::from_slice(&self.0));
        crypter.decrypt_block(GenericArray::from_mut_slice(&mut newkey));

        Ok(Aes128Key(newkey))
    }

    fn generate_kek(&self, key: &[u8; 0x10]) -> Result<Aes128Key, Error> {
        let mut newkey = *key;

        let crypter = Aes128::new(GenericArray::from_slice(&self.0));
        crypter.encrypt_block(GenericArray::from_mut_slice(&mut newkey));

        Ok(Aes128Key(newkey))
    }

    pub fn derive_xts_key(&self, source: &[u8; 0x20]) -> Result<AesXtsKey, Error> {
        let mut newkey = *source;

        let crypter = Aes128::new(GenericArray::from_slice(&self.0));
        crypter.decrypt_block(GenericArray::from_mut_slice(&mut newkey[0x00..0x10]));
        crypter.decrypt_block(GenericArray::from_mut_slice(&mut newkey[0x10..0x20]));

        Ok(AesXtsKey(newkey))
    }
}

fn get_tweak(mut sector: usize) -> [u8; 0x10] {
    let mut tweak = [0; 0x10];
    for tweak in tweak.iter_mut().rev() {
        /* Nintendo LE custom tweak... */
        *tweak = (sector & 0xFF) as u8;
        sector >>= 8;
    }
    tweak
}

impl AesXtsKey {
    pub fn decrypt(
        &self,
        data: &mut [u8],
        mut sector: usize,
        sector_size: usize,
    ) -> Result<(), Error> {
        if data.len() % sector_size != 0 {
            return Err(Error::Crypto {
                error: String::from("Length must be multiple of sectors!"),
                backtrace: Backtrace::generate(),
            });
        }

        for i in (0..data.len()).step_by(sector_size) {
            let tweak = get_tweak(sector);

            let key1 = Aes128::new(GenericArray::from_slice(&self.0[0x00..0x10]));
            let key2 = Aes128::new(GenericArray::from_slice(&self.0[0x10..0x20]));
            let crypter = Xts128::<Aes128>::new(key1, key2);
            crypter.decrypt_sector(&mut data[i..i + sector_size], tweak);
            sector += 1;
        }
        Ok(())
    }

    pub fn encrypt(
        &self,
        data: &mut [u8],
        mut sector: usize,
        sector_size: usize,
    ) -> Result<(), Error> {
        if data.len() % sector_size != 0 {
            return Err(Error::Crypto {
                error: String::from("Length must be multiple of sectors!"),
                backtrace: Backtrace::generate(),
            });
        }

        for i in (0..data.len()).step_by(sector_size) {
            let tweak = get_tweak(sector);

            let key1 = Aes128::new(GenericArray::from_slice(&self.0[0x00..0x10]));
            let key2 = Aes128::new(GenericArray::from_slice(&self.0[0x10..0x20]));
            let crypter = Xts128::<Aes128>::new(key1, key2);
            crypter.decrypt_sector(&mut data[i..i + sector_size], tweak);
            sector += 1;
        }
        Ok(())
    }
}

fn key_to_aes(keys: &Properties, name: &str, key: &mut [u8]) -> Result<Option<()>, Error> {
    let value = keys.get(name);
    if let Some(value) = value {
        if value.len() != key.len() * 2 {
            return Err(Error::Crypto {
                error: format!(
                    "Key {} is not of the right size. It should be a {} byte hexstring",
                    name,
                    key.len() * 2
                ),
                backtrace: Backtrace::generate(),
            });
        }
        for (idx, c) in value.bytes().enumerate() {
            let c = match c {
                b'a'..=b'z' => c - b'a' + 10,
                b'A'..=b'Z' => c - b'A' + 10,
                b'0'..=b'9' => c - b'0',
                c => return Err(Error::Crypto { error: format!("Key {} contains invalid character {}. Each character should be a hexadecimal digit.", name, c as char), backtrace: Backtrace::generate()})
            };
            key[idx / 2] |= c << if idx % 2 == 0 { 4 } else { 0 };
        }
        Ok(Some(()))
    } else {
        Ok(None)
    }
}

fn key_to_aes_array(
    keys: &Properties,
    name: &str,
    idx: usize,
    key: &mut [u8],
) -> Result<Option<()>, Error> {
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
    #[get = "pub"]
    secure_boot_key: Option<Aes128Key>,
    #[get = "pub"]
    tsec_key: Option<Aes128Key>,
    #[get = "pub"]
    device_key: Option<Aes128Key>,
    #[get = "pub"]
    keyblob_keys: [Option<Aes128Key>; 0x20],
    #[get = "pub"]
    keyblob_mac_keys: [Option<Aes128Key>; 0x20],
    #[get = "pub"]
    encrypted_keyblobs: [Option<EncryptedKeyblob>; 0x20],
    #[get = "pub"]
    mariko_aes_class_keys: [Option<Aes128Key>; 0xC],
    #[get = "pub"]
    mariko_kek: Option<Aes128Key>,
    #[get = "pub"]
    mariko_bek: Option<Aes128Key>,
    #[get = "pub"]
    keyblobs: [Option<Keyblob>; 0x20],
    #[get = "pub"]
    keyblob_key_sources: [Option<Aes128Key>; 0x20],
    #[get = "pub"]
    keyblob_mac_key_source: Option<Aes128Key>,
    #[get = "pub"]
    tsec_root_kek: Option<Aes128Key>,
    #[get = "pub"]
    package1_mac_kek: Option<Aes128Key>,
    #[get = "pub"]
    package1_kek: Option<Aes128Key>,
    #[get = "pub"]
    tsec_auth_signatures: [Option<Aes128Key>; 0x20],
    #[get = "pub"]
    tsec_root_key: [Option<Aes128Key>; 0x20],
    #[get = "pub"]
    master_kek_sources: [Option<Aes128Key>; 0x20],
    #[get = "pub"]
    mariko_master_kek_sources: [Option<Aes128Key>; 0x20],
    #[get = "pub"]
    master_keks: [Option<Aes128Key>; 0x20],
    #[get = "pub"]
    master_key_source: Option<Aes128Key>,
    #[get = "pub"]
    master_keys: [Option<Aes128Key>; 0x20],
    #[get = "pub"]
    package1_mac_keys: [Option<Aes128Key>; 0x20],
    #[get = "pub"]
    package1_keys: [Option<Aes128Key>; 0x20],
    #[get = "pub"]
    package2_keys: [Option<Aes128Key>; 0x20],
    #[get = "pub"]
    package2_key_source: Option<Aes128Key>,
    #[get = "pub"]
    per_console_key_source: Option<Aes128Key>,
    #[get = "pub"]
    aes_kek_generation_source: Option<Aes128Key>,
    #[get = "pub"]
    aes_key_generation_source: Option<Aes128Key>,
    #[get = "pub"]
    key_area_key_application_source: Option<Aes128Key>,
    #[get = "pub"]
    key_area_key_ocean_source: Option<Aes128Key>,
    #[get = "pub"]
    key_area_key_system_source: Option<Aes128Key>,
    #[get = "pub"]
    titlekek_source: Option<Aes128Key>,
    #[get = "pub"]
    header_kek_source: Option<Aes128Key>,
    #[get = "pub"]
    sd_card_kek_source: Option<Aes128Key>,
    #[get = "pub"]
    sd_card_save_key_source: Option<AesXtsKey>,
    #[get = "pub"]
    sd_card_nca_key_source: Option<AesXtsKey>,
    #[get = "pub"]
    save_mac_kek_source: Option<Aes128Key>,
    #[get = "pub"]
    save_mac_key_source: Option<Aes128Key>,
    #[get = "pub"]
    header_key_source: Option<AesXtsKey>,
    #[get = "pub"]
    header_key: Option<AesXtsKey>,
    #[get = "pub"]
    titlekeks: [Option<Aes128Key>; 0x20],
    #[get = "pub"]
    key_area_key_application: [Option<Aes128Key>; 0x20],
    #[get = "pub"]
    key_area_key_ocean: [Option<Aes128Key>; 0x20],
    #[get = "pub"]
    key_area_key_system: [Option<Aes128Key>; 0x20],
    #[get = "pub"]
    xci_header_key: Option<Aes128Key>,
    #[get = "pub"]
    save_mac_key: Option<Aes128Key>,
    #[get = "pub"]
    sd_card_save_key: Option<AesXtsKey>,
    #[get = "pub"]
    sd_card_nca_key: Option<AesXtsKey>,
    #[allow(dead_code)]
    #[get = "pub"]
    nca_hdr_fixed_key_modulus: [Option<Modulus>; 2],
    #[allow(dead_code)]
    #[get = "pub"]
    acid_fixed_key_modulus: [Option<Modulus>; 2],
    #[allow(dead_code)]
    #[get = "pub"]
    package2_fixed_key_modulus: Option<Modulus>,
}

macro_rules! make_key_macros_write {
    ($d:tt, $self:ident, $w:ident, $show_console_unique:expr, $minimal:expr) => {
        macro_rules! single_key {
            ($keyname:tt, $doc:expr, $console_unique:expr, [$d ($parent:expr),*]) => {
                if $show_console_unique || !$console_unique {
                    #[allow(unused_mut)]
                    for key in &$self.$keyname {
                        if $minimal {
                            let mut count = 0;
                            let mut total = 0;
                            $d (
                                total += 1;
                                if $parent.is_some() {
                                    count += 1;
                                }
                            )*
                            if count == total && total != 0 {
                                continue;
                            }
                        }
                        for line in $doc.split('\n') {
                            writeln!($w, "; {}", line)?;
                        }
                        writeln!($w, "{} = {}", stringify!($keyname), key)?;
                    }
                }
            };
        }

        macro_rules! single_key_xts {
            ($keyname:tt, $doc:expr, $console_unique:expr, [$d ($parent:expr),*]) => {
                if $show_console_unique || !$console_unique {
                    #[allow(unused_mut)]
                    for key in &$self.$keyname {
                        if $minimal {
                            let mut count = 0;
                            let mut total = 0;
                            $d (
                                total += 1;
                                if $parent.is_some() {
                                    count += 1;
                                }
                            )*
                            if count == total && total != 0 {
                                continue;
                                //println!("Skipping {}", stringify!($keyname));
                            } else if total != 0 {
                                //println!("Can't skip {}, need {}, have {}", stringify!($keyname), total, count);
                            }
                        }
                        for line in $doc.split('\n') {
                            writeln!($w, "; {}", line)?;
                        }
                        writeln!($w, "{} = {}", stringify!($keyname), key)?;
                    }
                }
            };
        }

        macro_rules! multi_key {
            ($keyname:tt, $doc:expr, $console_unique:expr, $idx:ident => $d ([$d ($parent:expr),*]),*) => {
                let mut first = true;
                if $show_console_unique || !$console_unique {
                    #[allow(unused_mut)]
                    for ($idx, v) in $self.$keyname.iter().enumerate() {
                        if $minimal {
                            $d (
                                let mut count = 0;
                                let mut total = 0;
                                $d (
                                    total += 1;
                                    if $parent.is_some() {
                                        count += 1;
                                    }
                                )*
                                if count == total && total != 0 {
                                    continue;
                                }
                            )*
                        }
                        if let Some(key) = v {
                            // remove trailing s
                            let mut name = String::from(stringify!($keyname));
                            if name.bytes().last() == Some(b's') {
                                name.pop();
                            }
                            if first {
                                for line in $doc.split('\n') {
                                    writeln!($w, "; {}", line)?;
                                }
                                first = false;
                            }
                            writeln!($w, "{}_{:02x} = {}", name, $idx, key)?;
                        }
                    }
                    if !first {
                        writeln!($w)?;
                    }
                }
            };
        }

        macro_rules! multi_keyblob {
            ($keyname:tt, $doc:expr, $console_unique:expr) => {
                if $show_console_unique || !$console_unique {
                    let mut first = true;
                    for (idx, v) in $self.$keyname.iter().enumerate() {
                        if let Some(key) = v {
                            // remove trailing s
                            let mut name = String::from(stringify!($keyname));
                            if name.bytes().last() == Some(b's') {
                                name.pop();
                            }
                            if first {
                                for line in $doc.split('\n') {
                                    writeln!($w, "; {}", line)?;
                                }
                                first = false;
                            }
                            writeln!($w, "{}_{:02x} = {}", name, idx, key)?;
                        }
                    }
                    if !first {
                        writeln!($w)?;
                    }
                }
            };
        }

        macro_rules! multi_encrypted_keyblob {
            ($keyname:tt, $doc:expr, $console_unique:expr) => {
                if $show_console_unique || !$console_unique {
                    let mut first = true;
                    for (idx, v) in $self.$keyname.iter().enumerate() {
                        if let Some(key) = v {
                            // remove trailing s
                            let mut name = String::from(stringify!($keyname));
                            if name.bytes().last() == Some(b's') {
                                name.pop();
                            }
                            if first {
                                for line in $doc.split('\n') {
                                    writeln!($w, "; {}", line)?;
                                }
                                first = false;
                            }
                            writeln!($w, "{}_{:02x} = {}", name, idx, key)?;
                        }
                    }
                    if !first {
                        writeln!($w)?;
                    }
                }
            };
        }
    };
}

macro_rules! make_key_macros {
    ($d:tt, $self:ident, $section:ident) => {
        macro_rules! single_key {
            ($keyname:tt, $doc:expr, $console_unique:expr, [$d ($parent:expr),*]) => {
                let mut key = [0; 0x10];
                $self.$keyname.or_in(
                    key_to_aes($section, stringify!($keyname), &mut key)?.map(|()| Aes128Key(key)),
                );
            };
        }

        macro_rules! single_key_xts {
            ($keyname:tt, $doc:expr, $console_unique:expr, [$d ($parent:expr),*]) => {
                let mut key = [0; 0x20];
                $self.$keyname.or_in(
                    key_to_aes($section, stringify!($keyname), &mut key)?.map(|()| AesXtsKey(key)),
                );
            };
        }

        macro_rules! multi_key {
            ($keyname:tt, $doc:expr, $console_unique:expr, $idx:ident => $d ([$d ($parent:expr),*]),*) => {
                for (idx, v) in $self.$keyname.iter_mut().enumerate() {
                    let mut key = [0; 0x10];
                    // remove trailing s
                    let mut name = String::from(stringify!($keyname));
                    if name.bytes().last() == Some(b's') {
                        name.pop();
                    }
                    v.or_in(
                        key_to_aes_array($section, &name, idx, &mut key)?.map(|()| Aes128Key(key)),
                    );
                }
            };
        }

        macro_rules! multi_keyblob {
            ($keyname:tt, $doc:expr, $console_unique:expr) => {
                for (idx, v) in $self.$keyname.iter_mut().enumerate() {
                    let mut key = [0; 0x90];
                    // remove trailing s
                    let mut name = String::from(stringify!($keyname));
                    if name.bytes().last() == Some(b's') {
                        name.pop();
                    }
                    v.or_in(
                        key_to_aes_array($section, &name, idx, &mut key)?.map(|()| Keyblob(key)),
                    );
                }
            };
        }

        macro_rules! multi_encrypted_keyblob {
            ($keyname:tt, $doc:expr, $console_unique:expr) => {
                for (idx, v) in $self.$keyname.iter_mut().enumerate() {
                    let mut key = [0; 0xB0];
                    // remove trailing s
                    let mut name = String::from(stringify!($keyname));
                    if name.bytes().last() == Some(b's') {
                        name.pop();
                    }
                    v.or_in(
                        key_to_aes_array($section, &name, idx, &mut key)?
                            .map(|()| EncryptedKeyblob(key)),
                    );
                }
            };
        }
    };
}

macro_rules! keys {
    ($self:ident) => {
        single_key!(secure_boot_key, "Dumpable using Fusee-Gelee and biskeydump.
Secure boot key of the console associated with given BOOT0.
Useful to derive master_key and package1_key from keyblobs.
NOTE: CONSOLE UNIQUE!", true, []);
        single_key!(tsec_key, "Dumpable using Fusee-Gelee and biskeydump.
TSEC key of the console associated with given BOOT0.
Useful to derive master_key and package1_key from keyblobs.
NOTE: CONSOLE UNIQUE!", true, []);
        single_key!(device_key, "Device key used to derive some FS keys.
Derived from per_console_key_source and keyblob_key_00
NOTE: CONSOLE UNIQUE.", true, [$self.keyblob_keys[0], $self.per_console_key_source]);
        single_key!(tsec_root_kek, "Used to generate TSEC root keys.
Can be found using [magic hax] on the TSEC.", false, []);
        single_key!(package1_mac_kek, "Used to generate package1 validation keys.", false, []);
        single_key!(package1_kek, "Used to generate package1 keys.", false, []);

        multi_key!(tsec_auth_signatures, "Auth signatures, seeds for TSEC Root Key, Package1 MAC KEK and Package1 Key on 6.2.0+.", false, i => []);

        multi_key!(tsec_root_key, "Key for master kek decryption, from TSEC firmware on 6.2.0+.
Can be dumped using [magic hax] on the TSEC.
Can be derived from tsec_root_kek and tsec_auth_signatures.", false, i => [$self.tsec_auth_signatures[i], $self.tsec_root_kek]);

        single_key!(keyblob_mac_key_source, "Seed for keyblob MAC key derivation.", false, []);
        multi_key!(keyblob_key_sources, "Seeds for keyblob keys.", false, i => []);

        multi_key!(keyblob_keys, "Actual keys used to decrypt keyblobs. NOTE: CONSOLE UNIQUE.", true, i => [$self.keyblob_key_sources[i], $self.tsec_key, $self.secure_boot_key]);

        multi_key!(keyblob_mac_keys, "Keys used to validate keyblobs. NOTE: CONSOLE UNIQUE.", true, i => [$self.keyblob_keys[i], $self.keyblob_mac_key_source]);

        multi_encrypted_keyblob!(encrypted_keyblobs, "Actual encrypted keyblobs (EKS). NOTE: CONSOLE UNIQUE.", true);

        multi_keyblob!(keyblobs, "Actual decrypted keyblobs (EKS).", false);

        multi_key!(master_kek_sources, "Seeds for firmware master keks.", false, i => []);

        single_key!(mariko_kek, "Key Encryption Key for mariko.", false, []);
        single_key!(mariko_bek, "Boot Encryption Key for mariko.", false, []);
        multi_key!(mariko_aes_class_keys, "AES Class Keys set by mariko bootrom.", false, i => []);
        multi_key!(mariko_master_kek_sources, "Seeds for firmware master keks (Mariko).", false, i => []);
        multi_key!(master_keks, "Firmware master keks, stored in keyblob prior to 6.2.0.", false, i =>
            [$self.keyblobs[i]],
            [if i >= 6 { &$self.tsec_root_key[i - 6] } else { &None }, $self.master_kek_sources[i]],
            [$self.mariko_kek, $self.mariko_master_kek_sources[i]]
        );
        single_key!(master_key_source, "Seed for master key derivation.", false, []);
        multi_key!(master_keys, "Firmware master keys.", false, i => [$self.master_key_source, $self.master_keks[i]]);
        multi_key!(package1_keys, "Package1 keys.", false, i =>
            [$self.keyblobs[i]],
            [$self.package1_kek, if i >= 6 { &$self.tsec_auth_signatures[i - 6] } else { &None }]
        );
        multi_key!(package1_mac_keys, "Package1 MAC Keys.", false, i => [$self.package1_mac_kek, if i >= 6 { &$self.tsec_auth_signatures[i - 6] } else { &None }]);
        single_key!(package2_key_source, "Seed for Package2 key.", false, []);
        multi_key!(package2_keys, "Package2 keys.", false, i => [$self.master_keys[i], $self.package2_key_source]);
        single_key!(per_console_key_source, "Seed for Device key.", false, []);
        single_key!(aes_kek_generation_source, "Seed for GenerateAesKek, usecase + generation 0.", false, []);
        single_key!(aes_key_generation_source, "Seed for GenerateAesKek.", false, []);
        single_key!(titlekek_source, "Seed for titlekeks.", false, []);
        multi_key!(titlekeks, "Title key encryption keys.", false, i => [$self.master_keys[i], $self.titlekek_source]);
        single_key!(key_area_key_application_source, "Seed for kaek 0.", false, []);
        single_key!(key_area_key_ocean_source, "Seed for kaek 1.", false, []);
        single_key!(key_area_key_system_source, "Seed for kaek 2.", false, []);
        single_key!(sd_card_kek_source, "Seed for SD card kek.", false, []);
        single_key_xts!(sd_card_save_key_source, "Seed for SD card save encryption key.", false, []);
        single_key_xts!(sd_card_nca_key_source, "Seed for SD card NCA encryption key.", false, []);
        single_key!(save_mac_kek_source, "Seed for save kek.", false, []);
        single_key!(save_mac_key_source, "Seed for save key.", false, []);
        // Derived from save_mac_key_source, save_mac_kek_source and device_key
        single_key!(save_mac_key, "Key used to sign savedata. NOTE: CONSOLE UNIQUE!", true, [
            $self.device_key,
            $self.save_mac_kek_source,
            $self.aes_kek_generation_source,
            $self.save_mac_key_source
        ]);

        single_key!(header_kek_source, "Seed for header kek.", false, []);
        single_key_xts!(header_key_source, "Seed for NCA header key.", false, []);
        single_key_xts!(header_key, "NCA header key.", false, [
            $self.master_keys[0],
            $self.key_area_key_application_source,
            $self.aes_kek_generation_source,
            $self.aes_key_generation_source
        ]);
        multi_key!(key_area_key_application, "Key area encryption key 0.", true, i => [
            $self.master_keys[i],
            $self.key_area_key_application_source,
            $self.aes_kek_generation_source,
            $self.aes_key_generation_source
        ]);
        multi_key!(key_area_key_ocean, "Key area encryption key 1.", true, i => [
            $self.master_keys[i],
            $self.key_area_key_ocean_source,
            $self.aes_kek_generation_source,
            $self.aes_key_generation_source
        ]);
        multi_key!(key_area_key_system, "Key area encryption key 2.", true, i => [
            $self.master_keys[i],
            $self.key_area_key_system_source,
            $self.aes_kek_generation_source,
            $self.aes_key_generation_source
        ]);
        single_key_xts!(sd_card_save_key, "Encryption key for SD card save.", true, [
            $self.master_keys[0],
            $self.sd_card_save_key_source,
            $self.aes_kek_generation_source,
            $self.aes_key_generation_source
        ]);
        single_key_xts!(sd_card_nca_key, "Encryption key for SD card NCA.", true, [
            $self.master_keys[0],
            $self.sd_card_nca_key_source,
            $self.aes_kek_generation_source,
            $self.aes_key_generation_source
        ]);

        single_key!(xci_header_key, "Key for XCI partially encrypted header.", false, []);
    }
}

fn generate_kek(
    src: &Aes128Key,
    master_key: &Aes128Key,
    kek_seed: &Aes128Key,
    key_seed: &Aes128Key,
) -> Result<Aes128Key, Error> {
    let kek = master_key.derive_key(&kek_seed.0)?;
    let src_kek = kek.derive_key(&src.0)?;
    src_kek.derive_key(&key_seed.0)
}

impl Keys {
    #[allow(clippy::new_ret_no_self)]
    fn new_with_modulus(
        key_path: Option<&Path>,
        default_key_name: &Path,
        modulus: ([Modulus; 2], [Modulus; 2], Modulus),
    ) -> Result<Keys, Error> {
        let (modulus0, modulus1, modulus2) = modulus;
        let [modulus00, modulus01] = modulus0;
        let [modulus10, modulus11] = modulus1;
        let mut keys = Keys {
            nca_hdr_fixed_key_modulus: [Some(modulus00), Some(modulus01)],
            acid_fixed_key_modulus: [Some(modulus10), Some(modulus11)],
            package2_fixed_key_modulus: Some(modulus2),
            ..Default::default()
        };

        let paths = if let Some(key_path) = key_path {
            vec![Some(key_path.into())]
        } else {
            vec![
                dirs_next::config_dir().map(|mut v| {
                    v.push("switch");
                    v.push(default_key_name);
                    v
                }),
                dirs_next::home_dir().map(|mut v| {
                    v.push(".switch");
                    v.push(default_key_name);
                    v
                }),
            ]
        };

        let mut succeed = false;
        for path in paths.into_iter().flatten() {
            match File::open(&path) {
                Ok(file) => {
                    keys.read_from_ini(file)?;
                    succeed = true;
                    break;
                }
                Err(ref err) if err.kind() == ErrorKind::NotFound => (),
                Err(err) => println!("Failed to open {}: {}", path.display(), err),
            }
        }

        if !succeed {
            return Err(io::Error::new(ErrorKind::NotFound, "Keyfile not found.").into());
        }

        keys.derive_keys()?;
        Ok(keys)
    }

    pub fn new_retail(key_path: Option<&Path>) -> Result<Keys, Error> {
        Keys::new_with_modulus(
            key_path,
            Path::new("prod.keys"),
            (
                /* nca_hdr_fixed_key_modulus: */
                [
                    Modulus([
                        0xBF, 0xBE, 0x40, 0x6C, 0xF4, 0xA7, 0x80, 0xE9, 0xF0, 0x7D, 0x0C, 0x99,
                        0x61, 0x1D, 0x77, 0x2F, 0x96, 0xBC, 0x4B, 0x9E, 0x58, 0x38, 0x1B, 0x03,
                        0xAB, 0xB1, 0x75, 0x49, 0x9F, 0x2B, 0x4D, 0x58, 0x34, 0xB0, 0x05, 0xA3,
                        0x75, 0x22, 0xBE, 0x1A, 0x3F, 0x03, 0x73, 0xAC, 0x70, 0x68, 0xD1, 0x16,
                        0xB9, 0x04, 0x46, 0x5E, 0xB7, 0x07, 0x91, 0x2F, 0x07, 0x8B, 0x26, 0xDE,
                        0xF6, 0x00, 0x07, 0xB2, 0xB4, 0x51, 0xF8, 0x0D, 0x0A, 0x5E, 0x58, 0xAD,
                        0xEB, 0xBC, 0x9A, 0xD6, 0x49, 0xB9, 0x64, 0xEF, 0xA7, 0x82, 0xB5, 0xCF,
                        0x6D, 0x70, 0x13, 0xB0, 0x0F, 0x85, 0xF6, 0xA9, 0x08, 0xAA, 0x4D, 0x67,
                        0x66, 0x87, 0xFA, 0x89, 0xFF, 0x75, 0x90, 0x18, 0x1E, 0x6B, 0x3D, 0xE9,
                        0x8A, 0x68, 0xC9, 0x26, 0x04, 0xD9, 0x80, 0xCE, 0x3F, 0x5E, 0x92, 0xCE,
                        0x01, 0xFF, 0x06, 0x3B, 0xF2, 0xC1, 0xA9, 0x0C, 0xCE, 0x02, 0x6F, 0x16,
                        0xBC, 0x92, 0x42, 0x0A, 0x41, 0x64, 0xCD, 0x52, 0xB6, 0x34, 0x4D, 0xAE,
                        0xC0, 0x2E, 0xDE, 0xA4, 0xDF, 0x27, 0x68, 0x3C, 0xC1, 0xA0, 0x60, 0xAD,
                        0x43, 0xF3, 0xFC, 0x86, 0xC1, 0x3E, 0x6C, 0x46, 0xF7, 0x7C, 0x29, 0x9F,
                        0xFA, 0xFD, 0xF0, 0xE3, 0xCE, 0x64, 0xE7, 0x35, 0xF2, 0xF6, 0x56, 0x56,
                        0x6F, 0x6D, 0xF1, 0xE2, 0x42, 0xB0, 0x83, 0x40, 0xA5, 0xC3, 0x20, 0x2B,
                        0xCC, 0x9A, 0xAE, 0xCA, 0xED, 0x4D, 0x70, 0x30, 0xA8, 0x70, 0x1C, 0x70,
                        0xFD, 0x13, 0x63, 0x29, 0x02, 0x79, 0xEA, 0xD2, 0xA7, 0xAF, 0x35, 0x28,
                        0x32, 0x1C, 0x7B, 0xE6, 0x2F, 0x1A, 0xAA, 0x40, 0x7E, 0x32, 0x8C, 0x27,
                        0x42, 0xFE, 0x82, 0x78, 0xEC, 0x0D, 0xEB, 0xE6, 0x83, 0x4B, 0x6D, 0x81,
                        0x04, 0x40, 0x1A, 0x9E, 0x9A, 0x67, 0xF6, 0x72, 0x29, 0xFA, 0x04, 0xF0,
                        0x9D, 0xE4, 0xF4, 0x03,
                    ]),
                    Modulus([
                        0xAD, 0xE3, 0xE1, 0xFA, 0x04, 0x35, 0xE5, 0xB6, 0xDD, 0x49, 0xEA, 0x89,
                        0x29, 0xB1, 0xFF, 0xB6, 0x43, 0xDF, 0xCA, 0x96, 0xA0, 0x4A, 0x13, 0xDF,
                        0x43, 0xD9, 0x94, 0x97, 0x96, 0x43, 0x65, 0x48, 0x70, 0x58, 0x33, 0xA2,
                        0x7D, 0x35, 0x7B, 0x96, 0x74, 0x5E, 0x0B, 0x5C, 0x32, 0x18, 0x14, 0x24,
                        0xC2, 0x58, 0xB3, 0x6C, 0x22, 0x7A, 0xA1, 0xB7, 0xCB, 0x90, 0xA7, 0xA3,
                        0xF9, 0x7D, 0x45, 0x16, 0xA5, 0xC8, 0xED, 0x8F, 0xAD, 0x39, 0x5E, 0x9E,
                        0x4B, 0x51, 0x68, 0x7D, 0xF8, 0x0C, 0x35, 0xC6, 0x3F, 0x91, 0xAE, 0x44,
                        0xA5, 0x92, 0x30, 0x0D, 0x46, 0xF8, 0x40, 0xFF, 0xD0, 0xFF, 0x06, 0xD2,
                        0x1C, 0x7F, 0x96, 0x18, 0xDC, 0xB7, 0x1D, 0x66, 0x3E, 0xD1, 0x73, 0xBC,
                        0x15, 0x8A, 0x2F, 0x94, 0xF3, 0x00, 0xC1, 0x83, 0xF1, 0xCD, 0xD7, 0x81,
                        0x88, 0xAB, 0xDF, 0x8C, 0xEF, 0x97, 0xDD, 0x1B, 0x17, 0x5F, 0x58, 0xF6,
                        0x9A, 0xE9, 0xE8, 0xC2, 0x2F, 0x38, 0x15, 0xF5, 0x21, 0x07, 0xF8, 0x37,
                        0x90, 0x5D, 0x2E, 0x02, 0x40, 0x24, 0x15, 0x0D, 0x25, 0xB7, 0x26, 0x5D,
                        0x09, 0xCC, 0x4C, 0xF4, 0xF2, 0x1B, 0x94, 0x70, 0x5A, 0x9E, 0xEE, 0xED,
                        0x77, 0x77, 0xD4, 0x51, 0x99, 0xF5, 0xDC, 0x76, 0x1E, 0xE3, 0x6C, 0x8C,
                        0xD1, 0x12, 0xD4, 0x57, 0xD1, 0xB6, 0x83, 0xE4, 0xE4, 0xFE, 0xDA, 0xE9,
                        0xB4, 0x3B, 0x33, 0xE5, 0x37, 0x8A, 0xDF, 0xB5, 0x7F, 0x89, 0xF1, 0x9B,
                        0x9E, 0xB0, 0x15, 0xB2, 0x3A, 0xFE, 0xEA, 0x61, 0x84, 0x5B, 0x7D, 0x4B,
                        0x23, 0x12, 0x0B, 0x83, 0x12, 0xF2, 0x22, 0x6B, 0xB9, 0x22, 0x96, 0x4B,
                        0x26, 0x0B, 0x63, 0x5E, 0x96, 0x57, 0x52, 0xA3, 0x67, 0x64, 0x22, 0xCA,
                        0xD0, 0x56, 0x3E, 0x74, 0xB5, 0x98, 0x1F, 0x0D, 0xF8, 0xB3, 0x34, 0xE6,
                        0x98, 0x68, 0x5A, 0xAD,
                    ]),
                ],
                /* acid_fixed_key_modulus: */
                [
                    Modulus([
                        0xDD, 0xC8, 0xDD, 0xF2, 0x4E, 0x6D, 0xF0, 0xCA, 0x9E, 0xC7, 0x5D, 0xC7,
                        0x7B, 0xAD, 0xFE, 0x7D, 0x23, 0x89, 0x69, 0xB6, 0xF2, 0x06, 0xA2, 0x02,
                        0x88, 0xE1, 0x55, 0x91, 0xAB, 0xCB, 0x4D, 0x50, 0x2E, 0xFC, 0x9D, 0x94,
                        0x76, 0xD6, 0x4C, 0xD8, 0xFF, 0x10, 0xFA, 0x5E, 0x93, 0x0A, 0xB4, 0x57,
                        0xAC, 0x51, 0xC7, 0x16, 0x66, 0xF4, 0x1A, 0x54, 0xC2, 0xC5, 0x04, 0x3D,
                        0x1B, 0xFE, 0x30, 0x20, 0x8A, 0xAC, 0x6F, 0x6F, 0xF5, 0xC7, 0xB6, 0x68,
                        0xB8, 0xC9, 0x40, 0x6B, 0x42, 0xAD, 0x11, 0x21, 0xE7, 0x8B, 0xE9, 0x75,
                        0x01, 0x86, 0xE4, 0x48, 0x9B, 0x0A, 0x0A, 0xF8, 0x7F, 0xE8, 0x87, 0xF2,
                        0x82, 0x01, 0xE6, 0xA3, 0x0F, 0xE4, 0x66, 0xAE, 0x83, 0x3F, 0x4E, 0x9F,
                        0x5E, 0x01, 0x30, 0xA4, 0x00, 0xB9, 0x9A, 0xAE, 0x5F, 0x03, 0xCC, 0x18,
                        0x60, 0xE5, 0xEF, 0x3B, 0x5E, 0x15, 0x16, 0xFE, 0x1C, 0x82, 0x78, 0xB5,
                        0x2F, 0x47, 0x7C, 0x06, 0x66, 0x88, 0x5D, 0x35, 0xA2, 0x67, 0x20, 0x10,
                        0xE7, 0x6C, 0x43, 0x68, 0xD3, 0xE4, 0x5A, 0x68, 0x2A, 0x5A, 0xE2, 0x6D,
                        0x73, 0xB0, 0x31, 0x53, 0x1C, 0x20, 0x09, 0x44, 0xF5, 0x1A, 0x9D, 0x22,
                        0xBE, 0x12, 0xA1, 0x77, 0x11, 0xE2, 0xA1, 0xCD, 0x40, 0x9A, 0xA2, 0x8B,
                        0x60, 0x9B, 0xEF, 0xA0, 0xD3, 0x48, 0x63, 0xA2, 0xF8, 0xA3, 0x2C, 0x08,
                        0x56, 0x52, 0x2E, 0x60, 0x19, 0x67, 0x5A, 0xA7, 0x9F, 0xDC, 0x3F, 0x3F,
                        0x69, 0x2B, 0x31, 0x6A, 0xB7, 0x88, 0x4A, 0x14, 0x84, 0x80, 0x33, 0x3C,
                        0x9D, 0x44, 0xB7, 0x3F, 0x4C, 0xE1, 0x75, 0xEA, 0x37, 0xEA, 0xE8, 0x1E,
                        0x7C, 0x77, 0xB7, 0xC6, 0x1A, 0xA2, 0xF0, 0x9F, 0x10, 0x61, 0xCD, 0x7B,
                        0x5B, 0x32, 0x4C, 0x37, 0xEF, 0xB1, 0x71, 0x68, 0x53, 0x0A, 0xED, 0x51,
                        0x7D, 0x35, 0x22, 0xFD,
                    ]),
                    Modulus([
                        0xE7, 0xAA, 0x25, 0xC8, 0x01, 0xA5, 0x14, 0x6B, 0x01, 0x60, 0x3E, 0xD9,
                        0x96, 0x5A, 0xBF, 0x90, 0xAC, 0xA7, 0xFD, 0x9B, 0x5B, 0xBD, 0x8A, 0x26,
                        0xB0, 0xCB, 0x20, 0x28, 0x9A, 0x72, 0x12, 0xF5, 0x20, 0x65, 0xB3, 0xB9,
                        0x84, 0x58, 0x1F, 0x27, 0xBC, 0x7C, 0xA2, 0xC9, 0x9E, 0x18, 0x95, 0xCF,
                        0xC2, 0x73, 0x2E, 0x74, 0x8C, 0x66, 0xE5, 0x9E, 0x79, 0x2B, 0xB8, 0x07,
                        0x0C, 0xB0, 0x4E, 0x8E, 0xAB, 0x85, 0x21, 0x42, 0xC4, 0xC5, 0x6D, 0x88,
                        0x9C, 0xDB, 0x15, 0x95, 0x3F, 0x80, 0xDB, 0x7A, 0x9A, 0x7D, 0x41, 0x56,
                        0x25, 0x17, 0x18, 0x42, 0x4D, 0x8C, 0xAC, 0xA5, 0x7B, 0xDB, 0x42, 0x5D,
                        0x59, 0x35, 0x45, 0x5D, 0x8A, 0x02, 0xB5, 0x70, 0xC0, 0x72, 0x35, 0x46,
                        0xD0, 0x1D, 0x60, 0x01, 0x4A, 0xCC, 0x1C, 0x46, 0xD3, 0xD6, 0x35, 0x52,
                        0xD6, 0xE1, 0xF8, 0x3B, 0x5D, 0xEA, 0xDD, 0xB8, 0xFE, 0x7D, 0x50, 0xCB,
                        0x35, 0x23, 0x67, 0x8B, 0xB6, 0xE4, 0x74, 0xD2, 0x60, 0xFC, 0xFD, 0x43,
                        0xBF, 0x91, 0x08, 0x81, 0xC5, 0x4F, 0x5D, 0x16, 0x9A, 0xC4, 0x9A, 0xC6,
                        0xF6, 0xF3, 0xE1, 0xF6, 0x5C, 0x07, 0xAA, 0x71, 0x6C, 0x13, 0xA4, 0xB1,
                        0xB3, 0x66, 0xBF, 0x90, 0x4C, 0x3D, 0xA2, 0xC4, 0x0B, 0xB8, 0x3D, 0x7A,
                        0x8C, 0x19, 0xFA, 0xFF, 0x6B, 0xB9, 0x1F, 0x02, 0xCC, 0xB6, 0xD3, 0x0C,
                        0x7D, 0x19, 0x1F, 0x47, 0xF9, 0xC7, 0x40, 0x01, 0xFA, 0x46, 0xEA, 0x0B,
                        0xD4, 0x02, 0xE0, 0x3D, 0x30, 0x9A, 0x1A, 0x0F, 0xEA, 0xA7, 0x66, 0x55,
                        0xF7, 0xCB, 0x28, 0xE2, 0xBB, 0x99, 0xE4, 0x83, 0xC3, 0x43, 0x03, 0xEE,
                        0xDC, 0x1F, 0x02, 0x23, 0xDD, 0xD1, 0x2D, 0x39, 0xA4, 0x65, 0x75, 0x03,
                        0xEF, 0x37, 0x9C, 0x06, 0xD6, 0xFA, 0xA1, 0x15, 0xF0, 0xDB, 0x17, 0x47,
                        0x26, 0x4F, 0x49, 0x03,
                    ]),
                ],
                /* package2_fixed_key_modulus: */
                Modulus([
                    0x8D, 0x13, 0xA7, 0x77, 0x6A, 0xE5, 0xDC, 0xC0, 0x3B, 0x25, 0xD0, 0x58, 0xE4,
                    0x20, 0x69, 0x59, 0x55, 0x4B, 0xAB, 0x70, 0x40, 0x08, 0x28, 0x07, 0xA8, 0xA7,
                    0xFD, 0x0F, 0x31, 0x2E, 0x11, 0xFE, 0x47, 0xA0, 0xF9, 0x9D, 0xDF, 0x80, 0xDB,
                    0x86, 0x5A, 0x27, 0x89, 0xCD, 0x97, 0x6C, 0x85, 0xC5, 0x6C, 0x39, 0x7F, 0x41,
                    0xF2, 0xFF, 0x24, 0x20, 0xC3, 0x95, 0xA6, 0xF7, 0x9D, 0x4A, 0x45, 0x74, 0x8B,
                    0x5D, 0x28, 0x8A, 0xC6, 0x99, 0x35, 0x68, 0x85, 0xA5, 0x64, 0x32, 0x80, 0x9F,
                    0xD3, 0x48, 0x39, 0xA2, 0x1D, 0x24, 0x67, 0x69, 0xDF, 0x75, 0xAC, 0x12, 0xB5,
                    0xBD, 0xC3, 0x29, 0x90, 0xBE, 0x37, 0xE4, 0xA0, 0x80, 0x9A, 0xBE, 0x36, 0xBF,
                    0x1F, 0x2C, 0xAB, 0x2B, 0xAD, 0xF5, 0x97, 0x32, 0x9A, 0x42, 0x9D, 0x09, 0x8B,
                    0x08, 0xF0, 0x63, 0x47, 0xA3, 0xE9, 0x1B, 0x36, 0xD8, 0x2D, 0x8A, 0xD7, 0xE1,
                    0x54, 0x11, 0x95, 0xE4, 0x45, 0x88, 0x69, 0x8A, 0x2B, 0x35, 0xCE, 0xD0, 0xA5,
                    0x0B, 0xD5, 0x5D, 0xAC, 0xDB, 0xAF, 0x11, 0x4D, 0xCA, 0xB8, 0x1E, 0xE7, 0x01,
                    0x9E, 0xF4, 0x46, 0xA3, 0x8A, 0x94, 0x6D, 0x76, 0xBD, 0x8A, 0xC8, 0x3B, 0xD2,
                    0x31, 0x58, 0x0C, 0x79, 0xA8, 0x26, 0xE9, 0xD1, 0x79, 0x9C, 0xCB, 0xD4, 0x2B,
                    0x6A, 0x4F, 0xC6, 0xCC, 0xCF, 0x90, 0xA7, 0xB9, 0x98, 0x47, 0xFD, 0xFA, 0x4C,
                    0x6C, 0x6F, 0x81, 0x87, 0x3B, 0xCA, 0xB8, 0x50, 0xF6, 0x3E, 0x39, 0x5D, 0x4D,
                    0x97, 0x3F, 0x0F, 0x35, 0x39, 0x53, 0xFB, 0xFA, 0xCD, 0xAB, 0xA8, 0x7A, 0x62,
                    0x9A, 0x3F, 0xF2, 0x09, 0x27, 0x96, 0x3F, 0x07, 0x9A, 0x91, 0xF7, 0x16, 0xBF,
                    0xC6, 0x3A, 0x82, 0x5A, 0x4B, 0xCF, 0x49, 0x50, 0x95, 0x8C, 0x55, 0x80, 0x7E,
                    0x39, 0xB1, 0x48, 0x05, 0x1E, 0x21, 0xC7, 0x24, 0x4F,
                ]),
            ),
        )
    }

    pub fn new_dev(key_path: Option<&Path>) -> Result<Keys, Error> {
        Keys::new_with_modulus(
            key_path,
            Path::new("dev.keys"),
            (
                /* nca_hdr_fixed_key_modulus: */
                [
                    Modulus([
                        0xD8, 0xF1, 0x18, 0xEF, 0x32, 0x72, 0x4C, 0xA7, 0x47, 0x4C, 0xB9, 0xEA,
                        0xB3, 0x04, 0xA8, 0xA4, 0xAC, 0x99, 0x08, 0x08, 0x04, 0xBF, 0x68, 0x57,
                        0xB8, 0x43, 0x94, 0x2B, 0xC7, 0xB9, 0x66, 0x49, 0x85, 0xE5, 0x8A, 0x9B,
                        0xC1, 0x00, 0x9A, 0x6A, 0x8D, 0xD0, 0xEF, 0xCE, 0xFF, 0x86, 0xC8, 0x5C,
                        0x5D, 0xE9, 0x53, 0x7B, 0x19, 0x2A, 0xA8, 0xC0, 0x22, 0xD1, 0xF3, 0x22,
                        0x0A, 0x50, 0xF2, 0x2B, 0x65, 0x05, 0x1B, 0x9E, 0xEC, 0x61, 0xB5, 0x63,
                        0xA3, 0x6F, 0x3B, 0xBA, 0x63, 0x3A, 0x53, 0xF4, 0x49, 0x2F, 0xCF, 0x03,
                        0xCC, 0xD7, 0x50, 0x82, 0x1B, 0x29, 0x4F, 0x08, 0xDE, 0x1B, 0x6D, 0x47,
                        0x4F, 0xA8, 0xB6, 0x6A, 0x26, 0xA0, 0x83, 0x3F, 0x1A, 0xAF, 0x83, 0x8F,
                        0x0E, 0x17, 0x3F, 0xFE, 0x44, 0x1C, 0x56, 0x94, 0x2E, 0x49, 0x83, 0x83,
                        0x03, 0xE9, 0xB6, 0xAD, 0xD5, 0xDE, 0xE3, 0x2D, 0xA1, 0xD9, 0x66, 0x20,
                        0x5D, 0x1F, 0x5E, 0x96, 0x5D, 0x5B, 0x55, 0x0D, 0xD4, 0xB4, 0x77, 0x6E,
                        0xAE, 0x1B, 0x69, 0xF3, 0xA6, 0x61, 0x0E, 0x51, 0x62, 0x39, 0x28, 0x63,
                        0x75, 0x76, 0xBF, 0xB0, 0xD2, 0x22, 0xEF, 0x98, 0x25, 0x02, 0x05, 0xC0,
                        0xD7, 0x6A, 0x06, 0x2C, 0xA5, 0xD8, 0x5A, 0x9D, 0x7A, 0xA4, 0x21, 0x55,
                        0x9F, 0xF9, 0x3E, 0xBF, 0x16, 0xF6, 0x07, 0xC2, 0xB9, 0x6E, 0x87, 0x9E,
                        0xB5, 0x1C, 0xBE, 0x97, 0xFA, 0x82, 0x7E, 0xED, 0x30, 0xD4, 0x66, 0x3F,
                        0xDE, 0xD8, 0x1B, 0x4B, 0x15, 0xD9, 0xFB, 0x2F, 0x50, 0xF0, 0x9D, 0x1D,
                        0x52, 0x4C, 0x1C, 0x4D, 0x8D, 0xAE, 0x85, 0x1E, 0xEA, 0x7F, 0x86, 0xF3,
                        0x0B, 0x7B, 0x87, 0x81, 0x98, 0x23, 0x80, 0x63, 0x4F, 0x2F, 0xB0, 0x62,
                        0xCC, 0x6E, 0xD2, 0x46, 0x13, 0x65, 0x2B, 0xD6, 0x44, 0x33, 0x59, 0xB5,
                        0x8F, 0xB9, 0x4A, 0xA9,
                    ]),
                    Modulus([
                        0x9A, 0xBC, 0x88, 0xBD, 0x0A, 0xBE, 0xD7, 0x0C, 0x9B, 0x42, 0x75, 0x65,
                        0x38, 0x5E, 0xD1, 0x01, 0xCD, 0x12, 0xAE, 0xEA, 0xE9, 0x4B, 0xDB, 0xB4,
                        0x5E, 0x36, 0x10, 0x96, 0xDA, 0x3D, 0x2E, 0x66, 0xD3, 0x99, 0x13, 0x8A,
                        0xBE, 0x67, 0x41, 0xC8, 0x93, 0xD9, 0x3E, 0x42, 0xCE, 0x34, 0xCE, 0x96,
                        0xFA, 0x0B, 0x23, 0xCC, 0x2C, 0xDF, 0x07, 0x3F, 0x3B, 0x24, 0x4B, 0x12,
                        0x67, 0x3A, 0x29, 0x36, 0xA3, 0xAA, 0x06, 0xF0, 0x65, 0xA5, 0x85, 0xBA,
                        0xFD, 0x12, 0xEC, 0xF1, 0x60, 0x67, 0xF0, 0x8F, 0xD3, 0x5B, 0x01, 0x1B,
                        0x1E, 0x84, 0xA3, 0x5C, 0x65, 0x36, 0xF9, 0x23, 0x7E, 0xF3, 0x26, 0x38,
                        0x64, 0x98, 0xBA, 0xE4, 0x19, 0x91, 0x4C, 0x02, 0xCF, 0xC9, 0x6D, 0x86,
                        0xEC, 0x1D, 0x41, 0x69, 0xDD, 0x56, 0xEA, 0x5C, 0xA3, 0x2A, 0x58, 0xB4,
                        0x39, 0xCC, 0x40, 0x31, 0xFD, 0xFB, 0x42, 0x74, 0xF8, 0xEC, 0xEA, 0x00,
                        0xF0, 0xD9, 0x28, 0xEA, 0xFA, 0x2D, 0x00, 0xE1, 0x43, 0x53, 0xC6, 0x32,
                        0xF4, 0xA2, 0x07, 0xD4, 0x5F, 0xD4, 0xCB, 0xAC, 0xCA, 0xFF, 0xDF, 0x84,
                        0xD2, 0x86, 0x14, 0x3C, 0xDE, 0x22, 0x75, 0xA5, 0x73, 0xFF, 0x68, 0x07,
                        0x4A, 0xF9, 0x7C, 0x2C, 0xCC, 0xDE, 0x45, 0xB6, 0x54, 0x82, 0x90, 0x36,
                        0x1F, 0x2C, 0x51, 0x96, 0xC5, 0x0A, 0x53, 0x5B, 0xF0, 0x8B, 0x4A, 0xAA,
                        0x3B, 0x68, 0x97, 0x19, 0x17, 0x1F, 0x01, 0xB8, 0xED, 0xB9, 0x9A, 0x5E,
                        0x08, 0xC5, 0x20, 0x1E, 0x6A, 0x09, 0xF0, 0xE9, 0x73, 0xA3, 0xBE, 0x10,
                        0x06, 0x02, 0xE9, 0xFB, 0x85, 0xFA, 0x5F, 0x01, 0xAC, 0x60, 0xE0, 0xED,
                        0x7D, 0xB9, 0x49, 0xA8, 0x9E, 0x98, 0x7D, 0x91, 0x40, 0x05, 0xCF, 0xF9,
                        0x1A, 0xFC, 0x40, 0x22, 0xA8, 0x96, 0x5B, 0xB0, 0xDC, 0x7A, 0xF5, 0xB7,
                        0xE9, 0x91, 0x4C, 0x49,
                    ]),
                ],
                /* acid_fixed_key_modulus: */
                [
                    Modulus([
                        0xD6, 0x34, 0xA5, 0x78, 0x6C, 0x68, 0xCE, 0x5A, 0xC2, 0x37, 0x17, 0xF3,
                        0x82, 0x45, 0xC6, 0x89, 0xE1, 0x2D, 0x06, 0x67, 0xBF, 0xB4, 0x06, 0x19,
                        0x55, 0x6B, 0x27, 0x66, 0x0C, 0xA4, 0xB5, 0x87, 0x81, 0x25, 0xF4, 0x30,
                        0xBC, 0x53, 0x08, 0x68, 0xA2, 0x48, 0x49, 0x8C, 0x3F, 0x38, 0x40, 0x9C,
                        0xC4, 0x26, 0xF4, 0x79, 0xE2, 0xA1, 0x85, 0xF5, 0x5C, 0x7F, 0x58, 0xBA,
                        0xA6, 0x1C, 0xA0, 0x8B, 0x84, 0x16, 0x14, 0x6F, 0x85, 0xD9, 0x7C, 0xE1,
                        0x3C, 0x67, 0x22, 0x1E, 0xFB, 0xD8, 0xA7, 0xA5, 0x9A, 0xBF, 0xEC, 0x0E,
                        0xCF, 0x96, 0x7E, 0x85, 0xC2, 0x1D, 0x49, 0x5D, 0x54, 0x26, 0xCB, 0x32,
                        0x7C, 0xF6, 0xBB, 0x58, 0x03, 0x80, 0x2B, 0x5D, 0xF7, 0xFB, 0xD1, 0x9D,
                        0xC7, 0xC6, 0x2E, 0x53, 0xC0, 0x6F, 0x39, 0x2C, 0x1F, 0xA9, 0x92, 0xF2,
                        0x4D, 0x7D, 0x4E, 0x74, 0xFF, 0xE4, 0xEF, 0xE4, 0x7C, 0x3D, 0x34, 0x2A,
                        0x71, 0xA4, 0x97, 0x59, 0xFF, 0x4F, 0xA2, 0xF4, 0x66, 0x78, 0xD8, 0xBA,
                        0x99, 0xE3, 0xE6, 0xDB, 0x54, 0xB9, 0xE9, 0x54, 0xA1, 0x70, 0xFC, 0x05,
                        0x1F, 0x11, 0x67, 0x4B, 0x26, 0x8C, 0x0C, 0x3E, 0x03, 0xD2, 0xA3, 0x55,
                        0x5C, 0x7D, 0xC0, 0x5D, 0x9D, 0xFF, 0x13, 0x2F, 0xFD, 0x19, 0xBF, 0xED,
                        0x44, 0xC3, 0x8C, 0xA7, 0x28, 0xCB, 0xE5, 0xE0, 0xB1, 0xA7, 0x9C, 0x33,
                        0x8D, 0xB8, 0x6E, 0xDE, 0x87, 0x18, 0x22, 0x60, 0xC4, 0xAE, 0xF2, 0x87,
                        0x9F, 0xCE, 0x09, 0x5C, 0xB5, 0x99, 0xA5, 0x9F, 0x49, 0xF2, 0xD7, 0x58,
                        0xFA, 0xF9, 0xC0, 0x25, 0x7D, 0xD6, 0xCB, 0xF3, 0xD8, 0x6C, 0xA2, 0x69,
                        0x91, 0x68, 0x73, 0xB1, 0x94, 0x6F, 0xA3, 0xF3, 0xB9, 0x7D, 0xF8, 0xE0,
                        0x72, 0x9E, 0x93, 0x7B, 0x7A, 0xA2, 0x57, 0x60, 0xB7, 0x5B, 0xA9, 0x84,
                        0xAE, 0x64, 0x88, 0x69,
                    ]),
                    Modulus([
                        0xBC, 0xA5, 0x6A, 0x7E, 0xEA, 0x38, 0x34, 0x62, 0xA6, 0x10, 0x18, 0x3C,
                        0xE1, 0x63, 0x7B, 0xF0, 0xD3, 0x08, 0x8C, 0xF5, 0xC5, 0xC4, 0xC7, 0x93,
                        0xE9, 0xD9, 0xE6, 0x32, 0xF3, 0xA0, 0xF6, 0x6E, 0x8A, 0x98, 0x76, 0x47,
                        0x33, 0x47, 0x65, 0x02, 0x70, 0xDC, 0x86, 0x5F, 0x3D, 0x61, 0x5A, 0x70,
                        0xBC, 0x5A, 0xCA, 0xCA, 0x50, 0xAD, 0x61, 0x7E, 0xC9, 0xEC, 0x27, 0xFF,
                        0xE8, 0x64, 0x42, 0x9A, 0xEE, 0xBE, 0xC3, 0xD1, 0x0B, 0xC0, 0xE9, 0xBF,
                        0x83, 0x8D, 0xC0, 0x0C, 0xD8, 0x00, 0x5B, 0x76, 0x90, 0xD2, 0x4B, 0x30,
                        0x84, 0x35, 0x8B, 0x1E, 0x20, 0xB7, 0xE4, 0xDC, 0x63, 0xE5, 0xDF, 0xCD,
                        0x00, 0x5F, 0x81, 0x5F, 0x67, 0xC5, 0x8B, 0xDF, 0xFC, 0xE1, 0x37, 0x5F,
                        0x07, 0xD9, 0xDE, 0x4F, 0xE6, 0x7B, 0xF1, 0xFB, 0xA1, 0x5A, 0x71, 0x40,
                        0xFE, 0xBA, 0x1E, 0xAE, 0x13, 0x22, 0xD2, 0xFE, 0x37, 0xA2, 0xB6, 0x8B,
                        0xAB, 0xEB, 0x84, 0x81, 0x4E, 0x7C, 0x1E, 0x02, 0xD1, 0xFB, 0xD7, 0x5D,
                        0x11, 0x84, 0x64, 0xD2, 0x4D, 0xBB, 0x50, 0x00, 0x67, 0x54, 0xE2, 0x77,
                        0x89, 0xBA, 0x0B, 0xE7, 0x05, 0x57, 0x9A, 0x22, 0x5A, 0xEC, 0x76, 0x1C,
                        0xFD, 0xE8, 0xA8, 0x18, 0x16, 0x41, 0x65, 0x03, 0xFA, 0xC4, 0xA6, 0x31,
                        0x5C, 0x1A, 0x7F, 0xAB, 0x11, 0xC8, 0x4A, 0x99, 0xB9, 0xE6, 0xCF, 0x62,
                        0x21, 0xA6, 0x72, 0x47, 0xDB, 0xBA, 0x96, 0x26, 0x4E, 0x2E, 0xD4, 0x8C,
                        0x46, 0xD6, 0xA7, 0x1A, 0x6C, 0x32, 0xA7, 0xDF, 0x85, 0x1C, 0x03, 0xC3,
                        0x6D, 0xA9, 0xE9, 0x68, 0xF4, 0x17, 0x1E, 0xB2, 0x70, 0x2A, 0xA1, 0xE5,
                        0xE1, 0xF3, 0x8F, 0x6F, 0x63, 0xAC, 0xEB, 0x72, 0x0B, 0x4C, 0x4A, 0x36,
                        0x3C, 0x60, 0x91, 0x9F, 0x6E, 0x1C, 0x71, 0xEA, 0xD0, 0x78, 0x78, 0xA0,
                        0x2E, 0xC6, 0x32, 0x6B,
                    ]),
                ],
                /* package2_fixed_key_modulus: */
                Modulus([
                    0xB3, 0x65, 0x54, 0xFB, 0x0A, 0xB0, 0x1E, 0x85, 0xA7, 0xF6, 0xCF, 0x91, 0x8E,
                    0xBA, 0x96, 0x99, 0x0D, 0x8B, 0x91, 0x69, 0x2A, 0xEE, 0x01, 0x20, 0x4F, 0x34,
                    0x5C, 0x2C, 0x4F, 0x4E, 0x37, 0xC7, 0xF1, 0x0B, 0xD4, 0xCD, 0xA1, 0x7F, 0x93,
                    0xF1, 0x33, 0x59, 0xCE, 0xB1, 0xE9, 0xDD, 0x26, 0xE6, 0xF3, 0xBB, 0x77, 0x87,
                    0x46, 0x7A, 0xD6, 0x4E, 0x47, 0x4A, 0xD1, 0x41, 0xB7, 0x79, 0x4A, 0x38, 0x06,
                    0x6E, 0xCF, 0x61, 0x8F, 0xCD, 0xC1, 0x40, 0x0B, 0xFA, 0x26, 0xDC, 0xC0, 0x34,
                    0x51, 0x83, 0xD9, 0x3B, 0x11, 0x54, 0x3B, 0x96, 0x27, 0x32, 0x9A, 0x95, 0xBE,
                    0x1E, 0x68, 0x11, 0x50, 0xA0, 0x6B, 0x10, 0xA8, 0x83, 0x8B, 0xF5, 0xFC, 0xBC,
                    0x90, 0x84, 0x7A, 0x5A, 0x5C, 0x43, 0x52, 0xE6, 0xC8, 0x26, 0xE9, 0xFE, 0x06,
                    0xA0, 0x8B, 0x53, 0x0F, 0xAF, 0x1E, 0xC4, 0x1C, 0x0B, 0xCF, 0x50, 0x1A, 0xA4,
                    0xF3, 0x5C, 0xFB, 0xF0, 0x97, 0xE4, 0xDE, 0x32, 0x0A, 0x9F, 0xE3, 0x5A, 0xAA,
                    0xB7, 0x44, 0x7F, 0x5C, 0x33, 0x60, 0xB9, 0x0F, 0x22, 0x2D, 0x33, 0x2A, 0xE9,
                    0x69, 0x79, 0x31, 0x42, 0x8F, 0xE4, 0x3A, 0x13, 0x8B, 0xE7, 0x26, 0xBD, 0x08,
                    0x87, 0x6C, 0xA6, 0xF2, 0x73, 0xF6, 0x8E, 0xA7, 0xF2, 0xFE, 0xFB, 0x6C, 0x28,
                    0x66, 0x0D, 0xBD, 0xD7, 0xEB, 0x42, 0xA8, 0x78, 0xE6, 0xB8, 0x6B, 0xAE, 0xC7,
                    0xA9, 0xE2, 0x40, 0x6E, 0x89, 0x20, 0x82, 0x25, 0x8E, 0x3C, 0x6A, 0x60, 0xD7,
                    0xF3, 0x56, 0x8E, 0xEC, 0x8D, 0x51, 0x8A, 0x63, 0x3C, 0x04, 0x78, 0x23, 0x0E,
                    0x90, 0x0C, 0xB4, 0xE7, 0x86, 0x3B, 0x4F, 0x8E, 0x13, 0x09, 0x47, 0x32, 0x0E,
                    0x04, 0xB8, 0x4D, 0x5B, 0xB0, 0x46, 0x71, 0xB0, 0x5C, 0xF4, 0xAD, 0x63, 0x4F,
                    0xC5, 0xE2, 0xAC, 0x1E, 0xC4, 0x33, 0x96, 0x09, 0x7B,
                ]),
            ),
        )
    }

    pub fn new(key_path: Option<&Path>, is_dev: bool) -> Result<Keys, Error> {
        if is_dev {
            Self::new_dev(key_path)
        } else {
            Self::new_retail(key_path)
        }
    }

    #[allow(clippy::cognitive_complexity)]
    fn read_from_ini(&mut self, mut file: File) -> Result<(), Error> {
        let config = ini::Ini::read_from(&mut file)?;
        let section = config.general_section();

        make_key_macros!($, self, section);
        keys!(self);
        Ok(())
    }

    #[allow(clippy::cognitive_complexity)]
    pub fn write<W: Write>(
        &self,
        w: &mut W,
        console_unique: bool,
        minimal: bool,
    ) -> io::Result<()> {
        make_key_macros_write!($, self, w, console_unique, minimal);
        keys!(self);
        Ok(())
    }

    #[allow(clippy::cognitive_complexity)]
    #[allow(clippy::single_match)]
    pub fn derive_keys(&mut self) -> Result<(), Error> {
        for i in 0..6 {
            /* Derive the keyblob_keys */
            match (
                &self.secure_boot_key,
                &self.tsec_key,
                &self.keyblob_key_sources[i],
            ) {
                (Some(sbk), Some(tsec_key), Some(keyblob_key_source)) => {
                    let tmp = tsec_key.derive_key(&keyblob_key_source.0)?;
                    self.keyblob_keys[i] = Some(sbk.derive_key(&tmp.0)?);
                }
                _ => continue,
            }
        }
        for i in 0..6 {
            /* Derive the keyblob mac keys */
            match (&self.keyblob_keys[i], &self.keyblob_mac_key_source) {
                (Some(keyblob_key), Some(keyblob_mac_key_source)) => {
                    self.keyblob_mac_keys[i] =
                        Some(keyblob_key.derive_key(&keyblob_mac_key_source.0)?);
                }
                _ => continue,
            }
        }
        /* Derive the device key */
        match (&self.keyblob_keys[0], &self.per_console_key_source) {
            (Some(keyblob_key), Some(per_console_key_source)) => {
                self.device_key = Some(keyblob_key.derive_key(&per_console_key_source.0)?);
            }
            _ => (),
        }
        for i in 0..6 {
            match (
                &self.keyblob_keys[i],
                &self.keyblob_mac_keys[i],
                &mut self.encrypted_keyblobs[i],
                &mut self.keyblobs[i],
            ) {
                (
                    Some(keyblob_key),
                    Some(keyblob_mac_key),
                    Some(encrypted_keyblob),
                    ref mut keyblob @ None,
                ) => {
                    **keyblob = Some(encrypted_keyblob.decrypt(keyblob_key, keyblob_mac_key, i)?);
                }
                (
                    Some(keyblob_key),
                    Some(keyblob_mac_key),
                    ref mut encrypted_keyblob @ None,
                    Some(keyblob),
                ) => {
                    **encrypted_keyblob = Some(keyblob.encrypt(keyblob_key, keyblob_mac_key, i)?);
                }
                _ => continue,
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
            // Derive new 6.2.0+ keks
            match (&self.tsec_root_kek, &self.tsec_auth_signatures[i - 6]) {
                (Some(tsec_root_kek), Some(tsec_auth_signature)) => {
                    self.tsec_root_key[i - 6] =
                        Some(tsec_root_kek.derive_key(&tsec_auth_signature.0)?);
                }
                _ => (),
            }
            match (&self.package1_mac_kek, &self.tsec_auth_signatures[i - 6]) {
                (Some(package1_mac_kek), Some(tsec_auth_signature)) => {
                    self.package1_mac_keys[i] =
                        Some(package1_mac_kek.derive_key(&tsec_auth_signature.0)?);
                }
                _ => (),
            }
            match (&self.package1_kek, &self.tsec_auth_signatures[i - 6]) {
                (Some(package1_kek), Some(tsec_auth_signature)) => {
                    self.package1_keys[i] = Some(package1_kek.derive_key(&tsec_auth_signature.0)?);
                }
                _ => (),
            }
        }
        for i in 6..0x20 {
            /* Do keygen for 6.2.0+ */
            match (&self.tsec_root_key[i - 6], &self.master_kek_sources[i]) {
                (Some(tsec_root_key), Some(master_kek_source)) => {
                    self.master_keks[i] = Some(tsec_root_key.derive_key(&master_kek_source.0)?);
                }
                _ => continue,
            }
        }
        for i in 0..0x20 {
            /* Derive master keks with mariko keydata */
            match (
                &self.mariko_kek,
                &mut self.mariko_master_kek_sources[i],
                &mut self.master_keks[i],
            ) {
                (Some(mariko_kek), Some(mariko_master_kek_sources), ref mut master_kek @ None) => {
                    **master_kek = Some(mariko_kek.derive_key(&mariko_master_kek_sources.0)?)
                }
                (Some(mariko_kek), ref mut mariko_master_kek_sources @ None, Some(master_kek)) => {
                    **mariko_master_kek_sources = Some(mariko_kek.generate_kek(&master_kek.0)?)
                }
                _ => (),
            }
        }
        for i in 0..0x20 {
            /* Derive the master keys! */
            match (&self.master_key_source, &self.master_keks[i]) {
                (Some(master_key_source), Some(master_kek)) => {
                    self.master_keys[i] = Some(master_kek.derive_key(&master_key_source.0)?);
                }
                _ => continue,
            }
        }
        for i in 0..0x20 {
            if let Some(master_key) = &self.master_keys[i] {
                /* Derive key area encryption key */
                match (
                    &self.key_area_key_application_source,
                    &self.aes_kek_generation_source,
                    &self.aes_key_generation_source,
                ) {
                    (
                        Some(key_area_key_application_source),
                        Some(aes_kek_generation_source),
                        Some(aes_key_generation_source),
                    ) => {
                        self.key_area_key_application[i] = Some(generate_kek(
                            key_area_key_application_source,
                            master_key,
                            aes_kek_generation_source,
                            aes_key_generation_source,
                        )?);
                    }
                    _ => continue,
                }
                match (
                    &self.key_area_key_ocean_source,
                    &self.aes_kek_generation_source,
                    &self.aes_key_generation_source,
                ) {
                    (
                        Some(key_area_key_ocean_source),
                        Some(aes_kek_generation_source),
                        Some(aes_key_generation_source),
                    ) => {
                        self.key_area_key_ocean[i] = Some(generate_kek(
                            key_area_key_ocean_source,
                            master_key,
                            aes_kek_generation_source,
                            aes_key_generation_source,
                        )?);
                    }
                    _ => continue,
                }
                match (
                    &self.key_area_key_system_source,
                    &self.aes_kek_generation_source,
                    &self.aes_key_generation_source,
                ) {
                    (
                        Some(key_area_key_system_source),
                        Some(aes_kek_generation_source),
                        Some(aes_key_generation_source),
                    ) => {
                        self.key_area_key_system[i] = Some(generate_kek(
                            key_area_key_system_source,
                            master_key,
                            aes_kek_generation_source,
                            aes_key_generation_source,
                        )?);
                    }
                    _ => continue,
                }
                /* Derive titlekek */
                if let Some(titlekek_source) = &self.titlekek_source {
                    self.titlekeks[i] = Some(master_key.derive_key(&titlekek_source.0)?);
                }

                /* Derive Package2 key */
                if let Some(package2_key_source) = &self.package2_key_source {
                    self.package2_keys[i] = Some(master_key.derive_key(&package2_key_source.0)?);
                }
            }

            /* Derive Header Key */
            #[allow(clippy::single_match)]
            match (
                &self.master_keys[0],
                &self.header_kek_source,
                &self.header_key_source,
                &self.aes_kek_generation_source,
                &self.aes_key_generation_source,
            ) {
                (
                    Some(master_key),
                    Some(header_kek_source),
                    Some(header_key_source),
                    Some(aes_kek_generation_source),
                    Some(aes_key_generation_source),
                ) => {
                    let header_kek = generate_kek(
                        header_kek_source,
                        master_key,
                        aes_kek_generation_source,
                        aes_key_generation_source,
                    )?;
                    self.header_key = Some(header_kek.derive_xts_key(&header_key_source.0)?);
                }
                _ => (),
            }
            /* Derive SD Card key */
            match (
                &self.master_keys[0],
                &self.sd_card_kek_source,
                &self.aes_kek_generation_source,
                &self.aes_key_generation_source,
            ) {
                (
                    Some(master_key),
                    Some(sd_card_kek_source),
                    Some(aes_kek_generation_source),
                    Some(aes_key_generation_source),
                ) => {
                    let sd_kek = generate_kek(
                        sd_card_kek_source,
                        master_key,
                        aes_kek_generation_source,
                        aes_key_generation_source,
                    )?;
                    if let Some(sd_card_save_key_source) = &self.sd_card_save_key_source {
                        self.sd_card_save_key =
                            Some(sd_kek.derive_xts_key(&sd_card_save_key_source.0)?);
                    }
                    if let Some(sd_card_nca_key_source) = &self.sd_card_nca_key_source {
                        self.sd_card_nca_key =
                            Some(sd_kek.derive_xts_key(&sd_card_nca_key_source.0)?);
                    }
                }
                _ => (),
            }

            // Derive Save MAC key
            match (
                &self.device_key,
                &self.save_mac_kek_source,
                &self.aes_kek_generation_source,
                &self.save_mac_key_source,
            ) {
                (
                    Some(device_key),
                    Some(save_mac_kek_source),
                    Some(aes_kek_generation_source),
                    Some(save_mac_key_source),
                ) => {
                    self.save_mac_key = Some(generate_kek(
                        save_mac_kek_source,
                        device_key,
                        aes_kek_generation_source,
                        save_mac_key_source,
                    )?);
                }
                _ => (),
            }
        }
        Ok(())
    }
}
