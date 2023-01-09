use serde::de::{Unexpected, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::fmt;

pub fn align(size: usize, padding: usize) -> usize {
    ((size as usize) + padding) & !padding
}

pub fn add_padding(vec: &mut Vec<u8>, padding: usize) {
    let real_size = vec.len();
    vec.resize(align(real_size, padding), 0);
}

pub fn check_string_or_truncate(string: &mut String, name: &str, size: usize) {
    if string.len() >= size {
        println!("Warning: Truncating {} to 0x{:x}", name, size - 1);
        string.truncate(size);
    }
}

pub fn compress_lz4(uncompressed_data: &[u8]) -> std::io::Result<Vec<u8>> {
    lz4::block::compress(uncompressed_data, None, false)
}

pub fn compress_blz(uncompressed_data: &mut Vec<u8>) -> blz_nx::BlzResult<Vec<u8>> {
    let mut compressed_data =
        vec![0; blz_nx::get_worst_compression_buffer_size(uncompressed_data.len())];
    let res = blz_nx::compress_raw(&mut uncompressed_data[..], &mut compressed_data[..])?;
    compressed_data.resize(res, 0);
    Ok(compressed_data)
}

pub fn calculate_sha256(data: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut hasher = Sha256::default();
    hasher.update(data);
    Ok(Vec::from(hasher.finalize().as_slice()))
}

#[derive(Default)]
pub struct HexOrNum(pub u64);

impl fmt::Debug for HexOrNum {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_fmt(format_args!("{:#010x}", self.0))
    }
}

impl<'de> Deserialize<'de> for HexOrNum {
    fn deserialize<D>(deserializer: D) -> Result<HexOrNum, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct HexOrNumVisitor;

        impl<'a> Visitor<'a> for HexOrNumVisitor {
            type Value = u64;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                write!(formatter, "an integer or a hex-formatted string")
            }

            fn visit_u64<E>(self, v: u64) -> Result<u64, E>
            where
                E: serde::de::Error,
            {
                Ok(v)
            }

            fn visit_str<E>(self, v: &str) -> Result<u64, E>
            where
                E: serde::de::Error,
            {
                if let Some(v) = v.strip_prefix("0x") {
                    u64::from_str_radix(v, 16)
                        .map_err(|_| E::invalid_value(Unexpected::Str(v), &"a hex-encoded string"))
                } else {
                    Err(E::invalid_value(
                        Unexpected::Str(v),
                        &"a hex-encoded string",
                    ))
                }
            }
        }

        let num = Deserializer::deserialize_any(deserializer, HexOrNumVisitor)?;
        Ok(HexOrNum(num))
    }
}

impl Serialize for HexOrNum {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(&format_args!("{:#010x}", self.0))
    }
}
