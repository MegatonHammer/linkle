use elf;
use lz4;
use std;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use sha2::{Sha256, Digest};

pub fn align(size: usize, padding: usize) -> usize {
    ((size as usize) + padding) & !padding
}

pub fn add_padding(vec: &mut Vec<u8>, padding: usize) -> () {
    let real_size = vec.len();
    vec.resize(align(real_size, padding), 0);
}

pub fn check_string_or_truncate(string: &mut String, name: &str, size: usize) {
    if string.len() >= size {
        println!("Warning: Truncating {} to 0x{:x}", name, size - 1);
        string.truncate(size);
    }
}

pub fn get_section_data(
    file: &mut File,
    header: &elf::types::ProgramHeader,
) -> std::io::Result<Vec<u8>> {
    let mut data = vec![0; header.filesz as usize];
    file.seek(SeekFrom::Start(header.offset))?;
    file.read(&mut data)?;
    Ok(data)
}

pub fn compress_lz4(uncompressed_data: &mut Vec<u8>) -> std::io::Result<Vec<u8>> {
    lz4::block::compress(&mut uncompressed_data[..], None, false)
}

pub fn calculate_sha256(data: &Vec<u8>) -> std::io::Result<Vec<u8>> {
    let mut hasher = Sha256::default();
    hasher.input(data);
    Ok(Vec::from(hasher.result().as_slice()))
}
