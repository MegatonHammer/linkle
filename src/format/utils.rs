use elf;
use lz4_sys;
use std;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::process;
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

fn compress_lz4_unsafe(uncompressed_data: &mut Vec<u8>) -> Vec<u8> {
    let uncompressed_data_size = uncompressed_data.len() as i32;
    let max_compression_size = unsafe { lz4_sys::LZ4_compressBound(uncompressed_data_size) };

    // Create res vector and make sure the max memory needed is availaible
    let mut res: Vec<u8> = Vec::new();
    res.resize(max_compression_size as usize, 0);

    let res_code = unsafe {
        lz4_sys::LZ4_compress_default(
            uncompressed_data.as_mut_ptr(),
            res.as_mut_ptr(),
            uncompressed_data_size,
            max_compression_size,
        )
    };

    if res_code <= 0 {
        println!("Error: LZ4 compression function returned {}", res_code);
        process::exit(1)
    } else {
        res.resize(res_code as usize, 0);
        res
    }
}

pub fn compress_lz4(uncompressed_data: &mut Vec<u8>) -> Vec<u8> {
    compress_lz4_unsafe(uncompressed_data)
}

pub fn calculate_sha256(data: &Vec<u8>) -> std::io::Result<Vec<u8>> {
    let mut hasher = Sha256::default();
    hasher.input(data);
    Ok(Vec::from(hasher.result().as_slice()))
}
