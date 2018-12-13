use byteorder::{LittleEndian, WriteBytesExt};
use crate::format::utils;
use std;
use std::fs::File;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::io::Write;
use std::path::PathBuf;

pub struct Pfs0File {
    pub files: Vec<PathBuf>,
}

impl Pfs0File {
    pub fn from_directory(input: &str) -> std::io::Result<Self> {
        let path = PathBuf::from(input);
        let mut files: Vec<PathBuf> = Vec::new();
        for entry_res in std::fs::read_dir(path)? {
            let entry = entry_res?;
            let entry_path = &entry.path();
            if entry_path.is_dir() {
                println!("Ignoring directory \"{}\"", entry_path.display());
            } else {
                files.push(entry_path.clone());
            }
        }
        Ok(Pfs0File { files })
    }

    pub fn write<T>(&mut self, output_writter: &mut T) -> std::io::Result<()>
    where
        T: Write + Seek,
    {
        let paths: &Vec<PathBuf> = &self.files;
        let file_count = paths.len() as u32;

        // Header
        output_writter.write_all(b"PFS0")?;
        output_writter.write_u32::<LittleEndian>(file_count)?;
        let string_table_size = utils::align(
            paths
                .iter()
                .map(|x| x.file_name().unwrap().to_str().unwrap().len() + 1)
                .sum(),
            0x1F,
        );
        output_writter.write_u32::<LittleEndian>(string_table_size as u32)?;
        output_writter.write_u32::<LittleEndian>(0)?;

        let file_table_size = 0x18 * paths.len() as u64;
        let string_table_pos: u64 = 0x10 + file_table_size;
        let data_pos: u64 = string_table_pos + (string_table_size as u64);

        // Create empty tabes
        let mut empty_tables = Vec::new();
        empty_tables.resize(data_pos as usize - 0x10, 0);
        output_writter.write_all(&empty_tables)?;

        let mut string_offset = 0;
        let mut data_offset = 0;

        for (file_index, path) in paths.iter().enumerate().map(|(idx, path)| (idx as u64, path))  {
            // Seek and write file name to string table
            output_writter
                .seek(SeekFrom::Start(string_table_pos + string_offset))
                .unwrap();
            let file_name = path.file_name().unwrap().to_str().unwrap().to_string();
            println!(
                "Writing {}... [{}/{}]",
                file_name,
                file_index + 1,
                file_count
            );
            output_writter.write_all(file_name.as_bytes())?;
            output_writter.write_all(b"\0")?;

            // Open the file and retrieve the size of it
            let mut file = File::open(path)?;
            let file_size = file.metadata()?.len();

            // Write file entry to the file entry table
            output_writter
                .seek(SeekFrom::Start(0x10 + (file_index * 0x18)))
                .unwrap();
            output_writter.write_u64::<LittleEndian>(data_offset)?;
            output_writter.write_u64::<LittleEndian>(file_size)?;
            output_writter.write_u64::<LittleEndian>(string_offset)?;

            // Write the actual file content
            output_writter
                .seek(SeekFrom::Start(data_pos + data_offset))
                .unwrap();
            let mut buffer = [0; 4096];
            loop {
                let n = file.read(&mut buffer)?;
                if n == 0 {
                    break;
                }
                output_writter.write_all(&buffer[..n])?;
            }

            data_offset += file_size;
            string_offset += file_name.len() as u64 + 1;
        }

        Ok(())
    }
}
