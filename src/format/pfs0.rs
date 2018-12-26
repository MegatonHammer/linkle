use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use crate::format::utils;
use crate::error::Error;
use crate::utils::{ReadRange, TryClone};
use failure::Backtrace;
use std;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write, BufRead};
use std::path::PathBuf;

pub trait ReadSeek: Read + Seek {}

impl<T: Read + Seek> ReadSeek for T {}

enum Pfs0Meta {
    HostPath(PathBuf),
    SubFile {
        file: Box<ReadSeek>,
        name: String,
        size: u64
    }
}

impl Pfs0Meta {
    fn file_name(&self) -> &str {
        match self {
            Pfs0Meta::HostPath(path) => path.file_name().unwrap().to_str().unwrap(),
            Pfs0Meta::SubFile { ref name, .. } => name,
        }
    }
}

pub struct Pfs0 {
    files: Vec<Pfs0Meta>,
}

impl Pfs0 {
    pub fn from_directory(input: &str) -> std::io::Result<Self> {
        let path = PathBuf::from(input);
        let mut files = Vec::new();
        for entry_res in std::fs::read_dir(path)? {
            let entry = entry_res?;
            let entry_path = &entry.path();
            if entry_path.is_dir() {
                println!("Ignoring directory \"{}\"", entry_path.display());
            } else {
                files.push(Pfs0Meta::HostPath(entry_path.clone()));
            }
        }
        Ok(Pfs0 { files })
    }

    pub fn from_reader<R: Read + Seek + TryClone + 'static>(f: R) -> Result<Self, Error> {
        // Header
        let mut f = std::io::BufReader::new(f);
        let mut magic = [0; 4];
        f.read_exact(&mut magic)?;
        if &magic != b"PFS0" {
            return Err(Error::InvalidPfs0("magic is wrong", Backtrace::new()))
        }

        let filecount = f.read_u32::<LittleEndian>()?;
        let string_table_size = f.read_u32::<LittleEndian>()?;
        let _zero = f.read_u32::<LittleEndian>()?;
        let mut files = Vec::with_capacity(filecount as usize);

        let string_table_offset = 0x10 + filecount as u64 * 0x18;
        let data_offset = string_table_offset + string_table_size as u64;

        for file in 0..filecount {
            let offset = data_offset + f.read_u64::<LittleEndian>()?;
            let size = f.read_u64::<LittleEndian>()?;
            let filename_offset = string_table_offset + f.read_u32::<LittleEndian>()? as u64;
            let _zero = f.read_u32::<LittleEndian>()?;
            files.push((offset, size, filename_offset));
        }

        let mut finalfiles = Vec::with_capacity(filecount as usize);
        for (offset, size, filename_offset) in files {
            f.seek(SeekFrom::Start(filename_offset as u64))?;
            let mut filename = Vec::new();
            f.read_until(b'\0', &mut filename)?;
            filename.pop();
            let filename = String::from_utf8(filename)?;
            finalfiles.push(Pfs0Meta::SubFile {
                file: Box::new(ReadRange::new(f.get_ref().try_clone()?, offset, size)),
                name: filename,
                size
            });
        }
        Ok(Pfs0 {
            files: finalfiles
        })
    }

    pub fn write_pfs0<T>(&mut self, output_writter: &mut T) -> std::io::Result<()>
    where
        T: Write + Seek,
    {
        let files = &mut self.files;
        let file_count = files.len() as u32;

        // Header
        output_writter.write_all(b"PFS0")?;
        output_writter.write_u32::<LittleEndian>(file_count)?;
        let string_table_size = utils::align(
           files
                .iter()
                .map(|x| x.file_name().len() + 1)
                .sum(),
            0x1F,
        );
        output_writter.write_u32::<LittleEndian>(string_table_size as u32)?;
        output_writter.write_u32::<LittleEndian>(0)?;

        let file_table_size = 0x18 * files.len() as u64;
        let string_table_pos: u64 = 0x10 + file_table_size;
        let data_pos: u64 = string_table_pos + (string_table_size as u64);

        // Create empty tabes
        let mut empty_tables = Vec::new();
        empty_tables.resize(data_pos as usize - 0x10, 0);
        output_writter.write_all(&empty_tables)?;

        let mut string_offset = 0;
        let mut data_offset = 0;

        for (file_index, file) in files.iter_mut().enumerate().map(|(idx, path)| (idx as u64, path))  {
            // Seek and write file name to string table
            output_writter
                .seek(SeekFrom::Start(string_table_pos + string_offset))?;

            println!(
                "Writing {}... [{}/{}]",
                file.file_name(),
                file_index + 1,
                file_count
            );
            output_writter.write_all(file.file_name().as_bytes())?;
            output_writter.write_all(b"\0")?;

            let mut host_file;

            let (file, file_size, file_name) = match file {
                Pfs0Meta::HostPath(path) => {
                    // Open the file and retrieve the size of it
                    host_file = File::open(&path)?;
                    let file_size = host_file.metadata()?.len();
                    let name = path.file_name().unwrap().to_str().unwrap();
                    (&mut host_file as &mut dyn ReadSeek, file_size, name)
                },
                Pfs0Meta::SubFile { file, name, size, .. } => {
                    (file as &mut dyn ReadSeek, *size, &**name)
                }
            };

            // Write file entry to the file entry table
            output_writter
                .seek(SeekFrom::Start(0x10 + (file_index * 0x18)))?;

            output_writter.write_u64::<LittleEndian>(data_offset)?;
            output_writter.write_u64::<LittleEndian>(file_size)?;
            output_writter.write_u64::<LittleEndian>(string_offset)?;

            // Write the actual file content
            output_writter
                .seek(SeekFrom::Start(data_pos + data_offset))?;

            file.seek(SeekFrom::Start(0));
            let size = io::copy(file, output_writter)?;
            assert_eq!(size, file_size);

            data_offset += file_size;
            string_offset += file_name.len() as u64 + 1;
        }

        Ok(())
    }

    pub fn files(self) -> impl Iterator<Item = io::Result<Pfs0File>> + 'static {
        Pfs0FileIterator {
            pfs0: self,
        }
    }
}

pub struct Pfs0File {
    name: String,
    file: Box<dyn ReadSeek + 'static>
}

impl Pfs0File {
    pub fn file_name(&self) -> &str {
        &self.name
    }
}

impl Read for Pfs0File {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.file.read(buf)
    }
}

impl Seek for Pfs0File {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        self.file.seek(from)
    }
}

struct Pfs0FileIterator {
    pfs0: Pfs0,
}

impl Iterator for Pfs0FileIterator {
    type Item = io::Result<Pfs0File>;

    fn next(&mut self) -> Option<io::Result<Pfs0File>> {
        if let Some(meta) = self.pfs0.files.pop() {
            let name = meta.file_name().into();
            let file = match meta {
                Pfs0Meta::HostPath(path) => {
                    File::open(path)
                        .map(|v| Box::new(v) as Box<dyn ReadSeek>)
                },
                Pfs0Meta::SubFile { mut file, .. } => {
                    file.seek(SeekFrom::Start(0))
                        .map(|_| file)
                }
            };
            Some(file.map(|file| Pfs0File {
                name, file
            }))
        } else {
            None
        }
    }
}
