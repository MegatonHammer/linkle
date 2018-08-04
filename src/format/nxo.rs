use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use elf;
use elf::types::{EM_AARCH64, ProgramHeader, PT_LOAD, SHT_NOTE};
use format::utils;
use std;
use std::fs::File;
use std::io::Cursor;
use std::io::Seek;
use std::io::SeekFrom;
use std::io::Write;
use std::path::PathBuf;
use std::process;

// TODO: Support switchbrew's embedded files for NRO
pub struct NxoFile {
    file: File,
    text_section: ProgramHeader,
    rodata_section: ProgramHeader,
    data_section: ProgramHeader,
    bss_section: Option<ProgramHeader>,
    build_id: Option<Vec<u8>>,
}

fn pad_segment(previous_segment_data: &mut Vec<u8>, offset: usize, section: &ProgramHeader) {
    let section_vaddr = section.vaddr as usize;
    let section_supposed_start = previous_segment_data.len() + offset;

    if section_vaddr > section_supposed_start {
        let real_size = previous_segment_data.len();
        previous_segment_data.resize(real_size + (section_vaddr - section_supposed_start), 0);
    }
}

fn write_build_id<T>(build_id: &Option<Vec<u8>>, output_writter: &mut T) -> std::io::Result<()>
where
    T: Write,
{
    match build_id {
        Some(build_id) => {
            let mut build_id_data = build_id.clone();
            if build_id_data.len() > 0x30 {
                println!(
                    "Warning: build-id is too big (0x{:x} > 0x30), the content will be shrink.",
                    build_id_data.len()
                );
            }
            build_id_data.resize(0x30, 0);
            // skip the tag nhdr
            output_writter.write(&build_id_data[0x10..])?;
        }
        None => {
            output_writter.write(&[0; 0x20])?;
        }
    }
    Ok(())
}

impl NxoFile {
    pub fn from_elf(input: &str) -> std::io::Result<Self> {
        let path = PathBuf::from(input);
        let mut file = File::open(path)?;

        let elf_file = elf::File::open_stream(&mut file).unwrap();

        if elf_file.ehdr.machine != EM_AARCH64 {
            println!("Error: Invalid ELF file (expected AArch64 machine)");
            process::exit(1)
        }

        let sections = &elf_file.sections;
        let phdrs: Vec<ProgramHeader> = elf_file.phdrs.to_vec();
        let text_section = phdrs.get(0).unwrap_or_else(|| {
            println!("Error: .text not found in ELF file");
            process::exit(1)
        });

        let rodata_section = phdrs.get(1).unwrap_or_else(|| {
            println!("Error: .rodata not found in ELF file");
            process::exit(1)
        });

        let data_section = phdrs.get(2).unwrap_or_else(|| {
            println!("Error: .data not found in ELF file");
            process::exit(1)
        });

        let bss_section = match phdrs.get(3) {
            Some(s) => {
                if s.progtype == PT_LOAD {
                    Some(*s)
                } else {
                    None
                }
            }
            None => None,
        };
        let build_id = sections
            .into_iter()
            .filter(|&x| {
                match x.shdr.shtype == SHT_NOTE {
                    true => {
                        let mut data = Cursor::new(x.data.clone());
                        // Ignore the two first offset of nhdr32
                        data.seek(SeekFrom::Start(0x8)).unwrap();
                        let n_type = data.read_u32::<LittleEndian>().unwrap();

                        // BUILD_ID
                        n_type == 0x3
                    }
                    false => false,
                }
            })
            .map(|section| section.data.clone())
            .next();

        Ok(NxoFile {
            file,
            text_section: *text_section,
            rodata_section: *rodata_section,
            data_section: *data_section,
            bss_section: bss_section,
            build_id: build_id,
        })
    }

    pub fn write_nro<T>(&mut self, output_writter: &mut T) -> std::io::Result<()>
    where
        T: Write,
    {
        let text_section = &self.text_section;
        let rodata_section = &self.rodata_section;
        let data_section = &self.data_section;

        // Get segments data
        let mut code = utils::get_section_data(&mut self.file, text_section)?;
        let mut rodata = utils::get_section_data(&mut self.file, rodata_section)?;
        let mut data = utils::get_section_data(&mut self.file, data_section)?;

        // First correctly align to be conform to the NRO standard
        utils::add_padding(&mut code, 0xFFF);
        utils::add_padding(&mut rodata, 0xFFF);
        utils::add_padding(&mut data, 0xFFF);

        // Finally fix possible misalign of  vaddr because NRO only have one base
        pad_segment(&mut code, 0, rodata_section);
        pad_segment(&mut rodata, code.len(), data_section);

        match self.bss_section {
            Some(section) => {
                pad_segment(&mut data, code.len() + rodata.len(), &section);
            }
            _ => (),
        }

        let total_len: u32 = (code.len() + rodata.len() + data.len()) as u32;

        // Write the first branching and mod0 offset
        output_writter.write(&code[..0x10])?;

        // NRO magic
        output_writter.write(b"NRO0")?;
        // Unknown
        output_writter.write_u32::<LittleEndian>(0)?;
        // Total size
        output_writter.write_u32::<LittleEndian>(total_len)?;
        // Unknown
        output_writter.write_u32::<LittleEndian>(0)?;

        // Segment Header (3 entries)
        let mut file_offset = 0;

        // .text segment
        let code_size = code.len() as u32;
        output_writter.write_u32::<LittleEndian>(file_offset)?;
        output_writter.write_u32::<LittleEndian>(code_size)?;
        file_offset += code_size;

        // .rodata segment
        let rodata_size = rodata.len() as u32;
        output_writter.write_u32::<LittleEndian>(file_offset)?;
        output_writter.write_u32::<LittleEndian>(rodata_size)?;
        file_offset += rodata_size;

        // .data segment
        let data_size = data.len() as u32;
        output_writter.write_u32::<LittleEndian>(file_offset)?;
        output_writter.write_u32::<LittleEndian>(data_size)?;
        file_offset += data_size;

        // BSS size
        match self.bss_section {
            Some(section) => {
                if section.vaddr != file_offset as u64 {
                    println!(
                    "Warning: possible misalign bss\n.bss addr: 0x{:x}\nexpected offset: 0x{:x}",
                    section.vaddr, file_offset);
                }
                output_writter
                    .write_u32::<LittleEndian>(((section.memsz + 0xFFF) & !0xFFF) as u32)?;
            }
            _ => {
                // in this case the bss is missing or is embedeed in .data. libnx does that, let's support it
                let data_section_size = (data_section.filesz + 0xFFF) & !0xFFF;
                let bss_size = if data_section.memsz > data_section_size {
                    (((data_section.memsz - data_section_size) + 0xFFF) & !0xFFF) as u32
                } else {
                    0
                };
                output_writter.write_u32::<LittleEndian>(bss_size)?;
            }
        }
        // Unknown
        output_writter.write_u32::<LittleEndian>(0)?;

        write_build_id(&self.build_id, output_writter)?;

        // Padding
        output_writter.write_u64::<LittleEndian>(0)?;
        output_writter.write_u64::<LittleEndian>(0)?;

        // Unknown
        output_writter.write_u64::<LittleEndian>(0)?;
        output_writter.write_u64::<LittleEndian>(0)?;

        output_writter.write(&code[0x80..])?;
        output_writter.write(&rodata)?;
        output_writter.write(&data)?;
        Ok(())
    }

    pub fn write_nso<T>(&mut self, output_writter: &mut T) -> std::io::Result<()>
    where
        T: Write,
    {
        let text_section = &self.text_section;
        let rodata_section = &self.rodata_section;
        let data_section = &self.data_section;

        let mut code = utils::get_section_data(&mut self.file, text_section)?;
        let mut rodata = utils::get_section_data(&mut self.file, rodata_section)?;
        let mut data = utils::get_section_data(&mut self.file, data_section)?;

        // First correctly align to avoid possible compression issues
        utils::add_padding(&mut code, 0xFFF);
        utils::add_padding(&mut rodata, 0xFFF);
        utils::add_padding(&mut data, 0xFFF);

        // Because bss doesn't have it's own segment in NSO, we need to pad .data to the .bss vaddr
        match self.bss_section {
            Some(section) => {
                pad_segment(&mut data, data_section.vaddr as usize, &section);
            }
            _ => (),
        }

        // NSO magic
        output_writter.write(b"NSO0")?;
        // Unknown
        output_writter.write_u32::<LittleEndian>(0)?;
        // Unknown
        output_writter.write_u32::<LittleEndian>(0)?;

        // Flags, set compression + sum check
        output_writter.write_u32::<LittleEndian>(0x3F)?;

        // Segment Header (3 entries)
        let mut file_offset = 0x100;

        // .text segment
        let code_size = code.len() as u32;
        let compressed_code = utils::compress(&mut code);
        let compressed_code_size = compressed_code.len() as u32;
        output_writter.write_u32::<LittleEndian>(file_offset as u32)?;
        output_writter.write_u32::<LittleEndian>(text_section.vaddr as u32)?;
        output_writter.write_u32::<LittleEndian>(code_size as u32)?;

        // Module offset (TODO: SUPPORT THAT)
        output_writter.write_u32::<LittleEndian>(0)?;

        file_offset += compressed_code_size;

        // .rodata segment
        let rodata_size = rodata.len() as u32;
        let compressed_rodata = utils::compress(&mut rodata);
        let compressed_rodata_size = compressed_rodata.len() as u32;
        output_writter.write_u32::<LittleEndian>(file_offset as u32)?;
        output_writter.write_u32::<LittleEndian>(rodata_section.vaddr as u32)?;
        output_writter.write_u32::<LittleEndian>(rodata_size as u32)?;

        // Module file size (TODO: SUPPORT THAT)
        output_writter.write_u32::<LittleEndian>(0)?;

        file_offset += compressed_rodata_size;

        // .data segment
        let data_size = data.len() as u32;
        let compressed_data = utils::compress(&mut data);
        let compressed_data_size = compressed_data.len() as u32;
        let uncompressed_data_size = data.len() as u64;
        output_writter.write_u32::<LittleEndian>(file_offset as u32)?;
        output_writter.write_u32::<LittleEndian>(data_section.vaddr as u32)?;
        output_writter.write_u32::<LittleEndian>(data_size as u32)?;

        // BSS size
        match self.bss_section {
            Some(section) => {
                let memory_offset = data_section.vaddr + uncompressed_data_size;
                if section.vaddr != memory_offset {
                    println!(
                    "Warning: possible misalign bss\n.bss addr: 0x{:x}\nexpected offset: 0x{:x}",
                    section.vaddr, memory_offset);
                }
                // (bss_segment['p_memsz'] + 0xFFF) & ~0xFFF
                output_writter
                    .write_u32::<LittleEndian>(((section.memsz + 0xFFF) & !0xFFF) as u32)?;
            }
            _ => {
                // in this case the bss is missing or is embedeed in .data. libnx does that, let's support it
                output_writter
                    .write_u32::<LittleEndian>((data_section.memsz - data_section.filesz) as u32)?;
            }
        }

        write_build_id(&self.build_id, output_writter)?;

        // Compressed size
        output_writter.write_u32::<LittleEndian>(compressed_code_size)?;
        output_writter.write_u32::<LittleEndian>(compressed_rodata_size)?;
        output_writter.write_u32::<LittleEndian>(compressed_data_size)?;

        // Padding (0x24)
        output_writter.write_u64::<LittleEndian>(0)?;
        output_writter.write_u64::<LittleEndian>(0)?;
        output_writter.write_u64::<LittleEndian>(0)?;
        output_writter.write_u64::<LittleEndian>(0)?;
        output_writter.write_u32::<LittleEndian>(0)?;

        // Unknown
        output_writter.write_u64::<LittleEndian>(0)?;
        output_writter.write_u64::<LittleEndian>(0)?;

        // .text sha256
        let text_sum = utils::calculate_sha256(&code)?;
        output_writter.write(&text_sum)?;

        // .rodata sha256
        let rodata_sum = utils::calculate_sha256(&rodata)?;
        output_writter.write(&rodata_sum)?;

        // .data sha256
        let data_sum = utils::calculate_sha256(&data)?;
        output_writter.write(&data_sum)?;

        // compressed data
        output_writter.write(&compressed_code)?;
        output_writter.write(&compressed_rodata)?;
        output_writter.write(&compressed_data)?;
        Ok(())
    }
}
