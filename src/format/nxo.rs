use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use elf;
use elf::types::{EM_ARM, EM_AARCH64, ProgramHeader, PT_LOAD, SHT_NOTE, Machine};
use crate::format::{utils, romfs::RomFs, nacp::NacpFile, npdm::KernelCapability};
use std;
use std::fs::File;
use std::io::{self, Cursor, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process;
use serde_derive::{Serialize, Deserialize};
use crate::format::utils::HexOrNum;
use std::convert::TryFrom;

// TODO: Support switchbrew's embedded files for NRO
pub struct NxoFile {
    file: File,
    machine: Machine,
    text_section: ProgramHeader,
    rodata_section: ProgramHeader,
    data_section: ProgramHeader,
    bss_section: Option<ProgramHeader>,
    build_id: Option<Vec<u8>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KipNpdm {
    name: String,
    title_id: HexOrNum,
    main_thread_stack_size: HexOrNum,
    main_thread_priority: u8,
    default_cpu_id: u8,
    process_category: u8,
    flags: Option<u8>,
    kernel_capabilities: Vec<KernelCapability>,
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
            output_writter.write_all(&build_id_data[0x10..])?;
        }
        None => {
            output_writter.write_all(&[0; 0x20])?;
        }
    }
    Ok(())
}

impl NxoFile {
    pub fn from_elf(input: &str) -> std::io::Result<Self> {
        let path = PathBuf::from(input);
        let mut file = File::open(path)?;

        let elf_file = elf::File::open_stream(&mut file).unwrap();

        if elf_file.ehdr.machine != EM_AARCH64 && elf_file.ehdr.machine != EM_ARM {
            println!("Error: Invalid ELF file (expected ARM or AArch64 machine)");
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
                if x.shdr.shtype == SHT_NOTE {
                    let mut data = Cursor::new(x.data.clone());
                    // Ignore the two first offset of nhdr32
                    data.seek(SeekFrom::Start(0x8)).unwrap();
                    let n_type = data.read_u32::<LittleEndian>().unwrap();

                    // BUILD_ID
                    n_type == 0x3
                } else {
                    false
                }
            })
            .map(|section| section.data.clone())
            .next();

        Ok(NxoFile {
            file,
            machine: elf_file.ehdr.machine,
            text_section: *text_section,
            rodata_section: *rodata_section,
            data_section: *data_section,
            bss_section,
            build_id,
        })
    }

    pub fn write_nro<T>(&mut self, output_writter: &mut T, romfs: Option<RomFs>, icon: Option<&str>, nacp: Option<NacpFile>) -> std::io::Result<()>
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

        if let Some(section) = self.bss_section {
            pad_segment(&mut data, code.len() + rodata.len(), &section);
        }

        let total_len: u32 = (code.len() + rodata.len() + data.len()) as u32;

        // Write the first branching and mod0 offset
        output_writter.write_all(&code[..0x10])?;

        // NRO magic
        output_writter.write_all(b"NRO0")?;
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
                if section.vaddr != u64::from(file_offset) {
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

        output_writter.write_all(&code[0x80..])?;
        output_writter.write_all(&rodata)?;
        output_writter.write_all(&data)?;

        // Early return if there's no need for an ASET section.
        if let (None, None, None) = (&icon, &romfs, &nacp) {
            return Ok(())
        }

        // Aset handling
        output_writter.write_all(b"ASET")?;
        output_writter.write_u32::<LittleEndian>(0)?; // version

        // Offset to the next available region.
        let mut offset = 8 + 16 + 16 + 16;

        let icon_len = if let Some(icon) = &icon {
            // TODO: Check if icon is a 256x256 JPEG. Convert it if it isn't?
            let icon_len = Path::new(icon).metadata()?.len();
            output_writter.write_u64::<LittleEndian>(offset)?;
            output_writter.write_u64::<LittleEndian>(icon_len)?;
            icon_len
        } else {
            output_writter.write_u64::<LittleEndian>(0)?;
            output_writter.write_u64::<LittleEndian>(0)?;
            0
        };

        offset += icon_len;

        let nacp_len = if let Some(nacp) = &nacp {
            let nacp_len = nacp.len() as u64;
            output_writter.write_u64::<LittleEndian>(offset)?;
            output_writter.write_u64::<LittleEndian>(nacp_len)?;
            nacp_len
        } else {
            output_writter.write_u64::<LittleEndian>(0)?;
            output_writter.write_u64::<LittleEndian>(0)?;
            0
        };

        offset += nacp_len;

        if let Some(romfs) = &romfs {
            output_writter.write_u64::<LittleEndian>(offset)?;
            output_writter.write_u64::<LittleEndian>(romfs.len() as u64)?;
        } else {
            output_writter.write_u64::<LittleEndian>(0)?;
            output_writter.write_u64::<LittleEndian>(0)?;
        };

        if let Some(icon) = icon {
            assert_eq!(io::copy(&mut File::open(icon)?, output_writter)?, icon_len, "Icon changed while building.");
        }

        if let Some(mut nacp) = nacp {
            nacp.write(output_writter)?;
        }

        if let Some(romfs) = romfs {
            romfs.write(output_writter)?;
        }
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
        if let Some(section) = self.bss_section {
            pad_segment(&mut data, data_section.vaddr as usize, &section);
        }

        // NSO magic
        output_writter.write_all(b"NSO0")?;
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
        let compressed_code = utils::compress_lz4(&mut code)?;
        let compressed_code_size = compressed_code.len() as u32;
        output_writter.write_u32::<LittleEndian>(file_offset as u32)?;
        output_writter.write_u32::<LittleEndian>(text_section.vaddr as u32)?;
        output_writter.write_u32::<LittleEndian>(code_size as u32)?;

        // Module offset (TODO: SUPPORT THAT)
        output_writter.write_u32::<LittleEndian>(0)?;

        file_offset += compressed_code_size;

        // .rodata segment
        let rodata_size = rodata.len() as u32;
        let compressed_rodata = utils::compress_lz4(&mut rodata)?;
        let compressed_rodata_size = compressed_rodata.len() as u32;
        output_writter.write_u32::<LittleEndian>(file_offset as u32)?;
        output_writter.write_u32::<LittleEndian>(rodata_section.vaddr as u32)?;
        output_writter.write_u32::<LittleEndian>(rodata_size as u32)?;

        // Module file size (TODO: SUPPORT THAT)
        output_writter.write_u32::<LittleEndian>(0)?;

        file_offset += compressed_rodata_size;

        // .data segment
        let data_size = data.len() as u32;
        let compressed_data = utils::compress_lz4(&mut data)?;
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
        output_writter.write_all(&text_sum)?;

        // .rodata sha256
        let rodata_sum = utils::calculate_sha256(&rodata)?;
        output_writter.write_all(&rodata_sum)?;

        // .data sha256
        let data_sum = utils::calculate_sha256(&data)?;
        output_writter.write_all(&data_sum)?;

        // compressed data
        output_writter.write_all(&compressed_code)?;
        output_writter.write_all(&compressed_rodata)?;
        output_writter.write_all(&compressed_data)?;
        Ok(())
    }

    pub fn write_kip1<T>(&mut self, output_writer: &mut T, npdm: &KipNpdm) -> std::io::Result<()>
    where
        T: Write,
    {
        output_writer.write_all(b"KIP1")?;
        let mut name : Vec<u8> = npdm.name.clone().into();
        name.resize(12, 0);
        output_writer.write_all(&name[..])?;
        output_writer.write_u64::<LittleEndian>(npdm.title_id.0)?; // TitleId
        output_writer.write_u32::<LittleEndian>(u32::from(npdm.process_category))?;
        output_writer.write_u8(npdm.main_thread_priority)?;
        output_writer.write_u8(npdm.default_cpu_id)?;
        output_writer.write_u8(0)?; // Reserved
        if let Some(flags) = npdm.flags {
            output_writer.write_u8(flags)?;
        } else if self.machine == EM_AARCH64 {
            // Compression enable, Is64Bit, IsAddrSpace32Bit, UseSystemPoolPartition
            output_writer.write_u8(0b00111111)?;
        } else if self.machine == EM_ARM {
            // Compression enable, UseSystemPoolPartition
            output_writer.write_u8(0b00100111)?;
        } else {
            unimplemented!("Unknown machine type");
        }

        let mut section_data = utils::get_section_data(&mut self.file, &self.text_section)?;
        let text_data = utils::compress_blz(&mut section_data).unwrap();
        let mut section_data = utils::get_section_data(&mut self.file, &self.rodata_section)?;
        let rodata_data = utils::compress_blz(&mut section_data).unwrap();
        let mut section_data = utils::get_section_data(&mut self.file, &self.data_section)?;
        let data_data = utils::compress_blz(&mut section_data).unwrap();

        write_kip_section_header(output_writer, &self.text_section, 0, text_data.len() as u32)?;
        write_kip_section_header(output_writer, &self.rodata_section, u32::try_from(npdm.main_thread_stack_size.0).expect("Exected main_thread_stack_size to be an u32"), rodata_data.len() as u32)?;
        write_kip_section_header(output_writer, &self.data_section, 0, data_data.len() as u32)?;

        if let Some(section) = self.bss_section {
            output_writer.write_u32::<LittleEndian>(u32::try_from(section.vaddr).expect("BSS vaddr too big"))?;
            output_writer.write_u32::<LittleEndian>(u32::try_from(section.memsz).expect("BSS memsize too big"))?;
        } else {
            // in this case the bss is missing or is embedeed in .data. libnx does that, let's support it
            let data_section_size = (self.data_section.filesz + 0xFFF) & !0xFFF;
            let bss_size = if self.data_section.memsz > data_section_size {
                (((self.data_section.memsz - data_section_size) + 0xFFF) & !0xFFF) as u32
            } else {
                0
            };
            output_writer.write_u32::<LittleEndian>(u32::try_from(self.data_section.vaddr + data_section_size).unwrap())?;
            output_writer.write_u32::<LittleEndian>(bss_size)?;
        }
        output_writer.write_u32::<LittleEndian>(0)?;
        output_writer.write_u32::<LittleEndian>(0)?;

        // Empty Sections:
        for i in 4..6 {
            output_writer.write_u32::<LittleEndian>(0)?;
            output_writer.write_u32::<LittleEndian>(0)?;
            output_writer.write_u32::<LittleEndian>(0)?;
            output_writer.write_u32::<LittleEndian>(0)?;
        }

        // Kernel caps:
        let caps = npdm.kernel_capabilities.iter()
            .map(|v| v.encode())
            .flatten()
            .collect::<Vec<u32>>();
        assert!(caps.len() < 0x20, "kernel_capabilities should have less than 0x20 entries!");

        unsafe {
            // Safety: This is safe. I'm just casting a slice of u32 to a slice of u8
            // for fuck's sake.
            output_writer.write_all(std::slice::from_raw_parts(caps.as_ptr() as *const u8, caps.len() * 4))?;
        }

        output_writer.write_all(&vec![0xFF; (0x20 - caps.len()) * 4])?;

        // Section data
        output_writer.write_all(&text_data);
        output_writer.write_all(&rodata_data);
        output_writer.write_all(&data_data);

        Ok(())
    }
}

pub fn write_kip_section_header<T>(output_writer: &mut T, section: &ProgramHeader, attributes: u32, compressed_size: u32) -> std::io::Result<()>
where
    T: Write,
{
    output_writer.write_u32::<LittleEndian>(u32::try_from(section.vaddr).expect("vaddr too big"))?;
    output_writer.write_u32::<LittleEndian>(u32::try_from(section.filesz).expect("memsz too big"))?;
    output_writer.write_u32::<LittleEndian>(u32::try_from(compressed_size).expect("Compressed size too big"))?;
    output_writer.write_u32::<LittleEndian>(attributes)?;

    Ok(())
}
