use crate::format::utils::HexOrNum;
use crate::format::{nacp::NacpFile, npdm::KernelCapability, romfs::RomFs, utils};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use elf::types::{Machine, ProgramHeader, SectionHeader, EM_AARCH64, EM_ARM, PT_LOAD, SHT_NOTE};
use serde_derive::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::convert::{TryFrom, TryInto};
use std::fs::File;
use std::io::{self, Cursor, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process;

// TODO: Support switchbrew's embedded files for NRO
pub struct NxoFile {
    file: File,
    machine: Machine,
    text_segment: ProgramHeader,
    rodata_segment: ProgramHeader,
    data_segment: ProgramHeader,
    bss_segment: Option<ProgramHeader>,
    eh_frame_hdr_section: Option<SectionHeader>,
    dynamic_section: Option<SectionHeader>,
    dynstr_section: Option<SectionHeader>,
    dynsym_section: Option<SectionHeader>,
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

fn pad_segment(previous_segment_data: &mut Vec<u8>, offset: usize, segment: &ProgramHeader) {
    let segment_vaddr = segment.vaddr as usize;
    let segment_supposed_start = previous_segment_data.len() + offset;

    if segment_vaddr > segment_supposed_start {
        let real_size = previous_segment_data.len();
        previous_segment_data.resize(real_size + (segment_vaddr - segment_supposed_start), 0);
    }
}

fn write_build_id<T>(
    build_id: &Option<Vec<u8>>,
    output_writter: &mut T,
    text_data: &[u8],
    rodata: &[u8],
    data: &[u8],
) -> std::io::Result<()>
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
            let mut hasher = Sha256::default();
            hasher.update(text_data);
            hasher.update(rodata);
            hasher.update(data);

            output_writter.write_all(&hasher.finalize().as_slice()[..0x20])?;
        }
    }
    Ok(())
}

fn write_mod0<T>(
    nxo_file: &NxoFile,
    offset: u32,
    output_writter: &mut T,
    bss_addr: u32,
    bss_size: u32,
) -> std::io::Result<()>
where
    T: Write,
{
    // MOD magic
    output_writter.write_all(b"MOD0")?;
    // Dynamic Offset
    output_writter.write_u32::<LittleEndian>(
        nxo_file
            .dynamic_section
            .as_ref()
            .map(|v| v.addr as u32 - offset)
            .unwrap_or(0),
    )?;

    // BSS Start Offset
    output_writter.write_u32::<LittleEndian>(bss_addr - offset)?;
    // BSS End Offset
    output_writter.write_u32::<LittleEndian>(bss_addr + bss_size - offset)?;

    let (eh_frame_hdr_addr, eh_frame_hdr_size) = nxo_file
        .eh_frame_hdr_section
        .as_ref()
        .map(|v| (v.addr, v.size))
        .unwrap_or((0, 0));
    // EH Frame Header Start
    output_writter.write_u32::<LittleEndian>(eh_frame_hdr_addr as u32 - offset)?;
    // EH Frame Header End
    output_writter
        .write_u32::<LittleEndian>(eh_frame_hdr_addr as u32 + eh_frame_hdr_size as u32 - offset)?;

    // RTLD ptr - written at runtime by RTLD
    output_writter.write_u32::<LittleEndian>(0)?;

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
        let text_segment = phdrs.get(0).unwrap_or_else(|| {
            println!("Error: .text not found in ELF file");
            process::exit(1)
        });

        let rodata_segment = phdrs.get(1).unwrap_or_else(|| {
            println!("Error: .rodata not found in ELF file");
            process::exit(1)
        });

        let data_segment = phdrs.get(2).unwrap_or_else(|| {
            println!("Error: .data not found in ELF file");
            process::exit(1)
        });

        let bss_segment = match phdrs.get(3) {
            Some(s) => {
                if s.progtype == PT_LOAD {
                    Some(*s)
                } else {
                    None
                }
            }
            None => None,
        };

        let mut build_id = None;
        let mut dynamic_section = None;
        let mut dynstr_section = None;
        let mut dynsym_section = None;
        let mut eh_frame_hdr_section = None;

        for section in sections {
            if section.shdr.shtype == SHT_NOTE {
                let mut data = Cursor::new(section.data.clone());
                // Ignore the two first offset of nhdr32
                data.seek(SeekFrom::Start(0x8)).unwrap();
                let n_type = data.read_u32::<LittleEndian>().unwrap();

                // BUILD_ID
                if n_type == 0x3 {
                    build_id = Some(data.into_inner());
                }
            }
            match &*section.shdr.name {
                ".dynamic" => dynamic_section = Some(section.shdr.clone()),
                ".dynstr" => dynstr_section = Some(section.shdr.clone()),
                ".dynsym" => dynsym_section = Some(section.shdr.clone()),
                ".eh_frame_hdr" => eh_frame_hdr_section = Some(section.shdr.clone()),
                _ => (),
            }
        }

        Ok(NxoFile {
            file,
            machine: elf_file.ehdr.machine,
            text_segment: *text_segment,
            rodata_segment: *rodata_segment,
            data_segment: *data_segment,
            bss_segment,
            build_id,
            dynamic_section,
            dynstr_section,
            dynsym_section,
            eh_frame_hdr_section,
        })
    }

    pub fn write_nro<T>(
        &mut self,
        output_writter: &mut T,
        romfs: Option<RomFs>,
        icon: Option<&str>,
        nacp: Option<NacpFile>,
    ) -> std::io::Result<()>
    where
        T: Write,
    {
        let text_segment = &self.text_segment;
        let rodata_segment = &self.rodata_segment;
        let data_segment = &self.data_segment;

        // Get segments data
        let mut code = utils::get_segment_data(&mut self.file, text_segment)?;
        let mut rodata = utils::get_segment_data(&mut self.file, rodata_segment)?;
        let mut data = utils::get_segment_data(&mut self.file, data_segment)?;

        // First correctly align to be conform to the NRO standard
        utils::add_padding(&mut code, 0xFFF);
        utils::add_padding(&mut rodata, 0xFFF);
        utils::add_padding(&mut data, 0xFFF);

        // Finally fix possible misalign of  vaddr because NRO only have one base
        pad_segment(&mut code, 0, rodata_segment);
        pad_segment(&mut rodata, code.len(), data_segment);

        if let Some(segment) = self.bss_segment {
            pad_segment(&mut data, code.len() + rodata.len(), &segment);
        }

        let total_len: u32 = (code.len() + rodata.len() + data.len()) as u32;

        // Write the first branching and mod0 offset
        output_writter.write_all(&code[..0x10])?;

        // NRO magic
        output_writter.write_all(b"NRO0")?;
        // Version
        output_writter.write_u32::<LittleEndian>(0)?;
        // Total size
        output_writter.write_u32::<LittleEndian>(total_len)?;
        // Flags
        output_writter.write_u32::<LittleEndian>(0)?;

        // Segment Header (3 entries)
        let mut file_offset = 0;

        // .text segment
        let code_size = code.len() as u32;
        output_writter.write_u32::<LittleEndian>(file_offset)?;
        output_writter.write_u32::<LittleEndian>(code_size)?;
        file_offset += code_size;

        // .rodata segment
        let rodata_offset = file_offset;
        let rodata_size = rodata.len() as u32;
        output_writter.write_u32::<LittleEndian>(file_offset)?;
        output_writter.write_u32::<LittleEndian>(rodata_size)?;
        file_offset += rodata_size;

        // .data segment
        let data_offset = file_offset;
        let data_size = data.len() as u32;
        output_writter.write_u32::<LittleEndian>(file_offset)?;
        output_writter.write_u32::<LittleEndian>(data_size)?;
        file_offset += data_size;

        // BSS size
        let (bss_start, bss_size) = match self.bss_segment {
            Some(segment) => {
                if segment.vaddr != u64::from(file_offset) {
                    println!(
                    "Warning: possible misalign bss\n.bss addr: 0x{:x}\nexpected offset: 0x{:x}",
                    segment.vaddr, file_offset);
                }
                output_writter
                    .write_u32::<LittleEndian>(((segment.memsz + 0xFFF) & !0xFFF) as u32)?;
                (
                    segment.vaddr as u32,
                    ((segment.memsz + 0xFFF) & !0xFFF) as u32,
                )
            }
            _ => {
                // in this case the bss is missing or is embedeed in .data. libnx does that, let's support it
                let data_segment_size = (data_segment.filesz + 0xFFF) & !0xFFF;
                let bss_size = if data_segment.memsz > data_segment_size {
                    (((data_segment.memsz - data_segment_size) + 0xFFF) & !0xFFF) as u32
                } else {
                    0
                };
                output_writter.write_u32::<LittleEndian>(bss_size)?;
                (
                    data_segment.vaddr as u32 + data_segment.memsz as u32,
                    bss_size,
                )
            }
        };

        // Reserved
        output_writter.write_u32::<LittleEndian>(0)?;

        write_build_id(&self.build_id, output_writter, &code, &rodata, &data)?;

        // TODO: DSO Module Offset (unused)
        output_writter.write_u32::<LittleEndian>(0)?;
        // Reserved (unused)
        output_writter.write_u32::<LittleEndian>(0)?;

        // TODO: apiInfo
        output_writter.write_u64::<LittleEndian>(0)?;

        // .dynstr section info
        output_writter.write_u32::<LittleEndian>(
            self.dynstr_section
                .as_ref()
                .map(|v| u32::try_from(v.addr).unwrap())
                .unwrap_or(0),
        )?;
        output_writter.write_u32::<LittleEndian>(
            self.dynstr_section
                .as_ref()
                .map(|v| u32::try_from(v.size).unwrap())
                .unwrap_or(0),
        )?;

        // .dynsym section info
        output_writter.write_u32::<LittleEndian>(
            self.dynsym_section
                .as_ref()
                .map(|v| u32::try_from(v.addr).unwrap())
                .unwrap_or(0),
        )?;
        output_writter.write_u32::<LittleEndian>(
            self.dynsym_section
                .as_ref()
                .map(|v| u32::try_from(v.size).unwrap())
                .unwrap_or(0),
        )?;

        let module_offset = u32::from_le_bytes(code[4..8].try_into().unwrap()) as usize;
        if module_offset != 0
            && !((0x80..code_size).contains(&(module_offset as u32))
                || (rodata_offset..data_offset).contains(&(module_offset as u32))
                || (data_offset..file_offset).contains(&(module_offset as u32)))
        {
            panic!("Invalid module offset {}", module_offset)
        }

        if (0x80..code_size).contains(&(module_offset as u32))
            && &code[module_offset..module_offset + 4] != b"MOD0"
        {
            output_writter.write_all(&code[0x80..module_offset])?;
            write_mod0(
                self,
                module_offset as u32,
                output_writter,
                bss_start,
                bss_size,
            )?;
            output_writter.write_all(&code[module_offset + 0x1C..])?;
        } else {
            output_writter.write_all(&code[0x80..])?;
        }

        if (rodata_offset..data_offset).contains(&(module_offset as u32))
            && &rodata
                [module_offset - rodata_offset as usize..module_offset - rodata_offset as usize + 4]
                != b"MOD0"
        {
            let rodata_module_offset = module_offset - rodata_offset as usize;
            output_writter.write_all(&rodata[..rodata_module_offset])?;
            write_mod0(
                self,
                module_offset as u32,
                output_writter,
                bss_start,
                bss_size,
            )?;
            output_writter.write_all(&rodata[rodata_module_offset + 0x1C..])?;
        } else {
            output_writter.write_all(&rodata)?;
        }

        if (data_offset..file_offset).contains(&(module_offset as u32))
            && &data[module_offset - data_offset as usize..module_offset - data_offset as usize + 4]
                != b"MOD0"
        {
            let data_module_offset = module_offset - data_offset as usize;
            output_writter.write_all(&data[..data_module_offset])?;
            write_mod0(
                self,
                module_offset as u32,
                output_writter,
                bss_start,
                bss_size,
            )?;
            output_writter.write_all(&data[data_module_offset + 0x1C..])?;
        } else {
            output_writter.write_all(&data)?;
        }

        // Early return if there's no need for an ASET segment.
        if let (None, None, None) = (&icon, &romfs, &nacp) {
            return Ok(());
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
            assert_eq!(
                io::copy(&mut File::open(icon)?, output_writter)?,
                icon_len,
                "Icon changed while building."
            );
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
        let text_segment = &self.text_segment;
        let rodata_segment = &self.rodata_segment;
        let data_segment = &self.data_segment;

        let mut code = utils::get_segment_data(&mut self.file, text_segment)?;
        let mut rodata = utils::get_segment_data(&mut self.file, rodata_segment)?;
        let mut data = utils::get_segment_data(&mut self.file, data_segment)?;

        // First correctly align to avoid possible compression issues
        utils::add_padding(&mut code, 0xFFF);
        utils::add_padding(&mut rodata, 0xFFF);
        utils::add_padding(&mut data, 0xFFF);

        // Because bss doesn't have it's own segment in NSO, we need to pad .data to the .bss vaddr
        if let Some(segment) = self.bss_segment {
            pad_segment(&mut data, data_segment.vaddr as usize, &segment);
        }

        // NSO magic
        output_writter.write_all(b"NSO0")?;
        // Version
        output_writter.write_u32::<LittleEndian>(0)?;
        // Reserved
        output_writter.write_u32::<LittleEndian>(0)?;

        // Flags, set compression + sum check
        output_writter.write_u32::<LittleEndian>(0x3F)?;

        // Segment Header (3 entries)
        let mut file_offset = 0x100;

        // .text segment
        let code_size = code.len() as u32;
        let compressed_code = utils::compress_lz4(&code)?;
        let compressed_code_size = compressed_code.len() as u32;
        output_writter.write_u32::<LittleEndian>(file_offset as u32)?;
        output_writter.write_u32::<LittleEndian>(text_segment.vaddr as u32)?;
        output_writter.write_u32::<LittleEndian>(code_size as u32)?;

        // TODO: Module Name Offset
        output_writter.write_u32::<LittleEndian>(0)?;

        file_offset += compressed_code_size;

        // .rodata segment
        let rodata_size = rodata.len() as u32;
        let compressed_rodata = utils::compress_lz4(&rodata)?;
        let compressed_rodata_size = compressed_rodata.len() as u32;
        output_writter.write_u32::<LittleEndian>(file_offset as u32)?;
        output_writter.write_u32::<LittleEndian>(rodata_segment.vaddr as u32)?;
        output_writter.write_u32::<LittleEndian>(rodata_size as u32)?;

        // TODO: Module Name Size
        output_writter.write_u32::<LittleEndian>(0)?;

        file_offset += compressed_rodata_size;

        // .data segment
        let data_size = data.len() as u32;
        let compressed_data = utils::compress_lz4(&data)?;
        let compressed_data_size = compressed_data.len() as u32;
        let uncompressed_data_size = data.len() as u64;
        output_writter.write_u32::<LittleEndian>(file_offset as u32)?;
        output_writter.write_u32::<LittleEndian>(data_segment.vaddr as u32)?;
        output_writter.write_u32::<LittleEndian>(data_size as u32)?;

        // BSS size
        match self.bss_segment {
            Some(segment) => {
                let memory_offset = data_segment.vaddr + uncompressed_data_size;
                if segment.vaddr != memory_offset {
                    println!(
                    "Warning: possible misalign bss\n.bss addr: 0x{:x}\nexpected offset: 0x{:x}",
                    segment.vaddr, memory_offset);
                }
                // (bss_segment['p_memsz'] + 0xFFF) & ~0xFFF
                output_writter
                    .write_u32::<LittleEndian>(((segment.memsz + 0xFFF) & !0xFFF) as u32)?;
            }
            _ => {
                // in this case the bss is missing or is embedeed in .data. libnx does that, let's support it
                output_writter
                    .write_u32::<LittleEndian>((data_segment.memsz - data_segment.filesz) as u32)?;
            }
        }

        write_build_id(&self.build_id, output_writter, &code, &rodata, &data)?;

        // Compressed size
        output_writter.write_u32::<LittleEndian>(compressed_code_size)?;
        output_writter.write_u32::<LittleEndian>(compressed_rodata_size)?;
        output_writter.write_u32::<LittleEndian>(compressed_data_size)?;

        // Reserved (0x1C)
        output_writter.write_u32::<LittleEndian>(0)?;
        output_writter.write_u64::<LittleEndian>(0)?;
        output_writter.write_u64::<LittleEndian>(0)?;
        output_writter.write_u64::<LittleEndian>(0)?;

        // TODO: SegmentHeaderRelative for .api_info
        output_writter.write_u64::<LittleEndian>(0)?;
        // SegmentHeaderRelative for .dynstr
        output_writter.write_u32::<LittleEndian>(
            self.dynstr_section
                .as_ref()
                .map(|v| u32::try_from(v.addr).unwrap())
                .unwrap_or(0),
        )?;
        output_writter.write_u32::<LittleEndian>(
            self.dynstr_section
                .as_ref()
                .map(|v| u32::try_from(v.size).unwrap())
                .unwrap_or(0),
        )?;
        // SegmentHeaderRelative for .dynsym
        output_writter.write_u32::<LittleEndian>(
            self.dynsym_section
                .as_ref()
                .map(|v| u32::try_from(v.addr).unwrap())
                .unwrap_or(0),
        )?;
        output_writter.write_u32::<LittleEndian>(
            self.dynsym_section
                .as_ref()
                .map(|v| u32::try_from(v.size).unwrap())
                .unwrap_or(0),
        )?;

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
        let mut name: Vec<u8> = npdm.name.clone().into();
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
            output_writer.write_u8(0b0011_1111)?;
        } else if self.machine == EM_ARM {
            // Compression enable, UseSystemPoolPartition
            output_writer.write_u8(0b0010_0111)?;
        } else {
            unimplemented!("Unknown machine type");
        }

        let mut segment_data = utils::get_segment_data(&mut self.file, &self.text_segment)?;
        let text_data = utils::compress_blz(&mut segment_data).unwrap();
        let mut segment_data = utils::get_segment_data(&mut self.file, &self.rodata_segment)?;
        let rodata_data = utils::compress_blz(&mut segment_data).unwrap();
        let mut segment_data = utils::get_segment_data(&mut self.file, &self.data_segment)?;
        let data_data = utils::compress_blz(&mut segment_data).unwrap();

        write_kip_segment_header(output_writer, &self.text_segment, 0, text_data.len() as u32)?;
        write_kip_segment_header(
            output_writer,
            &self.rodata_segment,
            u32::try_from(npdm.main_thread_stack_size.0)
                .expect("Exected main_thread_stack_size to be an u32"),
            rodata_data.len() as u32,
        )?;
        write_kip_segment_header(output_writer, &self.data_segment, 0, data_data.len() as u32)?;

        if let Some(segment) = self.bss_segment {
            output_writer.write_u32::<LittleEndian>(
                u32::try_from(segment.vaddr).expect("BSS vaddr too big"),
            )?;
            output_writer.write_u32::<LittleEndian>(
                u32::try_from(segment.memsz).expect("BSS memsize too big"),
            )?;
        } else {
            // in this case the bss is missing or is embedeed in .data. libnx does that, let's support it
            let data_segment_size = (self.data_segment.filesz + 0xFFF) & !0xFFF;
            let bss_size = if self.data_segment.memsz > data_segment_size {
                (((self.data_segment.memsz - data_segment_size) + 0xFFF) & !0xFFF) as u32
            } else {
                0
            };
            output_writer.write_u32::<LittleEndian>(
                u32::try_from(self.data_segment.vaddr + data_segment_size).unwrap(),
            )?;
            output_writer.write_u32::<LittleEndian>(bss_size)?;
        }
        output_writer.write_u32::<LittleEndian>(0)?;
        output_writer.write_u32::<LittleEndian>(0)?;

        // Empty Sections:
        for _ in 4..6 {
            output_writer.write_u32::<LittleEndian>(0)?;
            output_writer.write_u32::<LittleEndian>(0)?;
            output_writer.write_u32::<LittleEndian>(0)?;
            output_writer.write_u32::<LittleEndian>(0)?;
        }

        // Kernel caps:
        let caps = npdm
            .kernel_capabilities
            .iter()
            .flat_map(|v| v.encode())
            .collect::<Vec<u32>>();
        assert!(
            caps.len() < 0x20,
            "kernel_capabilities should have less than 0x20 entries!"
        );

        unsafe {
            // Safety: This is safe. I'm just casting a slice of u32 to a slice of u8
            // for fuck's sake.
            output_writer.write_all(std::slice::from_raw_parts(
                caps.as_ptr() as *const u8,
                caps.len() * 4,
            ))?;
        }

        output_writer.write_all(&vec![0xFF; (0x20 - caps.len()) * 4])?;

        // Section data
        output_writer.write_all(&text_data)?;
        output_writer.write_all(&rodata_data)?;
        output_writer.write_all(&data_data)?;

        Ok(())
    }
}

pub fn write_kip_segment_header<T>(
    output_writer: &mut T,
    segment: &ProgramHeader,
    attributes: u32,
    compressed_size: u32,
) -> std::io::Result<()>
where
    T: Write,
{
    output_writer
        .write_u32::<LittleEndian>(u32::try_from(segment.vaddr).expect("vaddr too big"))?;
    output_writer
        .write_u32::<LittleEndian>(u32::try_from(segment.filesz).expect("memsz too big"))?;
    output_writer.write_u32::<LittleEndian>(compressed_size)?;
    output_writer.write_u32::<LittleEndian>(attributes)?;

    Ok(())
}
