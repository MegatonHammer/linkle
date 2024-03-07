use std::fs::File;
use std::io::{Seek, SeekFrom, Read};
use byteorder::{LittleEndian, ReadBytesExt};

pub struct Cnmt {
	title_id: u64,
	title_version: u32,
	title_type: TitleType,
	table_offset: u16,
	content_entry_count: u16,
	meta_entry_count: u16,
	title_header: Option<TitleHeader> /* TODO: figure out a better way to do this with the different title types. */,
	content_entries: Vec<ContentEntry>,
	meta_entries: Vec<MetaEntry>
}

pub enum TitleType {
	SystemProgram,
	SystemData,
	SystemUpdate,
	BootImagePackage,
	BootImagePackageSafe,
	Application,
	Patch,
	AddOnContent,
	Delta,
	Unknown
}

pub struct TitleHeader {
	title_id: u64,
	minimum_version: u32
}

pub struct ContentEntry {
	hash: [u8; 32],
	nca_id: [u8; 16],
	size: u64,
	content_type: ContentType
}

pub enum ContentType {
	Meta,
	Program,
	Data,
	Control,
	HtmlDocument,
	LegalInformation,
	DeltaFragment,
	Unknown
}

pub struct MetaEntry {
	title_id: u64,
	title_version: u32,
	title_type: TitleType
}

impl Cnmt {
	pub fn from_file(mut file: &File) -> std::io::Result<Cnmt> {
		let title_id = file.read_u64::<LittleEndian>()?;
		
		let title_version = file.read_u32::<LittleEndian>()?;

		let title_type = TitleType::from_u8(&file.read_u8()?);

		file.read_u8()?;

		let table_offset = file.read_u16::<LittleEndian>()?;

		let content_entry_count = file.read_u16::<LittleEndian>()?;

		let meta_entry_count = file.read_u16::<LittleEndian>()?;

		file.seek(SeekFrom::Current(12))?;

		let title_header = match title_type {
			TitleType::Application | TitleType::Patch | TitleType::AddOnContent =>
				Some(TitleHeader {
					title_id: file.read_u64::<LittleEndian>()?,
					minimum_version: file.read_u32::<LittleEndian>()?
				}),
			_ => None
		};

		file.seek(SeekFrom::Start((0x20 + table_offset) as u64))?;

		let mut content_entries = Vec::new();

		for _ in 0..content_entry_count {
			let mut hash = [0; 32];

			file.read_exact(&mut hash)?;

			let mut nca_id = [0; 16];

			file.read_exact(&mut nca_id)?;

			content_entries.push(ContentEntry {
				hash,
				nca_id,
				size: file.read_u48::<LittleEndian>()?,
				content_type: ContentType::from_u8(&file.read_u8()?)
			});

			file.read_u8()?;
		}

		let mut meta_entries = Vec::new();

		for _ in 0..meta_entry_count {
			meta_entries.push(MetaEntry {
				title_id: file.read_u64::<LittleEndian>()?,
				title_version: file.read_u32::<LittleEndian>()?,
				title_type: TitleType::from_u8(&file.read_u8()?)
			});

			file.read_u24::<LittleEndian>()?;
		}

		Ok(Cnmt {
			title_id,
			title_version,
			title_type,
			table_offset,
			content_entry_count,
			meta_entry_count,
			title_header,
			content_entries,
			meta_entries
		})
	}
}

impl TitleType {
	fn from_u8(title_type: &u8) -> Self {
		match title_type {
			0x01 => TitleType::SystemProgram,
			0x02 => TitleType::SystemData,
			0x03 => TitleType::SystemUpdate,
			0x04 => TitleType::BootImagePackage,
			0x05 => TitleType::BootImagePackageSafe,
			0x80 => TitleType::Application,
			0x81 => TitleType::Patch,
			0x82 => TitleType::AddOnContent,
			0x83 => TitleType::Delta,
			_ => TitleType::Unknown
		}
	}
}

impl ContentType {
	fn from_u8(content_type: &u8) -> Self {
		match content_type {
			00 => ContentType::Meta,
			01 => ContentType::Program,
			02 => ContentType::Data,
			03 => ContentType::Control,
			04 => ContentType::HtmlDocument,
			05 => ContentType::LegalInformation,
			06 => ContentType::DeltaFragment,
			_ => ContentType::Unknown
		}
	}
}
