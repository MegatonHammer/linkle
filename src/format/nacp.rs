use byteorder::{LittleEndian, WriteBytesExt};
use crate::format::utils;
use std;
use std::fs::File;
use std::io::Write;
use serde_derive::{Serialize, Deserialize};
use serde_json;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NacpLangEntry {
    pub name: String,
    pub author: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct NacpLangEntries {
    #[serde(rename = "en-US")]
    pub en_us: Option<NacpLangEntry>,

    #[serde(rename = "en-GB")]
    pub en_gb: Option<NacpLangEntry>,

    pub ja: Option<NacpLangEntry>,
    pub fr: Option<NacpLangEntry>,
    pub de: Option<NacpLangEntry>,

    #[serde(rename = "es-419")]
    pub es_419: Option<NacpLangEntry>,

    pub es: Option<NacpLangEntry>,
    pub it: Option<NacpLangEntry>,
    pub nl: Option<NacpLangEntry>,

    #[serde(rename = "fr-CA")]
    pub fr_ca: Option<NacpLangEntry>,
    pub pt: Option<NacpLangEntry>,

    pub ru: Option<NacpLangEntry>,
    pub ko: Option<NacpLangEntry>,

    #[serde(rename = "zh-TW")]
    pub zh_tw: Option<NacpLangEntry>,

    #[serde(rename = "zh-CN")]
    pub zh_cn: Option<NacpLangEntry>,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct NacpFile {
    pub name: Option<String>,
    pub author: Option<String>,
    pub version: Option<String>,
    pub title_id: Option<String>,
    pub dlc_base_title_id: Option<String>,
    pub lang: Option<NacpLangEntries>,
}

impl NacpFile {
    pub fn from_file(input: &str) -> std::io::Result<Self> {
        let file = File::open(input)?;
        match serde_json::from_reader(file) {
            Ok(res) => Ok(res),
            Err(error) => Err(std::io::Error::from(error)),
        }
    }

    fn write_lang_entry<T>(
        &self,
        output_writter: &mut T,
        lang_entry: &NacpLangEntry,
    ) -> std::io::Result<()>
    where
        T: Write,
    {
        let name = &lang_entry.name;
        let name_padding = 0x200 - name.len();
        output_writter.write(name.as_bytes())?;
        output_writter.write(&vec![0; name_padding])?;

        let author = &lang_entry.author;
        let author_padding = 0x100 - author.len();
        output_writter.write(author.as_bytes())?;
        output_writter.write(&vec![0; author_padding])?;
        Ok(())
    }

    /// The size in bytes of this entry once serialized.
    pub fn len(&self) -> usize {
        0x4000
    }

    pub fn write<T>(&mut self, output_writter: &mut T) -> std::io::Result<()>
    where
        T: Write,
    {
        let mut name = self
            .name
            .clone()
            .unwrap_or("Unknown Application".to_string());
        let mut version = self.version.clone().unwrap_or("1.0.0".to_string());
        let mut author = self.author.clone().unwrap_or("Unknown Author".to_string());

        let title_id = match &self.title_id {
            None => 0,
            Some(title_string) => {
                u64::from_str_radix(title_string.as_str(), 16).expect("Invalid title_id provided!")
            }
        };

        let dlc_base_title_id = match &self.dlc_base_title_id {
            None => title_id + 0x1000,
            Some(title_string) => {
                u64::from_str_radix(title_string.as_str(), 16).expect("Invalid title_id provided!")
            }
        };

        let lang_entries = &self.lang;

        // Truncate names if needed
        utils::check_string_or_truncate(&mut name, "name", 0x200);
        utils::check_string_or_truncate(&mut version, "version", 0x10);
        utils::check_string_or_truncate(&mut author, "author", 0x100);

        // fallback entry if lang entry isn't defined
        let default_lang_entry = NacpLangEntry { name, author };
        match lang_entries {
            None => {
                for _ in 0..16 {
                    self.write_lang_entry(output_writter, &default_lang_entry)?;
                }
            }
            Some(data) => {
                let lang_entries = data.clone();

                // Write every langs in order
                self.write_lang_entry(
                    output_writter,
                    &lang_entries
                        .en_us
                        .clone()
                        .unwrap_or(default_lang_entry.clone()),
                )?;
                self.write_lang_entry(
                    output_writter,
                    &lang_entries
                        .en_gb
                        .clone()
                        .unwrap_or(default_lang_entry.clone()),
                )?;
                self.write_lang_entry(
                    output_writter,
                    &lang_entries
                        .ja
                        .clone()
                        .unwrap_or(default_lang_entry.clone()),
                )?;
                self.write_lang_entry(
                    output_writter,
                    &lang_entries
                        .fr
                        .clone()
                        .unwrap_or(default_lang_entry.clone()),
                )?;
                self.write_lang_entry(
                    output_writter,
                    &lang_entries
                        .de
                        .clone()
                        .unwrap_or(default_lang_entry.clone()),
                )?;
                self.write_lang_entry(
                    output_writter,
                    &lang_entries
                        .es_419
                        .clone()
                        .unwrap_or(default_lang_entry.clone()),
                )?;
                self.write_lang_entry(
                    output_writter,
                    &lang_entries
                        .es
                        .clone()
                        .unwrap_or(default_lang_entry.clone()),
                )?;
                self.write_lang_entry(
                    output_writter,
                    &lang_entries
                        .it
                        .clone()
                        .unwrap_or(default_lang_entry.clone()),
                )?;
                self.write_lang_entry(
                    output_writter,
                    &lang_entries
                        .nl
                        .clone()
                        .unwrap_or(default_lang_entry.clone()),
                )?;
                self.write_lang_entry(
                    output_writter,
                    &lang_entries
                        .fr_ca
                        .clone()
                        .unwrap_or(default_lang_entry.clone()),
                )?;
                self.write_lang_entry(
                    output_writter,
                    &lang_entries
                        .pt
                        .clone()
                        .unwrap_or(default_lang_entry.clone()),
                )?;
                self.write_lang_entry(
                    output_writter,
                    &lang_entries
                        .ru
                        .clone()
                        .unwrap_or(default_lang_entry.clone()),
                )?;
                self.write_lang_entry(
                    output_writter,
                    &lang_entries
                        .ko
                        .clone()
                        .unwrap_or(default_lang_entry.clone()),
                )?;
                self.write_lang_entry(
                    output_writter,
                    &lang_entries
                        .zh_tw
                        .clone()
                        .unwrap_or(default_lang_entry.clone()),
                )?;
                self.write_lang_entry(
                    output_writter,
                    &lang_entries
                        .zh_cn
                        .clone()
                        .unwrap_or(default_lang_entry.clone()),
                )?;
                // There are 16 entries. One is missing :eyes:
                self.write_lang_entry(output_writter, &default_lang_entry)?;
            }
        }

        // 0x3000 - 0x3038: Unknown
        output_writter.write(&[0; 0x38])?;

        output_writter.write_u64::<LittleEndian>(title_id)?;

        // Unknown 0x20 bytes
        let mut unknown = Vec::new();
        unknown.resize(0x20, 0xFF);
        output_writter.write(&unknown)?;

        // Version string part (probably UTF8)
        let version_padding = 0x10 - version.len();
        output_writter.write(version.as_bytes())?;
        output_writter.write(&vec![0; version_padding])?;

        output_writter.write_u64::<LittleEndian>(dlc_base_title_id)?;
        output_writter.write_u64::<LittleEndian>(title_id)?;

        //  0x3080 - 0x30B0: Unknown
        output_writter.write(&[0; 0x30])?;

        output_writter.write_u64::<LittleEndian>(title_id)?;

        // title id array (0x7 entries), only write the base, other entries seems to be for update titles
        output_writter.write_u64::<LittleEndian>(title_id)?;
        output_writter.write(&[0; 0x30])?;

        // 0x30F0 - 0x30F8: Unknown
        output_writter.write_u64::<LittleEndian>(0)?;
        output_writter.write_u64::<LittleEndian>(title_id)?;

        let mut end_of_file = Vec::new();
        end_of_file.resize(0xF00, 0);
        output_writter.write(&end_of_file)?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn nacp_is_4000_size() {
        let mut buf = Vec::new();
        NacpFile::default().write(&mut buf).unwrap();
        assert_eq!(buf.len(), 0x4000, "Nacp length is wrong");
    }
}
