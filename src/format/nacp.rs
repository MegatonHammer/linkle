use crate::format::utils::{HexOrNum, check_string_or_truncate};
use byteorder::{LittleEndian, WriteBytesExt};
use serde_derive::{Deserialize, Serialize};
use std::fs::File;
use std::io::Write;

mod fmt;
use fmt::*;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ApplicationTitle {
    pub name: String,
    pub author: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ApplicationTitles {
    #[serde(alias = "en-US", alias = "AmericanEnglish")]
    pub en_us: Option<ApplicationTitle>,

    #[serde(alias = "en-GB", alias = "BritishEnglish")]
    pub en_gb: Option<ApplicationTitle>,

    #[serde(alias = "Japanese")]
    pub ja: Option<ApplicationTitle>,

    #[serde(alias = "French")]
    pub fr: Option<ApplicationTitle>,

    #[serde(alias = "German")]
    pub de: Option<ApplicationTitle>,

    #[serde(alias = "es-419", alias = "LatinAmericanSpanish")]
    pub es_419: Option<ApplicationTitle>,

    #[serde(alias = "Spanish")]
    pub es: Option<ApplicationTitle>,

    #[serde(alias = "Italian")]
    pub it: Option<ApplicationTitle>,

    #[serde(alias = "Dutch")]
    pub nl: Option<ApplicationTitle>,

    #[serde(alias = "fr-CA", alias = "CanadianFrench")]
    pub fr_ca: Option<ApplicationTitle>,

    #[serde(alias = "Portuguese")]
    pub pt: Option<ApplicationTitle>,

    #[serde(alias = "Russian")]
    pub ru: Option<ApplicationTitle>,

    #[serde(alias = "Korean")]
    pub ko: Option<ApplicationTitle>,

    #[serde(alias = "zh-TW", alias = "TraditionalChinese")]
    pub zh_tw: Option<ApplicationTitle>, // 4.0.0+

    #[serde(alias = "zh-CN", alias = "SimplifiedChinese")]
    pub zh_cn: Option<ApplicationTitle>, // 4.0.0+

    #[serde(alias = "pt-BR", alias = "BrazilianPortuguese")]
    pub pt_br: Option<ApplicationTitle>, // 10.0.0+
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct Nacp {
    #[serde(alias = "name")]
    pub default_name: Option<String>,
    #[serde(alias = "author")]
    pub default_author: Option<String>,
    pub version: String,
    #[serde(alias = "title_id")]
    pub application_id: Option<HexOrNum>,
    pub presence_group_id: Option<HexOrNum>,
    #[serde(alias = "dlc_base_title_id")]
    pub add_on_content_base_id: Option<HexOrNum>,
    #[serde(alias = "lang")]
    pub titles: Option<ApplicationTitles>,
    pub isbn: Option<String>,
    pub startup_user_account: Option<StartupUserAccount>,
    pub attribute: Option<Attribute>,
    pub screenshot: Option<Screenshot>,
    pub video_capture: Option<VideoCapture>,
    pub logo_type: Option<LogoType>,
    pub logo_handling: Option<LogoHandling>,
    pub crash_report: Option<CrashReport>,
    pub bcat_passphrase: Option<String>,
    pub program_index: Option<HexOrNum>,
    pub save_data_owner_id: Option<HexOrNum>,
    // TODO: support more NACP fields
}

#[allow(clippy::len_without_is_empty)]
impl Nacp {
    pub fn from_json(input: &str) -> std::io::Result<Self> {
        let file = File::open(input)?;
        match serde_json::from_reader(file) {
            Ok(res) => Ok(res),
            Err(error) => Err(std::io::Error::from(error)),
        }
    }

    fn write_lang_entry<T>(
        &self,
        out_writer: &mut T,
        lang_entry: &ApplicationTitle,
    ) -> std::io::Result<()>
    where
        T: Write,
    {
        let name = &lang_entry.name;
        let name_padding = 0x200 - name.len();
        out_writer.write_all(name.as_bytes())?;
        out_writer.write_all(&vec![0; name_padding])?;

        let author = &lang_entry.author;
        let author_padding = 0x100 - author.len();
        out_writer.write_all(author.as_bytes())?;
        out_writer.write_all(&vec![0; author_padding])?;
        Ok(())
    }

    /// The size in bytes of this entry once serialized.
    pub fn len(&self) -> usize {
        0x4000
    }

    pub fn write<T>(&mut self, out_writer: &mut T) -> std::io::Result<()>
    where
        T: Write,
    {
        let mut def_name = self
            .default_name
            .clone()
            .unwrap_or_else(|| "Unknown application".to_string());
        let mut version = self.version.clone();
        let mut def_author = self
            .default_author
            .clone()
            .unwrap_or_else(|| "Unknown author".to_string());

        // Truncate default names if needed
        check_string_or_truncate(&mut def_name, "default_name", 0x200);
        check_string_or_truncate(&mut def_author, "default_author", 0x100);

        let application_id = self.application_id.map(|h| h.0).unwrap_or(0);
        let presence_group_id = self.presence_group_id.map(|h| h.0).unwrap_or(application_id);
        let add_on_content_base_id = self.add_on_content_base_id.map(|h| h.0).unwrap_or(application_id + 0x1000);
        let save_data_owner_id = self.save_data_owner_id.map(|h| h.0).unwrap_or(application_id);

        // Fallback default entry for each entry that wasn't provided
        let default_title = ApplicationTitle { name: def_name, author: def_author };
        match &self.titles {
            None => {
                for _ in 0..16 {
                    self.write_lang_entry(out_writer, &default_title)?;
                }
            }
            Some(app_titles_ref) => {
                // Write languages in order
                self.write_lang_entry(
                    out_writer,
                    &app_titles_ref
                        .en_us
                        .clone()
                        .unwrap_or_else(|| default_title.clone()),
                )?;
                self.write_lang_entry(
                    out_writer,
                    &app_titles_ref
                        .en_gb
                        .clone()
                        .unwrap_or_else(|| default_title.clone()),
                )?;
                self.write_lang_entry(
                    out_writer,
                    &app_titles_ref
                        .ja
                        .clone()
                        .unwrap_or_else(|| default_title.clone()),
                )?;
                self.write_lang_entry(
                    out_writer,
                    &app_titles_ref
                        .fr
                        .clone()
                        .unwrap_or_else(|| default_title.clone()),
                )?;
                self.write_lang_entry(
                    out_writer,
                    &app_titles_ref
                        .de
                        .clone()
                        .unwrap_or_else(|| default_title.clone()),
                )?;
                self.write_lang_entry(
                    out_writer,
                    &app_titles_ref
                        .es_419
                        .clone()
                        .unwrap_or_else(|| default_title.clone()),
                )?;
                self.write_lang_entry(
                    out_writer,
                    &app_titles_ref
                        .es
                        .clone()
                        .unwrap_or_else(|| default_title.clone()),
                )?;
                self.write_lang_entry(
                    out_writer,
                    &app_titles_ref
                        .it
                        .clone()
                        .unwrap_or_else(|| default_title.clone()),
                )?;
                self.write_lang_entry(
                    out_writer,
                    &app_titles_ref
                        .nl
                        .clone()
                        .unwrap_or_else(|| default_title.clone()),
                )?;
                self.write_lang_entry(
                    out_writer,
                    &app_titles_ref
                        .fr_ca
                        .clone()
                        .unwrap_or_else(|| default_title.clone()),
                )?;
                self.write_lang_entry(
                    out_writer,
                    &app_titles_ref
                        .pt
                        .clone()
                        .unwrap_or_else(|| default_title.clone()),
                )?;
                self.write_lang_entry(
                    out_writer,
                    &app_titles_ref
                        .ru
                        .clone()
                        .unwrap_or_else(|| default_title.clone()),
                )?;
                self.write_lang_entry(
                    out_writer,
                    &app_titles_ref
                        .ko
                        .clone()
                        .unwrap_or_else(|| default_title.clone()),
                )?;
                self.write_lang_entry(
                    out_writer,
                    &app_titles_ref
                        .zh_tw
                        .clone()
                        .unwrap_or_else(|| default_title.clone()),
                )?;
                self.write_lang_entry(
                    out_writer,
                    &app_titles_ref
                        .zh_cn
                        .clone()
                        .unwrap_or_else(|| default_title.clone()),
                )?;
                self.write_lang_entry(
                    out_writer,
                    &app_titles_ref
                        .pt_br
                        .clone()
                        .unwrap_or_else(|| default_title.clone()),
                )?;
            }
        }

        // 0x3000: u8 isbn[0x25]
        let isbn_max_len = 0x25usize;
        let mut isbn_pad = isbn_max_len;
        if let Some(mut isbn) = self.isbn.as_mut() {
            check_string_or_truncate(&mut isbn, "isbn", isbn_max_len);
            isbn_pad = isbn_max_len - version.len();
            out_writer.write_all(version.as_bytes())?;
        }
        out_writer.write_all(&vec![0; isbn_pad])?;

        // 0x3025: u8 startup_user_account
        let startup_user_account = self.startup_user_account.unwrap_or(StartupUserAccount::None);
        out_writer.write_u8(startup_user_account as u8)?;

        // 0x3026: u8 user_account_switch_lock?
        out_writer.write_u8(0)?;

        // 0x3027: u8 add_on_content_registration_type?
        out_writer.write_u8(0)?;

        // 0x3028: u32 attribute
        let attribute = self.attribute.unwrap_or(Attribute::None);
        out_writer.write_u32::<LittleEndian>(attribute as u32)?;

        // 0x302C: u32 supported_language?
        out_writer.write_u32::<LittleEndian>(0)?;

        // 0x3030: u32 parental_control?
        out_writer.write_u32::<LittleEndian>(0)?;

        // 0x3034: u8 screenshot
        let screenshot = self.screenshot.unwrap_or(Screenshot::Allow);
        out_writer.write_u8(screenshot as u8)?;

        // 0x3035: u8 video_capture
        let video_capture = self.video_capture.unwrap_or(VideoCapture::Disabled);
        out_writer.write_u8(video_capture as u8)?;

        // 0x3036: u8 data_loss_confirmation?
        out_writer.write_u8(0)?;

        // 0x3037: u8 play_log_policy?
        out_writer.write_u8(0)?;

        // 0x3038: u64 presence_group_id
        out_writer.write_u64::<LittleEndian>(presence_group_id)?;

        // 0x3040: u8 rating_age[0x20]?
        let mut unk_rating_age = Vec::new();
        unk_rating_age.resize(0x20, 0xFF);
        out_writer.write_all(&unk_rating_age)?;

        // 0x3060: u8 display_version[0x10]
        let display_version_max_len = 0x10usize;
        check_string_or_truncate(&mut version, "version", display_version_max_len);
        let display_version_pad = display_version_max_len - version.len();
        out_writer.write_all(version.as_bytes())?;
        out_writer.write_all(&vec![0; display_version_pad])?;

        // 0x3070: u64 add_on_content_base_id
        out_writer.write_u64::<LittleEndian>(add_on_content_base_id)?;

        // 0x3078: save_data_owner_id
        out_writer.write_u64::<LittleEndian>(save_data_owner_id)?;

        // 0x3080: u64 user_account_save_data_size?
        out_writer.write_u64::<LittleEndian>(0)?;

        // 0x3088: u64 user_account_save_data_journal_size?
        out_writer.write_u64::<LittleEndian>(0)?;

        // 0x3090: u64 device_save_data_size?
        out_writer.write_u64::<LittleEndian>(0)?;

        // 0x3098: u64 device_save_data_journal_size?
        out_writer.write_u64::<LittleEndian>(0)?;

        // 0x30A0: u64 bcat_delivery_cache_storage_size?
        out_writer.write_u64::<LittleEndian>(0)?;

        // 0x30A8: u64 application_error_code_category?
        out_writer.write_u64::<LittleEndian>(0)?;

        // 0x30B0: u64 local_communication_id[8]
        for _ in 0..8 {
            out_writer.write_u64::<LittleEndian>(0)?;
        }

        // 0x30F0: u8 logo_type
        let logo_type = self.logo_type.unwrap_or(LogoType::LicensedByNintendo);
        out_writer.write_u8(logo_type as u8)?;

        // 0x30F1: u8 logo_handling
        let logo_handling = self.logo_handling.unwrap_or(LogoHandling::Auto);
        out_writer.write_u8(logo_handling as u8)?;

        // 0x30F2: u8 runtime_add_on_content_install?
        out_writer.write_u8(0)?;

        // 0x30F3: u8 runtime_parameter_delivery?
        out_writer.write_u8(0)?;

        // 0x30F4: u8 reserved[2]
        out_writer.write_all(&vec![0; 2])?;

        // 0x30F6: u8 crash_report
        let crash_report = self.crash_report.unwrap_or(CrashReport::Allow);
        out_writer.write_u8(crash_report as u8)?;

        // 0x30F7: u8 hdcp?
        out_writer.write_u8(0)?;

        // 0x30F8: u64 seed_for_pseudo_device_id?
        out_writer.write_u64::<LittleEndian>(0)?;

        // 0x3100: u8 bcat_passphrase[0x41]
        let bcat_passphrase_max_len = 0x41usize;
        let mut bcat_passphrase_pad = bcat_passphrase_max_len;
        if let Some(mut bcat_passphrase) = self.bcat_passphrase.as_mut() {
            check_string_or_truncate(&mut bcat_passphrase, "bcat_passphrase", bcat_passphrase_max_len);
            bcat_passphrase_pad = bcat_passphrase_max_len - version.len();
            out_writer.write_all(bcat_passphrase.as_bytes())?;
        }
        out_writer.write_all(&vec![0; bcat_passphrase_pad])?;

        // 0x3141: u8 startup_user_account_option?
        out_writer.write_u8(0)?;

        // 0x3142: u8 reserved_for_user_account_save_data_operation[6]?
        out_writer.write_all(&vec![0; 6])?;

        // 0x3148: u64 user_account_save_data_size_max?
        out_writer.write_u64::<LittleEndian>(0)?;

        // 0x3150: u64 user_account_save_data_journal_size_max?
        out_writer.write_u64::<LittleEndian>(0)?;

        // 0x3158: u64 device_save_data_size_max?
        out_writer.write_u64::<LittleEndian>(0)?;

        // 0x3160: u64 device_save_data_journal_size_max?
        out_writer.write_u64::<LittleEndian>(0)?;

        // 0x3168: u64 temporary_storage_size?
        out_writer.write_u64::<LittleEndian>(0)?;

        // 0x3170: u64 cache_storage_size?
        out_writer.write_u64::<LittleEndian>(0)?;

        // 0x3178: u64 cache_storage_journal_size?
        out_writer.write_u64::<LittleEndian>(0)?;

        // 0x3180: u64 cache_storage_data_and_journal_size_max?
        out_writer.write_u64::<LittleEndian>(0)?;

        // 0x3188: u16 cache_storage_index_max?
        out_writer.write_u16::<LittleEndian>(0)?;

        // 0x318A: u8 reserved
        out_writer.write_u8(0)?;

        // 0x318B: u8 runtime_upgrade?
        out_writer.write_u8(0)?;

        // 0x318C: u32 supporting_limited_licenses?
        out_writer.write_u32::<LittleEndian>(0)?;

        // 0x3190: u64 play_log_queryable_application_id[16]?
        for _ in 0..16 {
            out_writer.write_u64::<LittleEndian>(0)?;
        }

        // 0x3210: u8 play_log_query_capability?
        out_writer.write_u8(0)?;

        // 0x3211: u8 repair?
        out_writer.write_u8(0)?;

        // 0x3212: u8 program_index
        let program_index = self.program_index.map(|h| h.0 as u8).unwrap_or(0);
        out_writer.write_u8(program_index)?;

        // 0x3213: u8 required_network_service_license_on_launch?
        out_writer.write_u8(0)?;

        // 0x3214: u8 reserved[4]
        out_writer.write_all(&vec![0; 4])?;

        // 0x3218: u8 neighbor_detection_client_configuration[0x198]?
        out_writer.write_all(&vec![0; 0x198])?;

        // 0x33B0: u8 jit_configuration[0x10]?
        out_writer.write_all(&vec![0; 0x10])?;

        // 0x33C0: u16 required_add_on_contents_set_binary_descriptor[32]?
        for _ in 0..32 {
            out_writer.write_u16::<LittleEndian>(0)?;
        }

        // 0x3400: u8 play_report_permission?
        out_writer.write_u8(0)?;

        // 0x3401: u8 crash_screenshot_for_prod?
        out_writer.write_u8(0)?;

        // 0x3402: u8 crash_screenshot_for_dev?
        out_writer.write_u8(0)?;

        // 0x3403: u8 contents_availability_transition_policy?
        out_writer.write_u8(0)?;

        // 0x3404: u8 reserved[4]
        out_writer.write_all(&vec![0; 4])?;

        // 0x3408: u64 accessible_launch_required_version[8]?
        for _ in 0..8 {
            out_writer.write_u64::<LittleEndian>(0)?;
        }

        // 0x3448: u8 reserved[0xBB8]
        out_writer.write_all(&vec![0; 0xBB8])?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn generated_nacp_has_expected_size() {
        let mut gen_nacp_buf = Vec::new();
        Nacp::default().write(&mut gen_nacp_buf).unwrap();
        assert_eq!(gen_nacp_buf.len(), 0x4000, "NACP length is wrong");
    }
}
