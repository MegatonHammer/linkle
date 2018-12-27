extern crate structopt;

extern crate linkle;

use std::fs::{OpenOptions};
use std::path::{Path, PathBuf};
use std::process;
use structopt::StructOpt;
use linkle::error::ResultExt;

#[derive(StructOpt)]
#[structopt(name = "linkle", about = "The legendary hero")]
enum Opt {
    /// Create a NRO file from an ELF file.
    #[structopt(name = "nro")]
    Nro {
        /// Sets the input file to use.
        input_file: String,

        /// Sets the output file to use.
        output_file: String,

        /// Sets the icon to use when bundling into an NRO.
        #[structopt(long = "icon-path")]
        icon: Option<String>,

        /// Sets the directory to use as RomFs when bundling into an NRO.
        #[structopt(long = "romfs-path")]
        romfs: Option<String>,

        /// Sets the NACP JSON to use when bundling into an NRO.
        #[structopt(long = "nacp-path")]
        nacp: Option<String>,
    },
    /// Create a NSO file from an ELF file.
    #[structopt(name = "nso")]
    Nso {
        /// Sets the input file to use.
        input_file: String,
        /// Sets the output file to use.
        output_file: String,
    },
    /// Create a PFS0 or NSP file from a directory.
    #[structopt(name = "pfs0"/*, raw(alias = "nsp")*/)]
    Pfs0 {
        /// Sets the input directory to use.
        input_directory: String,
        /// Sets the output file to use.
        output_file: String,
    },
    /// Create a NACP file from a JSON file.
    #[structopt(name = "nacp")]
    Nacp {
        /// Sets the input file to use.
        input_file: String,
        /// Sets the output file to use.
        output_file: String
    },
    /// Create a RomFS file from a directory.
    #[structopt(name = "romfs")]
    Romfs {
        /// Sets the input directory to use.
        #[structopt(parse(from_os_str))]
        input_directory: PathBuf,
        /// Sets the output file to use.
        #[structopt(parse(from_os_str))]
        output_file: PathBuf,
    },
}

fn create_nxo(format: &str, input_file: &str, output_file: &str, icon_file: Option<&str>, romfs_dir: Option<&str>, nacp_file: Option<&str>) -> Result<(), linkle::error::Error> {
    let romfs_dir = if let Some(romfs_path) = romfs_dir {
        Some(linkle::format::romfs::RomFs::from_directory(Path::new(&romfs_path))?)
    } else {
        None
    };
    let nacp_file = if let Some(nacp_path) = nacp_file {
        Some(linkle::format::nacp::NacpFile::from_file(&nacp_path).map_err(|err| (err, &nacp_path))?)
    } else {
        None
    };

    let mut nxo = linkle::format::nxo::NxoFile::from_elf(&input_file).map_err(|err| (err, &input_file))?;
    let mut option = OpenOptions::new();
    let output_option = option.write(true).create(true).truncate(true);
    match format {
        "nro" => {
            let mut out_file = output_option.open(output_file).map_err(|err| (err, output_file))?;
            nxo.write_nro(&mut out_file, romfs_dir, icon_file.as_ref().map(|v| &**v), nacp_file)
                .map_err(|err| (err, output_file))?;
        },
        "nso" => {
            let mut out_file = output_option.open(output_file).map_err(|err| (err, output_file))?;
            nxo.write_nso(&mut out_file).map_err(|err| (err, output_file))?;
        }
        _ => process::exit(1),
    }
    Ok(())
}

fn create_pfs0(input_directory: &str, output_file: &str) -> Result<(), linkle::error::Error> {
    let mut pfs0 = linkle::format::pfs0::Pfs0File::from_directory(&input_directory)?;
    let mut option = OpenOptions::new();
    let output_option = option.write(true).create(true).truncate(true);
    pfs0.write(&mut output_option.open(output_file).map_err(|err| (err, output_file))?).map_err(|err| (err, output_file))?;
    Ok(())
}

fn create_nacp(input_file: &str, output_file: &str) -> Result<(), linkle::error::Error> {
    let mut nacp = linkle::format::nacp::NacpFile::from_file(&input_file)?;
    let mut option = OpenOptions::new();
    let output_option = option.write(true).create(true).truncate(true);
    let mut out_file = output_option.open(output_file).map_err(|err| (err, output_file))?;
    nacp.write(&mut out_file).map_err(|err| (err, output_file))?;
    Ok(())
}

fn create_romfs(input_directory: &Path, output_file: &Path) -> Result<(), linkle::error::Error> {
    let romfs = linkle::format::romfs::RomFs::from_directory(&input_directory)?;
    let mut option = OpenOptions::new();
    let output_option = option.write(true).create(true).truncate(true);
    let mut out_file = output_option.open(output_file).map_err(|err| (err, output_file))?;
    romfs.write(&mut out_file).map_err(|err| (err, output_file))?;
    Ok(())
}

fn to_opt_str(s: &Option<String>) -> Option<&str> {
    s.as_ref().map(String::as_ref)
}

fn process_args(app: &Opt) {
    let res = match app {
        Opt::Nro { ref input_file, ref output_file, ref icon, ref romfs, ref nacp } => create_nxo("nro", input_file, output_file, to_opt_str(icon), to_opt_str(romfs), to_opt_str(nacp)),
        Opt::Nso { ref input_file, ref output_file } => create_nxo("nro", input_file, output_file, None, None, None),
        Opt::Pfs0 { ref input_directory, ref output_file } => create_pfs0(input_directory, output_file),
        Opt::Nacp { ref input_file, ref output_file } => create_nacp(input_file, output_file),
        Opt::Romfs { ref input_directory, ref output_file } => create_romfs(input_directory, output_file),
    };

    if let Err(e) = res {
        println!("Error: {}", e);
        process::exit(1)
    }
}

fn main() {
    process_args(&Opt::from_args());
}
