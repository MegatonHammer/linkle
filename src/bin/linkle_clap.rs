#[macro_use]
extern crate clap;

extern crate linkle;

use clap::{App, AppSettings, Arg, ArgMatches, SubCommand};

use std::fs::OpenOptions;
use std::process;

fn create_nxo(format: &str, matches: &ArgMatches) -> std::io::Result<()> {
    let input_file = matches.value_of("INPUT_FILE").unwrap();
    let output_file = matches.value_of("OUTPUT_FILE").unwrap();
    let mut nxo = linkle::format::nxo::NxoFile::from_elf(input_file)?;
    let mut option = OpenOptions::new();
    let output_option = option.write(true).create(true).truncate(true);
    match format {
        "nro" => nxo.write_nro(&mut output_option.open(output_file)?),
        "nso" => nxo.write_nso(&mut output_option.open(output_file)?),
        _ => process::exit(1),
    }
}

fn create_pfs0(matches: &ArgMatches) -> std::io::Result<()> {
    let input_directory = matches.value_of("INPUT_DIRECTORY").unwrap();
    let output_file = matches.value_of("OUTPUT_FILE").unwrap();
    let mut pfs0 = linkle::format::pfs0::Pfs0File::from_directory(input_directory)?;
    let mut option = OpenOptions::new();
    let output_option = option.write(true).create(true).truncate(true);
    pfs0.write(&mut output_option.open(output_file)?)?;
    Ok(())
}

fn create_nacp(matches: &ArgMatches) -> std::io::Result<()> {
    let input_file = matches.value_of("INPUT_FILE").unwrap();
    let output_file = matches.value_of("OUTPUT_FILE").unwrap();
    let mut nacp = linkle::format::nacp::NacpFile::from_file(input_file)?;
    let mut option = OpenOptions::new();
    let output_option = option.write(true).create(true).truncate(true);
    nacp.write(&mut output_option.open(output_file)?)?;
    Ok(())
}

fn create_romfs(matches: &ArgMatches) -> std::io::Result<()> {
    let input_directory = matches.value_of("INPUT_DIRECTORY").unwrap();
    let output_file = matches.value_of("OUTPUT_FILE").unwrap();
    let romfs = linkle::format::romfs::RomFs::from_directory(input_directory)?;
    let mut option = OpenOptions::new();
    let output_option = option.write(true).create(true).truncate(true);
    romfs.write(&mut output_option.open(output_file)?)?;
    Ok(())
}

fn process_args(app: App) -> () {
    let matches = app.get_matches();

    let res = match matches.subcommand() {
        ("nro", Some(sub_matches)) => create_nxo("nro", sub_matches),
        ("nso", Some(sub_matches)) => create_nxo("nso", sub_matches),
        ("pfs0", Some(sub_matches)) => create_pfs0(sub_matches),
        ("nacp", Some(sub_matches)) => create_nacp(sub_matches),
        ("romfs", Some(sub_matches)) => create_romfs(sub_matches),
        _ => process::exit(1),
    };

    match res {
        Err(e) => {
            println!("Error: {:?}", e);
            process::exit(1)
        }
        _ => (),
    }
}

fn main() {
    let input_directory_arg = Arg::with_name("INPUT_DIRECTORY")
        .help("Sets the input directory to use")
        .required(true);
    let input_file_arg = Arg::with_name("INPUT_FILE")
        .help("Sets the input file to use")
        .required(true);
    let output_file_arg = Arg::with_name("OUTPUT_FILE")
        .help("Sets the output file to use")
        .required(true);
    let app = App::new(crate_name!())
        .about("The legendary hero")
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .author(crate_authors!("\n"))
        .subcommands(vec![
            SubCommand::with_name("nro")
                .about("Create a NRO file from an ELF file")
                .args(&vec![input_file_arg.clone(), output_file_arg.clone()]),
            SubCommand::with_name("nso")
                .about("Create a NSO file from an ELF file")
                .args(&vec![input_file_arg.clone(), output_file_arg.clone()]),
            SubCommand::with_name("pfs0")
                .alias("nsp")
                .about("Create a PFS0/NSP file from a directory")
                .args(&vec![input_directory_arg.clone(), output_file_arg.clone()]),
            SubCommand::with_name("nacp")
                .about("Create a NACP file from a JSON file")
                .args(&vec![input_file_arg.clone(), output_file_arg.clone()]),
            SubCommand::with_name("romfs")
                .about("Create a RomFS file from a directory")
                .args(&vec![input_directory_arg.clone(), output_file_arg.clone()]),
        ]);
    process_args(app);
}
