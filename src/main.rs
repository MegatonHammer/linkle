extern crate byteorder;
#[macro_use]
extern crate clap;
extern crate crypto_hash;
extern crate elf;
extern crate lz4_sys;

use clap::{App, AppSettings, Arg, ArgMatches, SubCommand};

use std::fs::OpenOptions;
use std::process;

mod format;

fn create_nxo(format: &str, matches: &ArgMatches) -> std::io::Result<()> {
    let input_file = matches.value_of("INPUT_FILE").unwrap();
    let output_file = matches.value_of("OUTPUT_FILE").unwrap();
    let mut nxo = format::nxo::NxoFile::from_elf(input_file)?;
    let mut option = OpenOptions::new();
    let output_option = option.write(true).create(true).truncate(true);
    match format {
        "nro" => nxo.write_nro(&mut output_option.open(output_file)?),
        "nso" => nxo.write_nso(&mut output_option.open(output_file)?),
        _ => process::exit(1),
    }
}

fn create_pfs0(matches: &ArgMatches) -> std::io::Result<()> {
    let input_file = matches.value_of("INPUT_DIRECTORY").unwrap();
    let output_file = matches.value_of("OUTPUT_FILE").unwrap();
    let mut pfs0 = format::pfs0::Pfs0File::from_directory(input_file)?;
    let mut option = OpenOptions::new();
    let output_option = option.write(true).create(true).truncate(true);
    pfs0.write(&mut output_option.open(output_file)?)?;
    Ok(())
}

fn process_args(app: App) -> () {
    let matches = app.get_matches();

    let res = match matches.subcommand() {
        ("nro", Some(sub_matches)) => create_nxo("nro", sub_matches),
        ("nso", Some(sub_matches)) => create_nxo("nso", sub_matches),
        ("pfs0", Some(sub_matches)) => create_pfs0(sub_matches),
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
                .args(&vec![input_directory_arg, output_file_arg]),
        ]);
    process_args(app);
}
