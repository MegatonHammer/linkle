extern crate byteorder;
#[macro_use]
extern crate clap;
extern crate crypto_hash;
extern crate elf;
extern crate lz4_sys;

use clap::{App, AppSettings, Arg, ArgMatches, SubCommand};

use std::fs::OpenOptions;
use std::process;

mod converter;
mod utils;

fn create_nxo(format: &str, matches: &ArgMatches) -> std::io::Result<()> {
    let input_file = matches.value_of("INPUT").unwrap();
    let output_file = matches.value_of("OUTPUT").unwrap();
    let mut nxo = converter::nxo::NxoFile::from_elf(input_file)?;
    let mut option = OpenOptions::new();
    let output_option = option.write(true).create(true);
    match format {
        "nro" => nxo.write_nro(&mut output_option.open(output_file)?),
        "nso" => nxo.write_nso(&mut output_option.open(output_file)?),
        _ => process::exit(1),
    }
}

fn process_args(app: App) -> () {
    let matches = app.get_matches();

    let res = match matches.subcommand() {
        ("nro", Some(sub_matches)) => create_nxo("nro", sub_matches),
        ("nso", Some(sub_matches)) => create_nxo("nso", sub_matches),
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
    let input_arg = Arg::with_name("INPUT")
        .help("Sets the input file to use")
        .required(true);
    let output_arg = Arg::with_name("OUTPUT")
        .help("Sets the output file to use")
        .required(true);
    let app = App::new(crate_name!())
        .about("The legendary hero")
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .author(crate_authors!("\n"))
        .subcommands(vec![
            SubCommand::with_name("nro")
                .about("Creating a NRO file from an ELF file")
                .args(&vec![input_arg.clone(), output_arg.clone()]),
            SubCommand::with_name("nso")
                .about("Creating a NSO file from an ELF file")
                .args(&vec![input_arg, output_arg]),
        ]);
    process_args(app);
}
