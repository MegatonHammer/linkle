extern crate byteorder;
#[macro_use]
extern crate clap;
extern crate crypto_hash;
extern crate elf;
extern crate lz4_sys;

use clap::{App, AppSettings, Arg, SubCommand};

use std::fs::OpenOptions;
use std::process;

mod converter;
mod utils;

fn create_nxo(input: &str, output: &str, format: &str) -> std::io::Result<()> {
    let mut nxo = converter::Nxo::new(input)?;
    let mut option = OpenOptions::new();
    let output_option = option.write(true).create(true);
    match format {
        "nro" => nxo.write_nro(&mut output_option.open(output)?),
        "nso" => nxo.write_nso(&mut output_option.open(output)?),
        _ => process::exit(1),
    }
}

fn process_args(app: App) -> () {
    let matches = app.get_matches();

    let input_file = matches.value_of("INPUT").unwrap();
    let output_file = matches.value_of("OUTPUT").unwrap();

    let res = match matches.subcommand() {
        ("nro", Some(_)) => create_nxo(input_file, output_file, "nro"),
        ("nso", Some(_)) => create_nxo(input_file, output_file, "nso"),
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
    let app = App::new(crate_name!())
        .about("The legendary hero")
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .author(crate_authors!("\n"))
        .subcommands(vec![
            SubCommand::with_name("nro").about("Creating a NRO file from an ELF file"),
            SubCommand::with_name("nso").about("Creating a NSO file from an ELF file"),
        ])
        .arg(
            Arg::with_name("INPUT")
                .help("Sets the input file to use")
                .required(true),
        )
        .arg(
            Arg::with_name("OUTPUT")
                .help("Sets the output file to use")
                .required(true),
        );
    process_args(app);
}
