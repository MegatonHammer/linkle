extern crate byteorder;
extern crate crypto_hash;
extern crate elf;
extern crate lz4_sys;

use std::env;
use std::fs::OpenOptions;
use std::process;

mod converter;
mod utils;

fn create_nxo(input: String, output: String, format: String) -> std::io::Result<()> {
    let mut nxo = converter::Nxo::new(input)?;
    let mut option = OpenOptions::new();
    let output_option = option.write(true).create(true);
    match format.as_str() {
        "nro" => nxo.write_nro(&mut output_option.open(output)?),
        "nso" => nxo.write_nso(&mut output_option.open(output)?),
        unk_type => {
            println!("Unknown format type: '{}'", unk_type);
            process::exit(1)
        }
    }
}

fn main() {
    let input = env::args().nth(1);
    let output = env::args().nth(2);
    let format = env::args().nth(3).unwrap_or("nro".to_string());

    match (input, output) {
        (Some(input), Some(output)) => match create_nxo(input, output, format) {
            Err(e) => {
                println!("Error: {:?}", e);
                process::exit(1)
            }
            _ => (),
        },
        _ => println!("elf2nxo input output [type]"),
    };
}
