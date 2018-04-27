[![MIT license](https://img.shields.io/badge/license-MIT-blue.svg)](https://raw.githubusercontent.com/MegatonHammer/elf2nxo/master/LICENSE-MIT)
[![Apache 2 license](https://img.shields.io/badge/license-Apache-blue.svg)](https://raw.githubusercontent.com/MegatonHammer/elf2nxo/master/LICENSE-APACHE)
# Introduction

This program permits to convert a AArch64 ELF file to a NRO or a NSO file.

# Installation

Assuming you have `cargo` installed, `cargo install --git https://github.com/MegatonHammer/elf2nxo`
will install this program, by the command name `elf2nxo`.

# Usage

Creating a NRO file:

    elf2nxo input.elf output.nro

Creating a NSO file:

    elf2nxo input.elf output.nso nso
