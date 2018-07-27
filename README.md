[![MIT license](https://img.shields.io/badge/license-MIT-blue.svg)](https://raw.githubusercontent.com/MegatonHammer/linkle/master/LICENSE-MIT)
[![Apache 2 license](https://img.shields.io/badge/license-Apache-blue.svg)](https://raw.githubusercontent.com/MegatonHammer/linkle/master/LICENSE-APACHE)
# Introduction

This program permits to convert or create various formats used on the Nintendo Switch.
For now only AArch64 ELF file to a NRO/NSO file is supported.

# Installation

Assuming you have `cargo` installed, `cargo install --git https://github.com/MegatonHammer/linkle`
will install this program, by the command name `linkle`.

# Usage

Creating a NRO file:

    linkle nro input.elf output.nro

Creating a NSO file:

    linkle nso input.elf output.nso
