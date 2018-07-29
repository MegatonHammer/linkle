[![MIT license](https://img.shields.io/badge/license-MIT-blue.svg)](https://raw.githubusercontent.com/MegatonHammer/linkle/master/LICENSE-MIT)
[![Apache 2 license](https://img.shields.io/badge/license-Apache-blue.svg)](https://raw.githubusercontent.com/MegatonHammer/linkle/master/LICENSE-APACHE)
# Introduction

This program permits to convert or create various formats used on the Nintendo Switch.
For now, it only supports the creation of PFS0/NSP and 64 bits NRO/NSO.

# Installation

Assuming you have `cargo` installed, `cargo install --git https://github.com/MegatonHammer/linkle`
will install this program, by the command name `linkle`.

# Usage

Creating a NRO file:

    linkle nro input.elf output.nro

Creating a NSO file:

    linkle nso input.elf output.nso

Creating a PFS0/NSP file:

    linkle pfs0 input_directory output.pfs0
