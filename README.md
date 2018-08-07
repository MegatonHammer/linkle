[![MIT license](https://img.shields.io/badge/license-MIT-blue.svg)](https://raw.githubusercontent.com/MegatonHammer/linkle/master/LICENSE-MIT)
[![Apache 2 license](https://img.shields.io/badge/license-Apache-blue.svg)](https://raw.githubusercontent.com/MegatonHammer/linkle/master/LICENSE-APACHE)
# Introduction

This program permits to convert or create various formats used on the Nintendo Switch.
For now, it only supports the creation of PFS0/NSP and 64 bits NRO/NSO.

# Installation

Assuming you have `cargo` installed, `cargo install --features=binaries --git https://github.com/MegatonHammer/linkle`
will install this program, by the command name `linkle`.

# Usage

Creating a NRO file:

    linkle nro input.elf output.nro

Creating a NSO file:

    linkle nso input.elf output.nso

Creating a PFS0/NSP file:

    linkle pfs0 input_directory output.pfs0

Creating a NACP file:
    linkle ncap input.json output.nacp

# NACP input format

This is an example of a compatible JSON:

```json
{
    "name": "Link",
    "author": "Linkle",
    "version": "1.0.0",
    "title_id": "0400000000020000",
    "lang": {
        "ja": {
            "name": "リンク",
            "author": "リンクル"
        }
    }
}
```

## Fields

NOTE: Every fields are optional

| Field             | Description                                      | Default value       |
| ----------------- |:------------------------------------------------:| -------------------:|
| name              | The application name.                            | Unknown Application |
| author            | The application author.                          | Unknown Author      |
| version           | The application version.                         | 1.0.0               |
| title_id          | The application title id.                        | 0000000000000000    |
| dlc_base_title_id | The base id of all the title DLC.                | title_id + 0x1000   |
| lang (object)     | Different name/author depending of the language  | use name and author |

| Supported Languages|
|:------------------:|
| en-US              |
| en-UK              |
| ja                 |
| fr                 |
| de                 |
| es-419             |
| es                 |
| it                 |
| nl                 |
| fr-CA              |
| pt                 |
| ru                 |
| ko                 |
| zh-TW              |
| zh-CN              |
