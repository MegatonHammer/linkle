[![MIT license](https://img.shields.io/badge/license-MIT-blue.svg)](https://raw.githubusercontent.com/MegatonHammer/linkle/master/LICENSE-MIT)
[![Apache 2 license](https://img.shields.io/badge/license-Apache-blue.svg)](https://raw.githubusercontent.com/MegatonHammer/linkle/master/LICENSE-APACHE)
[![Discord](https://img.shields.io/discord/439418034130780182.svg)]( https://discord.gg/MZJbNZY)

# linkle

This program permits to convert or create various formats used on the Nintendo Switch.

It can also
be used with cargo through `cargo nro` to simplify the build process of Megaton-Hammer
homebrew.

Supported formats: PFS0/NSP, NSO, NRO, NPDM, NACP, RomFs

# Installation

Assuming you have `cargo` installed, `cargo install --features=binaries --git https://github.com/MegatonHammer/linkle`
will install this program, by the command name `linkle` and the `cargo nro` subcommand.

# Usage

Creating a NRO file:

    linkle nro input.elf output.nro

Creating a NSO file:

    linkle nso input.elf output.nso

Creating a PFS0/NSP file:

    linkle pfs0 input_directory output.pfs0

Creating a NACP file:

    linkle nacp input.json output.nacp

Creating a NPDM file:

    linkle npdm input.json output.npdm

Creating a RomFs file:

    linkle romfs input_directory output.romfs

Compiling and creating an NRO file (requires xargo from https://github.com/roblabla/xargo installed):

    cargo nro

# Cargo.toml metadata format

When compiling a project with `cargo nro`, a special `[package.metadata.linkle.BINARY_NAME]` key is
used to allow customizing the build. This is an example Cargo.toml:

```toml
[package]
name = "link"
version = "0.1.0"
authors = ["linkle"]

[package.metadata.linkle.megaton-example]
romfs = "res/"
icon = "icon.jpeg"
titleid = "0100000000819"

[package.metadata.linkle.megaton-example.nacp]
default_name = "Link"
default_author = "Linkle"

[package.metadata.linkle.megaton-example.nacp.titles.ja]
"name": "リンク",
"author": "リンクル"
```

All paths are relative to the project root (where the Cargo.toml file is located).

Every field has a sane default:

| Field             | Description                                      | Default value       |
| ----------------- |:------------------------------------------------:| -------------------:|
| romfs             | The application romfs directory.                 | res/                |
| icon              | The application icon.                            | icon.jpg            |
| title_id          | The application title id.                        | 0000000000000000    |

The `[package.metadata.linkle.BINARY_NAME.nacp]` key follows the [NACP input format](#nacp-input-format)

# NACP input format (JSON)

This is an example of a compatible JSON:

```json
{
    "default_name": "Link",
    "default_author": "Linkle",
    "version": "1.0.0",
    "application_id": "0100AAAABBBBCCCC",
    "startup_user_account": "Required",
    "titles": {
        "ja": {
            "name": "リンク",
            "author": "リンクル"
        },
        "Spanish": {
            "name": "Link (es)",
            "author": "Linkle (es)"
        }
    }
}
```

## Fields

| Field                  | Value                                                            | Description                                               | Default value           |
|------------------------|------------------------------------------------------------------|-----------------------------------------------------------|-------------------------|
| default_name           | String (max size 0x200)                                          | Default title name                                        | Unknown application     |
| default_author         | String (max size 0x100)                                          | Default application author                                | Unknown author          |
| version                | String (max size 0x10)                                           | Application version                                       | <required field>        |
| application_id         | Hex-String u64                                                   | Application ID                                            | 0000000000000000        |
| add_on_content_base_id | Hex-String u64                                                   | Base ID for add-on content (DLC)                          | application_id + 0x1000 |
| titles                 | Object of language titles                                        | Language-specific application name/author values          | Default values above    |
| presence_group_id      | Hex-String u64                                                   | Presence group ID                                         | application_id          |
| save_data_owner_id     | Hex-String u64                                                   | Save-data owner ID                                        | application_id          |
| isbn                   | String (max size 0x25)                                           | ISBN                                                      | Empty string            |
| startup_user_account   | "None", "Required", "RequiredWithNetworkServiceAccountAvailable" | Whether the application requires a user account on launch | "None"                  |
| attribute              | "None", "Demo", "RetailInteractiveDisplay"                       | Application attribute                                     | "None"                  |
| screenshot             | "Allow", "Deny"                                                  | Screenshot control                                        | "Allow"                 |
| video_capture          | "Disabled", "Enabled", "Automatic"                               | Video capture control                                     | "Disabled"              |
| logo_type              | "LicensedByNintendo", "Nintendo"                                 | Logo type                                                 | "LicensedByNintendo"    |
| logo_handling          | "Auto", "Manual"                                                 | Logo handling                                             | "Auto"                  |
| crash_report           | "Deny", "Allow"                                                  | Crash report control                                      | "Allow"                 |
| bcat_passphrase        | String (max size 0x41)                                           | BCAT passphrase                                           | Empty string            |
| program_index          | u8                                                               | Program index                                             | 0                       |

Note: default name/author and application ID are not actual NACP fields, but they are used as the default value for various fields, as the table shows.

### Available languages

| Language names       | Language codes |
|----------------------|----------------|
| AmericanEnglish      | en-US          |
| BritishEnglish       | en-UK          |
| Japanese             | ja             |
| French               | fr             |
| German               | de             |
| LatinAmericanSpanish | es-419         |
| Spanish              | es             |
| Italian              | it             |
| Dutch                | nl             |
| CanadianFrench       | fr-CA          |
| Portuguese           | pt             |
| Russian              | ru             |
| Korean               | ko             |
| TraditionalChinese   | zh-TW          |
| SimplifiedChinese    | zh-CN          |
| BrazilianPortuguese  | pt-BR          |

Note: languages in the titles object can be specified by their names or their codes, as the JSON example above shows.