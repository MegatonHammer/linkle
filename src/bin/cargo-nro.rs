#[macro_use]
extern crate clap;
extern crate linkle;
extern crate serde;
extern crate serde_json;
#[macro_use]
extern crate serde_derive;
extern crate cargo_metadata;
extern crate cargo_toml2;
extern crate goblin;
extern crate scroll;

use scroll::IOwrite;
use std::env::{self, VarError};
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use cargo_metadata::{Message, Package};
use cargo_toml2::CargoConfig;
use clap::{App, Arg};
use goblin::elf::section_header::{SHT_NOBITS, SHT_STRTAB, SHT_SYMTAB};
use goblin::elf::{Elf, Header as ElfHeader, ProgramHeader};
use linkle::format::{nacp::NacpFile, nxo::NxoFile, romfs::RomFs};
use snafu::Snafu;

#[derive(Debug, Snafu)]
enum Error {
    #[snafu(display("{}", error))]
    Goblin { error: goblin::error::Error },
    #[snafu(display("{}", error))]
    Linkle { error: linkle::error::Error },
}

impl From<goblin::error::Error> for Error {
    fn from(error: goblin::error::Error) -> Error {
        Error::Goblin { error }
    }
}

impl From<linkle::error::Error> for Error {
    fn from(error: linkle::error::Error) -> Error {
        Error::Linkle { error }
    }
}

impl From<std::io::Error> for Error {
    fn from(from: std::io::Error) -> Error {
        linkle::error::Error::from(from).into()
    }
}

// TODO: Run cargo build --help to get the list of options!
const CARGO_OPTIONS: &str = "CARGO OPTIONS:
    -p, --package <SPEC>...         Package to build
        --all                       Build all packages in the workspace
        --exclude <SPEC>...         Exclude packages from the build
    -j, --jobs <N>                  Number of parallel jobs, defaults to # of CPUs
        --lib                       Build only this package's library
        --bin <NAME>...             Build only the specified binary
        --bins                      Build all binaries
        --example <NAME>...         Build only the specified example
        --examples                  Build all examples
        --test <NAME>...            Build only the specified test target
        --tests                     Build all tests
        --bench <NAME>...           Build only the specified bench target
        --benches                   Build all benches
        --all-targets               Build all targets (lib and bin targets by default)
        --release                   Build artifacts in release mode, with optimizations
        --features <FEATURES>       Space-separated list of features to activate
        --all-features              Activate all available features
        --no-default-features       Do not activate the `default` feature
        --target <TRIPLE>           Build for the target triple
        --target-dir <DIRECTORY>    Directory for all generated artifacts
        --out-dir <PATH>            Copy final artifacts to this directory
        --manifest-path <PATH>      Path to Cargo.toml
        --message-format <FMT>      Error format [default: human]  [possible values: human, json]
        --build-plan                Output the build plan in JSON
    -v, --verbose                   Use verbose output (-vv very verbose/build.rs output)
    -q, --quiet                     No output printed to stdout
        --color <WHEN>              Coloring: auto, always, never
        --frozen                    Require Cargo.lock and cache are up to date
        --locked                    Require Cargo.lock is up to date
    -Z <FLAG>...                    Unstable (nightly-only) flags to Cargo, see 'cargo -Z help' for details
    -h, --help                      Prints help information";

trait BetterIOWrite<Ctx: Copy>: IOwrite<Ctx> {
    fn iowrite_with_try<N: scroll::ctx::SizeWith<Ctx> + scroll::ctx::TryIntoCtx<Ctx>>(
        &mut self,
        n: N,
        ctx: Ctx,
    ) -> Result<(), N::Error>
    where
        N::Error: From<std::io::Error>,
    {
        let mut buf = [0u8; 256];
        let size = N::size_with(&ctx);
        let buf = &mut buf[0..size];
        n.try_into_ctx(buf, ctx)?;
        self.write_all(buf)?;
        Ok(())
    }
}

impl<Ctx: Copy, W: IOwrite<Ctx> + ?Sized> BetterIOWrite<Ctx> for W {}

fn generate_debuginfo_romfs<P: AsRef<Path>>(
    elf_path: &Path,
    romfs: Option<P>,
) -> Result<RomFs, Error> {
    let mut elf_file = File::open(elf_path)?;
    let mut buffer = Vec::new();
    elf_file.read_to_end(&mut buffer)?;
    let elf = goblin::elf::Elf::parse(&buffer)?;
    let new_file = {
        let mut new_path = PathBuf::from(elf_path);
        new_path.set_extension("debug");
        let mut file = File::create(&new_path)?;
        let Elf {
            mut header,
            program_headers,
            mut section_headers,
            is_64,
            little_endian,
            ..
        } = elf;

        let ctx = goblin::container::Ctx {
            container: if is_64 {
                goblin::container::Container::Big
            } else {
                goblin::container::Container::Little
            },
            le: if little_endian {
                goblin::container::Endian::Little
            } else {
                goblin::container::Endian::Big
            },
        };

        for section in section_headers.iter_mut() {
            if section.sh_type == SHT_NOBITS
                || section.sh_type == SHT_SYMTAB
                || section.sh_type == SHT_STRTAB
            {
                continue;
            }
            if let Some(Ok(s)) = elf.shdr_strtab.get(section.sh_name) {
                if !(s.starts_with(".debug") || s == ".comment") {
                    section.sh_type = SHT_NOBITS;
                }
            }
        }

        // Calculate section data length + elf/program headers
        let data_off = ElfHeader::size(ctx) + ProgramHeader::size(ctx) * program_headers.len();
        let shoff = data_off as u64
            + section_headers
                .iter()
                .map(|v| {
                    if v.sh_type != SHT_NOBITS {
                        v.sh_size
                    } else {
                        0
                    }
                })
                .sum::<u64>();

        // Write ELF header
        // TODO: Anything else?
        header.e_phoff = ::std::mem::size_of::<ElfHeader>() as u64;
        header.e_shoff = shoff;
        file.iowrite_with(header, ctx)?;

        // Write program headers
        for phdr in program_headers {
            file.iowrite_with_try(phdr, ctx)?;
        }

        // Write section data
        let mut cur_idx = data_off;
        for section in section_headers
            .iter_mut()
            .filter(|v| v.sh_type != SHT_NOBITS)
        {
            file.write_all(
                &buffer[section.sh_offset as usize..(section.sh_offset + section.sh_size) as usize],
            )?;
            section.sh_offset = cur_idx as u64;
            cur_idx += section.sh_size as usize;
        }

        // Write section headers
        for section in section_headers {
            file.iowrite_with(section, ctx)?;
        }

        file.sync_all()?;
        new_path
    };

    let mut romfs = if let Some(romfs) = romfs {
        RomFs::from_directory(romfs.as_ref())?
    } else {
        RomFs::empty()
    };

    romfs.push_file(&new_file, "debug_info.elf")?;

    Ok(romfs)
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct PackageMetadata {
    romfs: Option<String>,
    nacp: Option<NacpFile>,
    icon: Option<String>,
    title_id: Option<String>,
}

trait WorkspaceMember {
    fn part(&self, n: usize) -> &str;

    fn name(&self) -> &str {
        self.part(0)
    }

    fn version(&self) -> semver::Version {
        semver::Version::parse(self.part(1)).expect("bad version in cargo metadata")
    }

    fn url(&self) -> &str {
        let url = self.part(2);
        &url[1..url.len() - 1]
    }
}

impl WorkspaceMember for cargo_metadata::PackageId {
    fn part(&self, n: usize) -> &str {
        self.repr.splitn(3, ' ').nth(n).unwrap()
    }
}

fn main() {
    let args = if env::args().nth(1) == Some("nro".to_string()) {
        // Skip the subcommand when running through cargo
        env::args().skip(1)
    } else {
        env::args().skip(0)
    };

    let matches = App::new(crate_name!())
        .about("Compile rust switch homebrews with ease!")
        .arg(
            Arg::with_name("CARGO_OPTIONS")
                .raw(true)
                .help("Options that will be passed to cargo build"),
        )
        .after_help(CARGO_OPTIONS)
        .get_matches_from(args);

    let metadata = cargo_metadata::MetadataCommand::new().exec().unwrap();

    let rust_target_path = match env::var("RUST_TARGET_PATH") {
        Err(VarError::NotPresent) => metadata.workspace_root.clone(),
        s => PathBuf::from(s.unwrap()),
    };

    let mut command = Command::new("xargo");

    let config_path = Path::new("./.cargo/config");
    let target = if config_path.exists() {
        let config: Option<CargoConfig> = cargo_toml2::from_path(config_path).ok();
        config
            .map(|config| config.build.map(|build| build.target).flatten())
            .flatten()
    } else {
        None
    };

    let target = target.as_deref().unwrap_or("aarch64-roblabla-switch");

    command
        .args(&[
            "build",
            &format!("--target={}", target),
            "--message-format=json-diagnostic-rendered-ansi",
        ])
        .stdout(Stdio::piped())
        .env("RUST_TARGET_PATH", rust_target_path.as_os_str());

    if let Some(cargo_opts) = matches.values_of("CARGO_OPTIONS") {
        command.args(cargo_opts);
    }

    let mut command = command.spawn().unwrap();
    let stdout_reader = std::io::BufReader::new(command.stdout.take().unwrap());

    let iter = cargo_metadata::Message::parse_stream(stdout_reader);
    for message in iter {
        match message {
            Ok(Message::CompilerArtifact(ref artifact))
                if artifact.target.kind.contains(&"bin".into())
                    || artifact.target.kind.contains(&"cdylib".into()) =>
            {
                let package: &Package = match metadata
                    .packages
                    .iter()
                    .find(|v| v.id == artifact.package_id)
                {
                    Some(v) => v,
                    None => continue,
                };

                let root = package.manifest_path.parent().unwrap();
                let target_metadata: PackageMetadata = serde_json::from_value(
                    package
                        .metadata
                        .pointer(&format!("linkle/{}", artifact.target.name))
                        .cloned()
                        .unwrap_or(serde_json::Value::Null),
                )
                .unwrap_or_default();

                let romfs = if let Some(romfs) = target_metadata.romfs {
                    let romfs_path = root.join(romfs);
                    if !romfs_path.is_dir() {
                        panic!("Invalid romfs directory {:?}", romfs_path);
                    } else {
                        Some(romfs_path)
                    }
                } else if root.join("res").is_dir() {
                    Some(root.join("res"))
                } else {
                    None
                };

                let icon_file = if let Some(icon) = target_metadata.icon {
                    let icon_path = root.join(icon);
                    if !icon_path.is_file() {
                        panic!("Invalid icon file {:?}", icon_path);
                    } else {
                        Some(icon_path)
                    }
                } else if root.join("icon.jpg").is_file() {
                    Some(root.join("icon.jpg"))
                } else {
                    None
                };

                let icon_file = icon_file.map(|v| v.to_string_lossy().into_owned());
                let icon_file = icon_file.as_ref().map(|v| v.as_ref());

                let mut nacp = target_metadata.nacp.unwrap_or_default();
                nacp.name.get_or_insert(package.name.clone());
                nacp.author.get_or_insert(package.authors[0].clone());
                nacp.version.get_or_insert(package.version.to_string());
                if nacp.title_id.is_none() {
                    nacp.title_id = target_metadata.title_id;
                }

                let romfs =
                    generate_debuginfo_romfs(Path::new(&artifact.filenames[0]), romfs).unwrap();

                let mut new_name = artifact.filenames[0].clone();
                assert!(new_name.set_extension("nro"));

                NxoFile::from_elf(artifact.filenames[0].to_str().unwrap())
                    .unwrap()
                    .write_nro(
                        &mut File::create(new_name.clone()).unwrap(),
                        Some(romfs),
                        icon_file,
                        Some(nacp),
                    )
                    .unwrap();

                println!("Built {}", new_name.to_string_lossy());
            }
            Ok(Message::CompilerArtifact(_artifact)) => {
                //println!("{:#?}", artifact);
            }
            Ok(Message::CompilerMessage(msg)) => {
                if let Some(msg) = msg.message.rendered {
                    println!("{}", msg);
                } else {
                    println!("{:?}", msg);
                }
            }
            Ok(_) => (),
            Err(err) => {
                panic!("{:?}", err);
            }
        }
    }
}
