#[macro_use]
extern crate clap;
extern crate url;
extern crate linkle;
extern crate serde;
extern crate serde_json;
#[macro_use]
extern crate serde_derive;
extern crate cargo_metadata;

use std::env::{self, VarError};
use std::process::{Command, Stdio};
use std::path::{Path, PathBuf};
use std::fs::File;
use linkle::format::{romfs::RomFs, nxo::NxoFile, nacp::NacpFile};
use cargo_metadata::{Package, Message};
use clap::{Arg, App};
use url::Url;

fn find_project_root(path: &Path) -> Option<&Path> {
    for parent in path.ancestors() {
        if parent.join("Cargo.toml").is_file() {
            return Some(parent);
        }
    }
    None
}


// TODO: Run cargo build --help to get the list of options!
const CARGO_OPTIONS: &'static str = "CARGO OPTIONS:
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


fn get_metadata(manifest_path: &Path, package_id: &str, target_name: &str) -> (Package, PackageMetadata) {
    let metadata = cargo_metadata::metadata(Some(&manifest_path)).unwrap();
    let package = metadata.packages.into_iter().find(|v| v.id == package_id).unwrap();
    let package_metadata = serde_json::from_value(package.metadata.pointer(&format!("linkle/{}", target_name)).cloned().unwrap_or(serde_json::Value::Null)).unwrap_or(PackageMetadata::default());
    (package, package_metadata)
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct PackageMetadata {
    romfs: Option<String>,
    nacp: Option<NacpFile>,
    icon: Option<String>,
    title_id: Option<String>
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
        .arg(Arg::with_name("CARGO_OPTIONS")
             .raw(true)
             .help("Options that will be passed to cargo build"))
        .after_help(CARGO_OPTIONS)
        .get_matches_from(args);


    let rust_target_path = match env::var("RUST_TARGET_PATH") {
        Err(VarError::NotPresent) => {
            // TODO: Handle workspace
            find_project_root(&env::current_dir().unwrap()).unwrap().into()
        },
        s => PathBuf::from(s.unwrap()),
    };

    let mut command = Command::new("xargo");

    command
        .args(&["build", "--target=aarch64-roblabla-switch", "--message-format=json"])
        .stdout(Stdio::piped())
        .env("RUST_TARGET_PATH", rust_target_path.as_os_str());

    if let Some(cargo_opts) = matches.values_of("CARGO_OPTIONS") {
        command.args(cargo_opts);
    }

    let command = command.spawn().unwrap();

    let iter = cargo_metadata::parse_message_stream(command.stdout.unwrap());
    for message in iter {
        match message {
            Ok(Message::CompilerArtifact(ref artifact)) if artifact.target.kind[0] == "bin" => {
                // Find the artifact's source. This is not going to be pretty.
                // For whatever reason, cargo thought it'd be a *great idea* to make file URLs use
                // the non-standard "path+file:///" scheme, instead of, y'know, the ""file:///" everyone
                // knows.
                //
                // So we check if it starts with path+file, and if it does, we skip the path+ part when
                // parsing it.
                let url = if artifact.package_id.url().starts_with("path+file") {
                    &artifact.package_id.url()["path+".len()..]
                } else {
                    artifact.package_id.url()
                };
                let url = Url::parse(url).unwrap();
                if url.scheme() != "file" {
                    continue;
                }

                let root = url.to_file_path().unwrap();
                let manifest = root.join("Cargo.toml");

                let (package, target_metadata) = get_metadata(&manifest, &artifact.package_id.raw, &artifact.target.name);

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

                let mut nacp = target_metadata.nacp.unwrap_or(Default::default());
                nacp.name.get_or_insert(package.name);
                nacp.author.get_or_insert(package.authors[0].clone());
                nacp.version.get_or_insert(package.version);
                if nacp.title_id.is_none() {
                    nacp.title_id = target_metadata.title_id;
                }

                let romfs = if let Some(romfs) = romfs {
                    Some(RomFs::from_directory(&romfs).unwrap())
                } else {
                    None
                };

                let mut new_name = PathBuf::from(artifact.filenames[0].clone());
                assert!(new_name.set_extension("nro"));

                NxoFile::from_elf(&artifact.filenames[0]).unwrap()
                    .write_nro(&mut File::create(new_name.clone()).unwrap(),
                               romfs,
                               icon_file,
                               Some(nacp)
                    ).unwrap();

                println!("Built {}", new_name.to_string_lossy());
            },
            Ok(Message::CompilerArtifact(_artifact)) => {
                //println!("{:#?}", artifact);
            },
            Ok(Message::CompilerMessage(msg)) => {
                if let Some(msg) = msg.message.rendered {
                    println!("{}", msg);
                } else {
                    println!("{:?}", msg);
                }
            },
            Ok(_) => (),
            Err(err) => {
                panic!("{:?}", err);
            }
        }
    }
}
