use crate::format::nca::RightsId;
use crate::pki::KeyName;
use snafu::Snafu;
use snafu::{Backtrace, GenerateImplicitData};
use std::io;
use std::path::{Path, PathBuf};
use std::str::Utf8Error;
use std::string::FromUtf8Error;

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Failed to deserialize: {}", error))]
    Deserialization { error: serde_json::error::Error },
    #[snafu(display( "{}: {}", path.display(), error))]
    Io {
        error: io::Error,
        path: PathBuf,
        backtrace: Backtrace,
    },
    #[snafu(display(
        "Internal IO Error (please submit a bug report with the backtrace): {}",
        error
    ))]
    IoInternal {
        error: io::Error,
        backtrace: Backtrace,
    },
    #[snafu(display("Error parsing the INI file: {}", error))]
    Ini {
        error: ini::Error,
        backtrace: Backtrace,
    },
    #[snafu(display("Key derivation error: {}", error))]
    Crypto { error: String, backtrace: Backtrace },
    #[snafu(display("Invalid keyblob {}: {}.", id, error))]
    MacError {
        error: digest::MacError,
        id: usize,
        backtrace: Backtrace,
    },
    #[snafu(display("Invalid PFS0: {}.", error))]
    InvalidPfs0 {
        error: &'static str,
        backtrace: Backtrace,
    },
    #[snafu(display("Failed to convert filename to UTF8: {}.", filename))]
    Utf8Conversion {
        filename: String,
        error: Utf8Error,
        backtrace: Backtrace,
    },
    #[snafu(display("Can't handles symlinks in romfs: {}", error.display()))]
    RomFsSymlink {
        error: PathBuf,
        backtrace: Backtrace,
    },
    #[snafu(display("Unknown file type at {}", error.display()))]
    RomFsFiletype {
        error: PathBuf,
        backtrace: Backtrace,
    },
    #[snafu(display("Missing key {:?}. Make sure your keyfile is complete", key_name))]
    MissingKey {
        key_name: KeyName,
        backtrace: Backtrace,
    },
    #[snafu(display("Missing titlekey for {}. Make sure you have provided it", rights_id))]
    MissingTitleKey {
        rights_id: RightsId,
        backtrace: Backtrace,
    },
    #[snafu(display("Failed to parse NCA. Make sure your {} key is correct.", key_name))]
    NcaParse {
        key_name: &'static str,
        backtrace: Backtrace,
    },
}

impl Error {
    fn with_path<T: AsRef<Path>>(self, path: T) -> Error {
        if let Error::IoInternal { error, backtrace } = self {
            Error::Io {
                error,
                path: path.as_ref().to_owned(),
                backtrace,
            }
        } else {
            self
        }
    }
}

pub trait ResultExt {
    fn with_path<T: AsRef<Path>>(self, path: T) -> Self;
}

impl<T> ResultExt for Result<T, Error> {
    fn with_path<U: AsRef<Path>>(self, path: U) -> Result<T, Error> {
        self.map_err(|err| err.with_path(path))
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Error {
        Error::IoInternal {
            error: err,
            backtrace: Backtrace::generate(),
        }
    }
}

impl<T: AsRef<Path>> From<(io::Error, T)> for Error {
    fn from((error, path): (io::Error, T)) -> Error {
        Error::Io {
            error,
            path: path.as_ref().to_owned(),
            backtrace: Backtrace::generate(),
        }
    }
}

impl From<ini::Error> for Error {
    fn from(error: ini::Error) -> Error {
        Error::Ini {
            error,
            backtrace: Backtrace::generate(),
        }
    }
}

impl From<serde_json::error::Error> for Error {
    fn from(error: serde_json::error::Error) -> Error {
        Error::Deserialization { error }
    }
}

impl From<FromUtf8Error> for Error {
    fn from(error: FromUtf8Error) -> Error {
        // Why the heck does OsStr not have display()?
        Error::Utf8Conversion {
            filename: String::from_utf8_lossy(error.as_bytes()).into_owned(),
            error: error.utf8_error(),
            backtrace: Backtrace::generate(),
        }
    }
}

impl From<(usize, digest::MacError)> for Error {
    fn from((id, error): (usize, digest::MacError)) -> Error {
        Error::MacError {
            error,
            id,
            backtrace: Backtrace::generate(),
        }
    }
}
