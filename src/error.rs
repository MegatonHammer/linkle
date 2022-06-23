use block_modes::BlockModeError;
use snafu::Backtrace;
use snafu::GenerateBacktrace;
use snafu::Snafu;
use std::io;
use std::borrow::Cow;
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
    #[snafu(display("Decryption failed"))]
    BlockMode {
        error: BlockModeError,
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
        error: cmac::crypto_mac::MacError,
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
    #[snafu(display("Invalid NPDM value for field {}", "_0"))]
    InvalidNpdmValue {
        error: Cow<'static, str>,
        backtrace: Backtrace,
    },
    #[snafu(display("Failed to serialize NPDM."))]
    BincodeError {
        error: Box<bincode::ErrorKind>,
        backtrace: Backtrace
    },
    #[snafu(display("Failed to sign NPDM."))]
    RsaError {
        error: rsa::errors::Error,
        backtrace: Backtrace
    },
    #[snafu(display("Failed to sign NPDM, invalid PEM."))]
    PemError {
        error: pem::PemError,
        backtrace: Backtrace
    },
    #[snafu(display("Failed to sign NPDM, invalid PEM."))]
    Asn1Error {
        error: yasna::ASN1Error,
        backtrace: Backtrace
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

impl From<BlockModeError> for Error {
    fn from(error: BlockModeError) -> Error {
        Error::BlockMode {
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

impl From<(usize, cmac::crypto_mac::MacError)> for Error {
    fn from((id, error): (usize, cmac::crypto_mac::MacError)) -> Error {
        Error::MacError {
            error,
            id,
            backtrace: Backtrace::generate(),
        }
    }
}

impl From<Box<bincode::ErrorKind>> for Error {
    fn from(err: Box<bincode::ErrorKind>) -> Error {
        Error::BincodeError {
            error: err,
            backtrace: Backtrace::generate()
        }
    }
}

impl From<rsa::errors::Error> for Error {
    fn from(err: rsa::errors::Error) -> Error {
        Error::RsaError {
            error: err,
            backtrace: Backtrace::generate()
        }
    }
}

impl From<pem::PemError> for Error {
    fn from(err: pem::PemError) -> Error {
        Error::PemError {
            error: err,
            backtrace: Backtrace::generate()
        }
    }
}

impl From<yasna::ASN1Error> for Error {
    fn from(err: yasna::ASN1Error) -> Error {
        Error::Asn1Error {
            error: err,
            backtrace: Backtrace::generate()
        }
    }
}