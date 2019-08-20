use std::io;
use std::str::Utf8Error;
use std::string::FromUtf8Error;
use std::path::{Path, PathBuf};
use ini;
use failure::Backtrace;
use block_modes::BlockModeError;
use failure::Fail;
use derive_more::Display;
use std::borrow::Cow;

#[derive(Debug, Fail, Display)]
pub enum Error {
    #[display(fmt = "Failed to deserialize: {}", _0)]
    Deserialization(#[cause] serde_json::error::Error),
    #[display(fmt = "{}: {}", "_1.display()", _0)]
    Io(#[cause] io::Error, PathBuf, Backtrace),
    #[display(fmt = "Internal IO Error (please submit a bug report with the backtrace): {}", _0)]
    IoInternal(#[cause] io::Error, Backtrace),
    #[display(fmt = "Decryption failed")]
    BlockMode(BlockModeError, Backtrace),
    #[display(fmt = "Error parsing the INI file: {}", _0)]
    Ini(#[cause] ini::ini::Error, Backtrace),
    #[display(fmt = "Key derivation error: {}", _0)]
    Crypto(String, Backtrace),
    #[display(fmt = "Invalid keyblob {}: {}.", _1, _0)]
    MacError(cmac::crypto_mac::MacError, usize, Backtrace),
    #[display(fmt = "Invalid PFS0: {}.", _0)]
    InvalidPfs0(&'static str, Backtrace),
    #[display(fmt = "Failed to convert filename to UTF8: {}.", _0)]
    Utf8Conversion(String, #[cause] Utf8Error, Backtrace),
    #[display(fmt = "Can't handles symlinks in romfs: {}", "_0.display()")]
    RomFsSymlink(PathBuf, Backtrace),
    #[display(fmt = "Unknown file type at {}", "_0.display()")]
    RomFsFiletype(PathBuf, Backtrace),
    #[display(fmt = "Invalid NPDM value for field {}", "_0")]
    InvalidNpdmValue(Cow<'static, str>, Backtrace),
    #[display(fmt = "Failed to serialize NPDM.")]
    BincodeError(#[cause] Box<bincode::ErrorKind>, Backtrace),
}

impl Error {
    fn with_path<T: AsRef<Path>>(self, path: T) -> Error {
        if let Error::IoInternal(err, backtrace) = self {
            Error::Io(err, path.as_ref().to_owned(), backtrace)
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
        Error::IoInternal(err, Backtrace::new())
    }
}

impl<T: AsRef<Path>> From<(io::Error, T)> for Error {
    fn from((err, path): (io::Error, T)) -> Error {
        Error::Io(err, path.as_ref().to_owned(), Backtrace::new())
    }
}

impl From<ini::ini::Error> for Error {
    fn from(err: ini::ini::Error) -> Error {
        Error::Ini(err, Backtrace::new())
    }
}

impl From<BlockModeError> for Error {
    fn from(err: BlockModeError) -> Error {
        Error::BlockMode(err, Backtrace::new())
    }
}

impl From<serde_json::error::Error> for Error {
    fn from(err: serde_json::error::Error) -> Error {
        Error::Deserialization(err)
    }
}

impl From<FromUtf8Error> for Error {
    fn from(err: FromUtf8Error) -> Error {
        // Why the heck does OsStr not have display()?
        Error::Utf8Conversion(String::from_utf8_lossy(err.as_bytes()).into_owned(), err.utf8_error(), Backtrace::new())
    }
}

impl From<(usize, cmac::crypto_mac::MacError)> for Error {
    fn from((id, err): (usize, cmac::crypto_mac::MacError)) -> Error {
        Error::MacError(err, id, Backtrace::new())
    }
}

impl From<Box<bincode::ErrorKind>> for Error {
    fn from(err: Box<bincode::ErrorKind>) -> Error {
        Error::BincodeError(err, Backtrace::new())
    }
}
