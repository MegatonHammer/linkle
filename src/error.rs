use std::io;
use std::path::{Path, PathBuf};
use ini;
use failure::Backtrace;
use block_modes::BlockModeError;
use failure::Fail;
use derive_more::Display;

#[derive(Debug, Fail, Display)]
pub enum Error {
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
    #[display(fmt = "Can't handles symlinks in romfs: {}", "_0.display()")]
    RomFsSymlink(PathBuf, Backtrace),
    #[display(fmt = "Unknown file type at {}", "_0.display()")]
    RomFsFiletype(PathBuf, Backtrace),
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
