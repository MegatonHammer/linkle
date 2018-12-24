use std::io;
use std::str::Utf8Error;
use std::string::FromUtf8Error;
use std::path::PathBuf;
use ini;
use failure::Backtrace;
use block_modes::BlockModeError;
use failure::Fail;
use derive_more::Display;

#[derive(Debug, Fail, Display)]
pub enum Error {
    #[display(fmt = "Error reading keys file: {}", _0)]
    Io(#[cause] io::Error, Backtrace),
    #[display(fmt = "Decryption failed")]
    BlockMode(BlockModeError, Backtrace),
    #[display(fmt = "Error parsing the INI file: {}", _0)]
    Ini(#[cause] ini::ini::Error, Backtrace),
    #[display(fmt = "Key derivation error: {}", _0)]
    Crypto(String, Backtrace),
    #[display(fmt = "Missing key: {}. Make sure your keyfile is complete.", _0)]
    MissingKey(&'static str, Backtrace),
    #[display(fmt = "Failed to parse NCA. Make sure your {} key is correct.", _0)]
    NcaParse(&'static str, Backtrace),
    #[display(fmt = "Missing section {}.", _0)]
    MissingSection(usize, Backtrace),
    #[display(fmt = "Invalid NCA: {}.", _0)]
    InvalidNca(&'static str, Backtrace),
    #[display(fmt = "Invalid PFS0: {}.", _0)]
    InvalidPfs0(&'static str, Backtrace),
    #[display(fmt = "Failed to convert filename to UTF8: {}.", _0)]
    Utf8Conversion(String, #[cause] Utf8Error, Backtrace),
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Error {
        Error::Io(err, Backtrace::new())
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

impl From<FromUtf8Error> for Error {
    fn from(err: FromUtf8Error) -> Error {
        // Why the heck does OsStr not have display()?
        Error::Utf8Conversion(String::from_utf8_lossy(err.as_bytes()).into_owned(), err.utf8_error(), Backtrace::new())
    }
}
