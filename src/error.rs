use std::io;
use std::string::FromUtf8Error;
use std::path::PathBuf;
use ini;
use failure::Backtrace;
use block_modes::BlockModeError;
use failure::Fail;

#[derive(Debug, Fail)]
pub enum Error {
    #[fail(display = "Error reading keys file: {}", _0)]
    Io(#[cause] io::Error, Backtrace),
    #[fail(display = "Decryption failed")]
    BlockMode(#[cause] BlockModeError, Backtrace),
    #[fail(display = "Error parsing the INI file: {}", _0)]
    Ini(#[cause] ini::ini::Error, Backtrace),
    #[fail(display = "Key derivation error: {}", _0)]
    Crypto(String, Backtrace),
    #[fail(display = "Missing key: {}. Make sure your keyfile is complete.", _0)]
    MissingKey(&'static str, Backtrace),
    #[fail(display = "Failed to parse NCA. Make sure your {} key is correct.", _0)]
    NcaParse(&'static str, Backtrace),
    #[fail(display = "Missing section {}.", _0)]
    MissingSection(usize, Backtrace),
    #[fail(display = "Invalid NCA: {}.", _0)]
    InvalidNca(&'static str, Backtrace),
    #[fail(display = "Invalid PFS0: {}.", _0)]
    InvalidPfs0(&'static str, Backtrace),
    #[fail(display = "Failed to convert filename to UTF8: {}.", _0)]
    Utf8Conversion(PathBuf, Backtrace),
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
        Error::Utf8Conversion(PathBuf::from(err.into_bytes()), Backtrace::new())
    }
}
