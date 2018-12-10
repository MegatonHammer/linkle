use std::io;
use ini;
use failure::Backtrace;
use openssl::error::ErrorStack;

#[derive(Debug, Fail)]
pub enum Error {
    #[fail(display = "Error reading keys file: {}", _0)]
    Io(io::Error, Backtrace),
    #[fail(display = "Key derivation error: {}", _0)]
    Openssl(ErrorStack, Backtrace),
    #[fail(display = "Error parsing the INI file: {}", _0)]
    Ini(ini::ini::Error, Backtrace),
    #[fail(display = "Key derivation error: {}", _0)]
    Crypto(String, Backtrace),
}

impl From<ErrorStack> for Error {
    fn from(err: ErrorStack) -> Error {
        Error::Openssl(err, Backtrace::new())
    }
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
