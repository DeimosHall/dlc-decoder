use std::error::Error as StdError;
use std::fmt;

#[derive(Debug)]
pub enum ErrorKind {
    Msg(String),
    Io(std::io::Error),
    Utf8(std::str::Utf8Error),
    FromUtf8(std::string::FromUtf8Error),
    Reqwest(reqwest::Error),
    Regex(regex::Error),
    Base64(base64::DecodeError),
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorKind::Msg(s) => write!(f, "{}", s),
            ErrorKind::Io(e) => write!(f, "IO error: {}", e),
            ErrorKind::Utf8(e) => write!(f, "UTF-8 error: {}", e),
            ErrorKind::FromUtf8(e) => write!(f, "FromUTF-8 error: {}", e),
            ErrorKind::Reqwest(e) => write!(f, "Reqwest error: {}", e),
            ErrorKind::Regex(e) => write!(f, "Regex error: {}", e),
            ErrorKind::Base64(e) => write!(f, "Base64 error: {}", e),
        }
    }
}

impl StdError for ErrorKind {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            ErrorKind::Msg(_) => None,
            ErrorKind::Io(e) => Some(e),
            ErrorKind::Utf8(e) => Some(e),
            ErrorKind::FromUtf8(e) => Some(e),
            ErrorKind::Reqwest(e) => Some(e),
            ErrorKind::Regex(e) => Some(e),
            ErrorKind::Base64(e) => Some(e),
        }
    }
}

#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
}

impl Error {
    pub fn new(kind: ErrorKind) -> Self {
        Error { kind }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.kind.fmt(f)
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.kind.source()
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::new(ErrorKind::Io(e))
    }
}

impl From<&str> for Error {
    fn from(e: &str) -> Self {
        Error::new(ErrorKind::Msg(e.to_string()))
    }
}

impl From<String> for Error {
    fn from(e: String) -> Self {
        Error::new(ErrorKind::Msg(e))
    }
}

impl From<std::str::Utf8Error> for Error {
    fn from(e: std::str::Utf8Error) -> Self {
        Error::new(ErrorKind::Utf8(e))
    }
}

impl From<std::string::FromUtf8Error> for Error {
    fn from(e: std::string::FromUtf8Error) -> Self {
        Error::new(ErrorKind::FromUtf8(e))
    }
}

impl From<reqwest::Error> for Error {
    fn from(e: reqwest::Error) -> Self {
        Error::new(ErrorKind::Reqwest(e))
    }
}

impl From<regex::Error> for Error {
    fn from(e: regex::Error) -> Self {
        Error::new(ErrorKind::Regex(e))
    }
}

impl From<base64::DecodeError> for Error {
    fn from(e: base64::DecodeError) -> Self {
        Error::new(ErrorKind::Base64(e))
    }
}

pub type Result<T> = std::result::Result<T, Error>;
