//! A library to decode dlc files to a readable format.
//!
//! ## Usage
//! Add `dlc_decrypter` as a dependency in `Cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! dlc-decrypter = "0.3.0"
//! ```
//!
//! Use the `dlc_decoder::DlcDecoder` to decrypt a .dlc file or datapackage:
//!
//! ```rust
//! extern crate dlc_decoder;
//!
//! fn main() {
//!     let decoder = dlc_decoder::DlcDecoder::new();
//!     for arg in std::env::args().skip(1) {
//!         let dlc = decoder.from_file(arg);
//!         println!("DLC: {:?}", dlc);
//!     }
//! }
//! ```

// Programmer Information
// DLC = Download Link Container. It's often used for downloading.
// Step 1: Split the file in 2 parts. Part 1 is the data. Part 2 are the last 88 chars from the file are the data_key.
// Step 2: Send the data_key to the service.jdownloader.org (with an app specific id) to get an other key.
// Step 3: Remove the surrounding <rc></rc> from the returned key and base64 decode the value.
// Step 4: AES/CBC decrypt the data from Step 3 with an app specific key/iv.
// Step 5: Base64 decode the data part from Step 1.
// Step 6: AES/CBC decrypt the data from Step 5 with the result from Step 4 as key/iv.
// Step 7: Base64 decode the result from Step 6. Now you have an XML.
// Step 8: The values in the xml are Base64 encoded. So you have to decode the values.

pub mod error;
pub use error::{Error, Result};

macro_rules! bail {
    ($($arg:tt)*) => {
        return Err($crate::error::Error::new($crate::error::ErrorKind::Msg(format!($($arg)*))))
    };
}

extern crate base64;
extern crate crypto;
extern crate regex;
extern crate reqwest;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use crypto::buffer::{ReadBuffer, WriteBuffer};
use crypto::{aes, blockmodes, buffer};
use regex::Regex;
use reqwest::blocking::Client;
use reqwest::header;
use std::fs::File;
use std::io::Read;
use std::ops::Deref;
use std::str;

/// Link struct which holds the data of a file and the link.
///
/// Fields:
///
/// - url: where to find the corrsponding file online
/// - name: name of the corrsponding file
/// - size: of the file
#[derive(Debug, Clone)]
pub struct DlcLink {
    pub url: String,
    pub name: String,
    pub size: String,
}

impl DlcLink {
    fn new() -> DlcLink {
        DlcLink {
            url: String::new(),
            name: String::new(),
            size: String::new(),
        }
    }
}

/// The readable result of an .dlc file.
///
/// It holds the information about:
///
/// - name: of the .dlc package
/// - password: ??? pwd to encrypt ???
/// - files: the corresponding files of the package
#[derive(Debug, Clone)]
pub struct DlcPackage {
    pub name: String,
    pub password: String,
    pub files: Vec<DlcLink>,
}

impl DlcPackage {
    fn new() -> DlcPackage {
        DlcPackage {
            name: String::new(),
            password: String::new(),
            files: Vec::new(),
        }
    }
}

/// Struct to decode the .dlc file or data into an readable format.
#[derive(Debug)]
pub struct DlcDecoder {
    jd_app_name: String,
    jd_decryption_key: Vec<u8>,
    jd_decryption_iv: Vec<u8>,
}

impl DlcDecoder {
    /// Create a new DlcDecoder with a standard login to jdownloader.
    pub fn new() -> DlcDecoder {
        DlcDecoder {
            jd_app_name: "pylo".to_string(),
            jd_decryption_key: b"cb99b5cbc24db398".to_vec(),
            jd_decryption_iv: b"9bc24cb995cb8db3".to_vec(),
        }
    }

    /// Set a different JDownloader credential to login, than the default ones.
    pub fn set_credentials<S, D>(&mut self, name: S, key: D, iv: D)
    where
        S: Into<String>,
        D: Into<Vec<u8>>,
    {
        self.jd_app_name = name.into();
        self.jd_decryption_key = key.into();
        self.jd_decryption_iv = iv.into();
    }

    /// Decrypt a specified .dlc file
    pub fn from_file<P: Into<String>>(&self, path: P) -> Result<DlcPackage> {
        let mut file = File::open(path.into())?;
        let mut data = Vec::new();
        file.read_to_end(&mut data)?;

        // return the decrypted dlc package
        self.from_data(&data)
    }

    /// Decrypt the content of a .dlc file.
    pub fn from_data(&self, data: &[u8]) -> Result<DlcPackage> {
        let data = self.decrypt_dlc(data)?;
        let mut dlc = self.parse_header(&data)?;
        self.parse_body(&mut dlc, &data)?;
        Ok(dlc)
    }

    /******************* Private Functions *****************/
    /// Decrypt the .dlc data to a plain String
    fn decrypt_dlc(&self, data: &[u8]) -> Result<String> {
        // check if the file is to short to get the key out of it
        if data.len() <= 88 {
            bail!("Corrupted data");
        };

        let (data, key) = data.split_at(data.len() - 88);

        // get decrypten key
        let key = self.get_jd_decryption_key(key)?;

        // decrypt the key
        let key =
            DlcDecoder::decrypt_raw_data(&key, &self.jd_decryption_key, &self.jd_decryption_iv)?;

        // decrypt the content
        let data = BASE64.decode(data)?;
        let data = DlcDecoder::decrypt_raw_data(&data, key.deref(), key.deref())?;

        // format to text
        let data = BASE64.decode(&data)?;
        let data = String::from_utf8(data)?;
        Ok(data)
    }

    /// Decrypt data by the given key and iv.
    fn decrypt_raw_data(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
        // create decryptor and set keys & values
        let mut decryptor =
            aes_cbc_decryptor(aes::KeySize::KeySize128, key, iv, blockmodes::NoPadding);

        // create the buffer objects
        let mut buffer = [0; 4096];
        let mut read_buffer = buffer::RefReadBuffer::new(data);
        let mut writ_buffer = buffer::RefWriteBuffer::new(&mut buffer);
        let mut result = Vec::new();

        loop {
            // decrypt the buffer
            if decryptor
                .decrypt(&mut read_buffer, &mut writ_buffer, true)
                .is_err()
            {
                bail!("Can't decrypt");
            }

            // when the write_buffer is empty, the decryption is finished
            if writ_buffer.is_empty() {
                break;
            }

            // add the encrypted data to the result
            result.extend_from_slice(writ_buffer.take_read_buffer().take_remaining());
        }

        // remove tailing zeros
        result.retain(|x| *x != 0);
        Ok(result)
    }

    /// Download the decryption key for the .dlc container
    fn get_jd_decryption_key(&self, key: &[u8]) -> Result<Vec<u8>> {
        // build the request url
        let url = format!(
            "http://service.jdownloader.org/dlcrypt/service.php?srcType=dlc&destType={}&data={}",
            &self.jd_app_name,
            str::from_utf8(key)?
        );

        // build up the request
        let res = Client::new()
            .get(&url)
            .header(header::CONNECTION, "close")
            .header(
                header::USER_AGENT,
                "Mozilla/5.3 (Windows; U; Windows NT 5.1; de; rv:1.8.1.6) Gecko/2232 Firefox/3.0.0.R",
            )
            .send()?;
        let key = res.bytes()?.to_vec();
        if key.len() != 33 {
            bail!("Unexpected Error");
        }

        // remove <rc> and </rc>
        let key = BASE64.decode(&key[4..28])?;
        Ok(key)
    }

    /// Extract the header data
    fn parse_header(&self, data: &str) -> Result<DlcPackage> {
        let mut dlc = DlcPackage::new();

        // get the package information
        let re = Regex::new(r"<package ([^>]*)")?;
        let pck = re
            .find(&data)
            .ok_or_else(|| Error::from("Can't find package in data"))?
            .as_str();

        // extract the name
        let re = Regex::new(r#"name="([^"]*)"#)?;
        let t = re
            .find(&pck)
            .ok_or_else(|| Error::from("Can't find name in data"))?;
        dlc.name = String::from_utf8(BASE64.decode(&pck[t.start() + 6..t.end()])?)?;

        // extract the password - optional
        let re = Regex::new(r#"passwords="([^"]*)"#)?;
        if let Some(t) = re.find(&pck) {
            dlc.password = String::from_utf8(BASE64.decode(&pck[t.start() + 11..t.end()])?)?;
        }
        Ok(dlc)
    }

    /// Edxtract the body data
    fn parse_body(&self, dlc: &mut DlcPackage, data: &str) -> Result<()> {
        // split at each file attribute
        let mut files_xml: Vec<&str> = data.split("<file>").collect();
        // remove the first one, becuase this is the header
        files_xml.remove(0);

        // loop over all files and parse them
        for f in files_xml {
            let details: Vec<&str> = f.split("<").collect();
            let mut link = DlcLink::new();
            for d in details {
                if d.len() > 3 && d[..3] == "url".to_string() {
                    let buf = self.file_details(d.to_string(), 4);
                    link.url = buf;
                } else if d.len() > 8 && d[..8] == "filename".to_string() {
                    let buf = self.file_details(d.to_string(), 9);
                    link.name = buf;
                } else if d.len() > 4 && d[..4] == "size".to_string() {
                    let buf = self.file_details(d.to_string(), 5);
                    link.size = buf;
                }
            }
            dlc.files.push(link);
        }
        Ok(())
    }

    /// Get the files details
    fn file_details(&self, data: String, pos: usize) -> String {
        // try to decode the data
        let buf: String = match BASE64.decode(&data[pos..]) {
            Ok(x) => match String::from_utf8(x) {
                Ok(x) => x,
                Err(_) => data[pos..].to_string(),
            },
            Err(_) => data[pos..].to_string(),
        };
        buf
    }
}

// use only for crypto
use crypto::aes::KeySize;
use crypto::aessafe;
use crypto::blockmodes::{CbcDecryptor, PaddingProcessor};
use crypto::symmetriccipher::Decryptor;

/// Reimplementation of the aes cbc decryptor function from Rust-Crypto.
///
/// This function always use the software decryption insted of the hardware one.
/// This can have a samll speed impact. But the hardware decryption fails for
/// musl-docker builds and is shutting down any programm without a warning.
///
/// To garuntee the stability of the dlc-decryptor, we use the software decryption.
fn aes_cbc_decryptor<X: PaddingProcessor + Send + 'static>(
    key_size: KeySize,
    key: &[u8],
    iv: &[u8],
    padding: X,
) -> Box<dyn Decryptor + 'static> {
    match key_size {
        KeySize::KeySize128 => {
            let aes_dec = aessafe::AesSafe128Decryptor::new(key);
            let dec = Box::new(CbcDecryptor::new(aes_dec, padding, iv.to_vec()));
            dec as Box<dyn Decryptor + 'static>
        }
        KeySize::KeySize192 => {
            let aes_dec = aessafe::AesSafe192Decryptor::new(key);
            let dec = Box::new(CbcDecryptor::new(aes_dec, padding, iv.to_vec()));
            dec as Box<dyn Decryptor + 'static>
        }
        KeySize::KeySize256 => {
            let aes_dec = aessafe::AesSafe256Decryptor::new(key);
            let dec = Box::new(CbcDecryptor::new(aes_dec, padding, iv.to_vec()));
            dec as Box<dyn Decryptor + 'static>
        }
    }
}
