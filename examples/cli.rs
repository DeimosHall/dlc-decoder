extern crate dlc_decoder;

use dlc_decoder::DlcDecoder;
use std::env;

fn main() {
    let decoder = DlcDecoder::new();

    for arg in env::args().skip(1) {
        let dlc_package = decoder.from_file(arg);
        dbg!(dlc_package.unwrap());
    }
}
