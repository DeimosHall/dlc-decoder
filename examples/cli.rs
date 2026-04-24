extern crate dlc_decoder;

use dlc_decoder::DlcDecoder;
use std::env;

fn main() {
    let decoder = DlcDecoder::new();

    for arg in env::args().skip(1) {
        let dlc = decoder.from_file(arg);

        println!("DLC: {:?}", dlc);
    }
}
