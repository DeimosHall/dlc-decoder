# dlc-decrypter

A simple library to decode dlc files to a readable format.

## Usage

Add `dlc_decrypter` as a dependency in `Cargo.toml`:

```toml
[dependencies]
dlc-decoder = "0.2.2"
```

Use the `dlc_decoder::DlcDecoder' to decrypt a .dlc file or datapackage:

```rust
extern crate dlc_decrypter;

use dlc_decrypter::DlcDecoder;
use std::env;

fn main() {
    let decoder = DlcDecoder::new();

    for arg in env::args().skip(1) {
        let dlc = decoder.from_file(arg);

        println!("DLC: {:?}", dlc);
    }
}

```

## Thanks

* [Bubblepoint](https://github.com/Bubblepoint) for creating and maintaing the crate.
* [Robert Sch&uuml;tte](https://github.com/Roba1993) for doing a great refactoring.

## License

Distributed under the [MIT License](LICENSE).
