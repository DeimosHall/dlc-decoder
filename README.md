# dlc-decrypter

A simple library to decode dlc files to a readable format.

## Usage

Add `dlc_decoder` as a dependency in `Cargo.toml`:

```toml
[dependencies]
dlc-decoder = "0.3.0"
```

Use the `dlc_decoder::DlcDecoder' to decrypt a .dlc file or datapackage:

```rust
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
```

Run the example of this repository with:

```bash
cargo run --example cli -- path/to/your/file.dlc
```

## Thanks

* [Bubblepoint](https://github.com/Bubblepoint) for creating and maintaing the crate.
* [Robert Sch&uuml;tte](https://github.com/Roba1993) for doing a great refactoring.

## License

Distributed under the [MIT License](LICENSE).
