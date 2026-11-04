# dlc-decoder

A simple library to decode dlc files to a readable format.

## Usage

Add `dlc_decoder` as a dependency in `Cargo.toml`:

```toml
[dependencies]
dlc-decoder = "0.3.2"
```

Use the `dlc_decoder::DlcDecoder' to decrypt a .dlc file or datapackage:

```rust
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
```

Run the example of this repository with:

```bash
cargo run --example cli -- path/to/your/file.dlc
```

## GUI

There's a Linux client for this crate. [Find it on Flathub](https://flathub.org/en/apps/dev.deimoshall.DecryptIt).

<p align="center">
  <img src="https://raw.githubusercontent.com/DeimosHall/decrypt-it/refs/heads/main/data/resources/screenshots/0.png" style="vertical-align: middle" />
</p>

## Credits

Maintained by [Deimos Hall](https://deimoshall.dev/).

**Thanks**

* [Bubblepoint](https://github.com/Bubblepoint) for creating the crate.
* [Robert Sch&uuml;tte](https://github.com/Roba1993) for doing a great refactoring.

## License

Distributed under the [MIT License](LICENSE).
