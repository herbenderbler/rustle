<p align="center">
  <img src="assets/logo.png" alt="rustle logo" width="360">
</p>

# rustle

rustle is a Bluetooth Low Energy (BLE) library for Linux, written in plain
Rust. It scans for nearby devices, decodes their advertisements, and talks
to them over GATT.

rustle has no dependencies. It needs no C libraries, no D-Bus and no async
runtime. It talks to the kernel's Bluetooth sockets directly.

## Features

- Passive and active scanning, including Bluetooth 5 extended advertising.
- Decoding of names, service UUIDs, manufacturer data and other
  advertising data.
- Filtering of scan results by service, name prefix or manufacturer.
- A GATT client for discovery, reads, writes and notifications.
- Fuzzed parsers that never panic on malformed input.

## Quick start

rustle is not on crates.io. Add it as a Git dependency and pin a commit:

```toml
[dependencies]
rustle = { git = "https://github.com/herbenderbler/rustle", rev = "<commit>" }
```

This program lists the devices it hears on `hci0`:

```rust,no_run
use rustle::hci::parse_hci_packet;
use rustle::scan::{HciScanner, ScanParams};
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // A zero timeout makes each read wait until a packet arrives.
    let mut scanner = HciScanner::open(0, Duration::ZERO)?;
    // The default scan is passive. The radio listens and sends nothing.
    scanner.start(ScanParams::default())?;

    let mut buf = [0u8; 512];
    loop {
        let n = scanner.read(&mut buf)?;
        for report in parse_hci_packet(&buf[..n]) {
            println!("{} {:?} {:?}", report.address, report.rssi, report.ad.local_name);
        }
    }
}
```

The program needs the `CAP_NET_RAW` capability, or root. It works best on
an adapter that `bluetoothd` is not using. [INSTALL.md](INSTALL.md)
explains both and shows how to run the bundled examples.

## Requirements

- Rust 1.88 or newer.
- Linux with BlueZ support in the kernel.
- A Bluetooth controller that supports Low Energy.

The crate also builds on other systems, but only Linux can reach the radio.

## Documentation

The walkthrough is published at <https://herbenderbler.github.io/rustle/>.

- [INSTALL.md](INSTALL.md) covers setup, permissions and the adapter.
- [USAGE.md](USAGE.md) is a guide to scanning, connecting and GATT.
- [ARCHITECTURE.md](ARCHITECTURE.md) describes the modules, the design
  and the tests.
- [examples/](examples) holds three small programs. `scan` lists nearby
  devices, `battery` reads a device's battery level, and `probe` runs a
  set of connection checks.
- `cargo doc --open` builds the API reference.

## License

rustle is licensed under either the [MIT license](LICENSE-MIT) or the
[Apache License 2.0](LICENSE-APACHE), at your option.
