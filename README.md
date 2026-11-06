<p align="center">
  <img src="assets/logo.png" alt="rustle logo" width="360">
</p>

# rustle

A dependency-free Bluetooth Low Energy stack for Linux hosts: raw-HCI
scanning, advertisement parsing, and an ATT/GATT client over L2CAP.

Everything is plain `std`. There are no C libraries, no D-Bus, no async
runtime and no third-party crates: the kernel's BlueZ sockets are driven
directly through a handful of `extern "C"` libc calls. The byte parsers that
face the radio are fuzzed (`fuzz/`) and never panic on malformed input.

rustle began life as the in-house BLE stack of
[fflock](https://github.com/herbenderbler/fflock), where it replaced an
external BLE stack, together with its async runtime and D-Bus bindings, with
a receive-only scanner that could be audited end to end. It is now maintained
here as a standalone library.

## Documentation

- [INSTALL.md](INSTALL.md): toolchain, adding the crate to a project,
  socket permissions and freeing the adapter from `bluetoothd`.
- [USAGE.md](USAGE.md): a walk through scanning, filtering, connecting,
  GATT reads and writes, notifications and testing without a radio.
- Examples: `examples/scan.rs` lists nearby devices,
  `examples/battery.rs` connects to one and reads its battery level, and
  `examples/probe.rs` connects to one and runs the discovery, RSSI,
  notification and security checks from USAGE.md.
- API reference: `cargo doc --open`.

## What's in the box

| Module | Pure (any OS) | Linux socket layer |
|---|---|---|
| `hci` | HCI event framing, LE Advertising Report (legacy + extended) and AD-structure decoding, HCI command framing | — |
| `scan` | scan parameters and their wire encodings | `HciScanner`: a raw HCI socket programmed for passive or active LE scanning, extended-scan with legacy fallback |
| `scan_merge` | pairs a scannable advertisement with its `SCAN_RSP` | — |
| `scan_filter` | `ScanFilter`: client-side matching of decoded advertisements against service UUIDs, a name prefix and manufacturer IDs | — |
| `adapter` | `hci_dev_info` decoding, adapter selection | `enumerate()`: `HCIGETDEVLIST` / `HCIGETDEVINFO` |
| `att` | ATT PDU encoder / decoder | — |
| `gatt` | GATT declarations, characteristic properties, CCCD values | — |
| `client` | `GattClient`, generic over an `AttIo` transport (MTU exchange, discovery, read / read-long / write with and without response, notifications) | — |
| `l2cap` | address helpers, `SecurityLevel` | `L2capAtt`: a connected L2CAP ATT channel implementing `AttIo` |
| `conn` | Read RSSI and connection-list codecs | `read_rssi()` and `connections()`: RSSI of an established LE connection, and the connections an adapter currently carries |

Every module keeps its pure layer separate from its socket layer, so the
protocol logic is unit-tested on any OS without a radio, and the `GattClient`
is tested against an in-memory transport.

## Platform support

The socket layers are Linux-only (`#[cfg(target_os = "linux")]`) and need
`CAP_NET_RAW` (or root). The scanner programs the controller directly,
without telling the kernel or `bluetoothd`, and turns off any scan already
running on it. Run it on an adapter nothing else scans on: stop
`bluetoothd`, or give rustle an adapter of its own.
[INSTALL.md](INSTALL.md) explains what goes wrong otherwise.

On other platforms the crate still builds and the socket types still exist,
but they cannot be constructed: `HciScanner::open`, `L2capAtt::connect` and
`adapter::enumerate` return an "unsupported" error. Platform-generic code
therefore compiles everywhere; only the Linux build can talk to hardware.

## Scanning

```rust,no_run
use rustle::hci::parse_hci_packet;
use rustle::scan::{HciScanner, ScanParams};
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // hci0, with a 1 s receive timeout so the loop can check a shutdown flag.
    let mut scanner = HciScanner::open(0, Duration::from_secs(1))?;
    // The default is a passive scan: the controller listens and transmits nothing.
    let start = scanner.start(ScanParams::default())?;
    println!("scanning in {:?} mode", start.mode);

    let mut buf = [0u8; 512];
    loop {
        match scanner.read(&mut buf) {
            Ok(n) => {
                for report in parse_hci_packet(&buf[..n]) {
                    println!("{} rssi={:?} name={:?}",
                        report.address, report.rssi, report.ad.local_name);
                }
            }
            // Receive timeout / signal: nothing yet.
            Err(e) if matches!(e.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted) => continue,
            Err(e) => return Err(e.into()),
        }
    }
}
```

`ScanParams::default()` is a passive scan: the controller only listens.
`HciScanner::start` prefers the Bluetooth 5 extended scan commands and
falls back to the legacy ones on a controller that rejects them.
`ScanParams::phys` selects the PHYs an extended scan listens on: LE 1M,
the long range LE Coded PHY, or both. A Coded-only scan has no legacy
equivalent, so it fails rather than falling back. Dropping the scanner
stops the scan and closes the socket. [USAGE.md](USAGE.md) covers active
scans, scan response merging and filtering.

## GATT

`l2cap::L2capAtt` opens an ATT channel to a peer, and `client::GattClient`
drives MTU exchange, discovery, reads, writes and notifications over it.
The client is generic over the `AttIo` trait, so a mock transport serves
for tests. [USAGE.md](USAGE.md) has the full walk, from connect to
notification loop.

## Fuzzing

`fuzz/` holds `cargo-fuzz` targets for the HCI packet, AD-structure and ATT
PDU parsers. It is its own nightly-only workspace; see `fuzz/README.md`. The
stable-toolchain `tests/parser_no_panic.rs` harness feeds the same parsers a
large deterministic mix of random and mutated bytes on every CI run.

## Minimum supported Rust version

1.88, checked in CI. Only `std` is used, so bumping it is never forced by a
dependency.

## License

MIT OR Apache-2.0.
