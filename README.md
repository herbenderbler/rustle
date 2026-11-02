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
[fflock](https://github.com/herbenderbler/fflock), where it replaced the
`btleplug` + `tokio` + `libdbus` dependency tree with a receive-only scanner
that could be audited end to end. It is now maintained here as a standalone
library.

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

Every module keeps its pure layer separate from its socket layer, so the
protocol logic is unit-tested on any OS without a radio, and the `GattClient`
is tested against an in-memory transport.

## Platform support

The socket layers are Linux-only (`#[cfg(target_os = "linux")]`) and need
`CAP_NET_RAW` (or root) plus a controller that `bluetoothd` is not managing —
a userland stack holding the adapter answers the scan commands with *Command
Disallowed*.

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

`ScanParams::default()` is **passive**: `scan_type = 0x00`, so the controller
only listens. An **active** scan (`ScanParams::new(ScanType::Active, …)`)
makes the controller answer scannable advertisements with a `SCAN_REQ`, which
carries the controller's own address — `OwnAddrType` chooses the public
hardware address or a random address you have programmed beforehand. Run an
active scan's reports through a `scan_merge::ScanMerger` so each device's
primary advertisement and its `SCAN_RSP` are seen as one.

`HciScanner::start` prefers the Bluetooth 5 extended scan commands (so
extended-advertising PDUs are reported too) and falls back to the legacy
commands on a controller that rejects them; the returned `ScanStart` says
which took and why. Dropping the scanner stops the scan and closes the socket.

## GATT

```rust,no_run
use rustle::client::GattClient;
use rustle::l2cap::{L2capAtt, SecurityLevel};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let link = L2capAtt::connect(None, false, "AA:BB:CC:DD:EE:FF", true, SecurityLevel::Low, 5)?;
    let mut client = GattClient::new(link);
    client.exchange_mtu(247)?;
    for service in client.discover_all()? {
        println!("{} ({} characteristics)",
            service.service.uuid, service.characteristics.len());
    }
    Ok(())
}
```

`GattClient` is generic over the `AttIo` trait (one `send`/`recv` per ATT
PDU), so any framed transport works — the Linux `L2capAtt`, a mock, or your
own.

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
