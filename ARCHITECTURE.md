# rustle architecture

This document explains how rustle is put together and why. The
[README](README.md) gives the overview. [USAGE.md](USAGE.md) shows how to
use each part, and [INSTALL.md](INSTALL.md) covers setup.

## Design

rustle uses only the Rust standard library. It has no C libraries, no
D-Bus, no async runtime and no other crates. The private `sys`
module drives the kernel's BlueZ sockets through a handful of `extern "C"`
calls into libc. Everything above it is plain Rust.

This keeps all the code between a radio packet and your program in one
small crate that can be read in full. The parsers that read bytes off the
radio are fuzzed, and they never panic on malformed input.

## Modules

| Module | Pure layer (any OS) | Linux socket layer |
|---|---|---|
| `hci` | HCI event framing, HCI command framing, and decoding of LE Advertising Reports (legacy and extended) and their advertising data | |
| `scan` | Scan parameters and their wire encodings | `HciScanner`, a raw HCI socket set up for passive or active scanning. It uses extended scanning where the controller supports it and falls back to legacy scanning. |
| `scan_merge` | Pairs a scannable advertisement with its scan response | |
| `scan_filter` | `ScanFilter`, which matches decoded advertisements against service UUIDs, a name prefix and manufacturer IDs | |
| `adapter` | Decoding of `hci_dev_info` and adapter selection | `enumerate()` and `info()`, built on `HCIGETDEVLIST` and `HCIGETDEVINFO` |
| `att` | ATT PDU encoder and decoder | |
| `gatt` | GATT declarations, characteristic properties and CCCD values | |
| `client` | `GattClient`, generic over an `AttIo` transport. It handles MTU exchange, discovery, reads, long reads, writes with and without a response, and notifications. | |
| `l2cap` | Address helpers and `SecurityLevel` | `L2capAtt`, a connected L2CAP ATT channel that implements `AttIo` |
| `conn` | Codecs for Read RSSI and the connection list | `read_rssi()` reads the RSSI of an open LE connection. `connections()` lists the connections an adapter carries. |
| `mgmt` | Codecs for management commands and replies | `end_discovery()` ends the device discovery the kernel thinks an active scan started |

## Pure and socket layers

Each module keeps its pure layer apart from its socket layer. The pure
layer only encodes and decodes bytes. It runs on any OS, so the protocol
logic has unit tests that need no radio. `GattClient` is generic over the
`AttIo` trait, and its tests run against a mock transport held in memory.

The socket layers exist only on Linux, behind
`#[cfg(target_os = "linux")]`. On other systems the socket types are still
declared, but they cannot be created. `HciScanner::open`,
`L2capAtt::connect` and `adapter::enumerate` return an "unsupported" error
there. Code that uses them compiles everywhere and reaches hardware only on
Linux.

## How the scanner shares the adapter

The scanner programs the controller directly. It does not tell the kernel
or `bluetoothd`, and it turns off any scan already running on the
controller. For this reason it should run on an adapter that nothing else
scans on. You can stop `bluetoothd` or give rustle an adapter of its own.

Active scans also need `CAP_NET_ADMIN`. The kernel treats an active scan as
the start of a device discovery. While that discovery runs, the kernel
refuses new ones and makes no LE connections on the adapter. Through the
kernel's management interface, the scanner ends any discovery already in
progress before an active scan starts, and the one the scan started when
it stops.

[INSTALL.md](INSTALL.md) explains the permissions, how to free the adapter
and how to recover a stuck discovery.

## Testing

`cargo test` runs the unit tests, the doctests and a parser harness. The
code blocks in USAGE.md are compiled as doctests, so the guide cannot drift
from the API.

The harness in `tests/parser_no_panic.rs` feeds every public parser a
large mix of random and mutated bytes. It uses a fixed seed, so a failure
can be reproduced. It needs only the stable toolchain and runs on every CI
build.

`fuzz/` holds `cargo-fuzz` targets for the HCI, advertising data and ATT
parsers. It is a separate
workspace that needs nightly Rust. CI does not fuzz, but every CI run
type-checks the targets on stable, so a parser change that breaks one
fails CI. See [fuzz/README.md](fuzz/README.md).

CI builds and tests on Linux and macOS. The macOS job proves that the
stubs for other systems compile and that the pure layer passes its tests
there.

## Minimum supported Rust version

rustle supports Rust 1.88 and newer, and a CI job checks that version.
Since rustle has no dependencies, no dependency can force a newer one.

## History

rustle began as the BLE stack inside
[fflock](https://github.com/herbenderbler/fflock). There it replaced an
external BLE stack, along with its async runtime and D-Bus bindings. The
replacement was a scanner that only receives and could be audited from end
to end. rustle is now maintained here as a standalone library.
