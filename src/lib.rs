//! A dependency-free Bluetooth Low Energy stack for Linux hosts: raw-HCI
//! scanning, advertisement parsing, and an ATT/GATT client over L2CAP.
//!
//! Everything is plain `std` — no C libraries, no D-Bus, no async runtime, and
//! no third-party crates. The kernel's BlueZ sockets are driven directly through
//! a handful of `extern "C"` libc calls, so the only code between an
//! attacker-controlled radio packet and your program is in this crate and is
//! fuzzed (see `fuzz/`).
//!
//! # Layering
//!
//! Every module splits into a **pure** layer, which is platform-independent and
//! unit-tested on any OS, and (where one is needed) a **Linux-only socket**
//! layer behind `#[cfg(target_os = "linux")]`. On other platforms the socket
//! types still exist but cannot be constructed — their constructors return an
//! "unsupported" error — so platform-generic code compiles everywhere.
//!
//! | Module | Pure | Linux socket |
//! |---|---|---|
//! | [`hci`] | HCI event framing, LE Advertising Report (legacy + extended) and AD-structure decoding, HCI command framing | — |
//! | [`scan`] | scan parameters and their wire encodings | [`scan::HciScanner`]: a raw HCI socket programmed for passive or active LE scanning |
//! | [`scan_merge`] | pairs a scannable advertisement with its `SCAN_RSP` | — |
//! | [`scan_filter`] | [`scan_filter::ScanFilter`]: client-side matching of decoded advertisements | — |
//! | [`adapter`] | `hci_dev_info` decoding, adapter selection | [`adapter::enumerate`]: `HCIGETDEVLIST` / `HCIGETDEVINFO` |
//! | [`att`] | ATT PDU encoder / decoder | — |
//! | [`gatt`] | GATT declarations, properties, CCCD values | — |
//! | [`client`] | [`client::GattClient`], generic over an [`client::AttIo`] transport | — |
//! | [`l2cap`] | address helpers, [`l2cap::SecurityLevel`] | [`l2cap::L2capAtt`]: a connected L2CAP ATT channel |
//! | [`conn`] | Read RSSI and connection-list codecs | [`conn::read_rssi`] and [`conn::connections`]: RSSI of an established LE connection, and the connections an adapter carries |
//!
//! # Scanning
//!
//! ```no_run
//! use rustle::hci::parse_hci_packet;
//! use rustle::scan::{HciScanner, ScanParams};
//! use std::time::Duration;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // hci0, with a 1 s receive timeout so the loop can check a shutdown flag.
//! let mut scanner = HciScanner::open(0, Duration::from_secs(1))?;
//! // The default is a passive scan: the controller listens and transmits nothing.
//! let start = scanner.start(ScanParams::default())?;
//! println!("scanning in {:?} mode", start.mode);
//!
//! let mut buf = [0u8; 512];
//! loop {
//!     match scanner.read(&mut buf) {
//!         Ok(n) => {
//!             for report in parse_hci_packet(&buf[..n]) {
//!                 println!("{} rssi={:?} name={:?}", report.address, report.rssi, report.ad.local_name);
//!             }
//!         }
//!         // Receive timeout / signal: nothing yet.
//!         Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted) => continue,
//!         Err(e) => return Err(e.into()),
//!     }
//! }
//! # }
//! ```
//!
//! An *active* scan (`ScanParams::new(ScanType::Active, OwnAddrType::Public)`)
//! makes the controller solicit `SCAN_RSP`s; run the reports through a
//! [`scan_merge::ScanMerger`] so each device's primary advertisement and
//! response are seen as one.
//!
//! # GATT
//!
//! ```no_run
//! use rustle::client::GattClient;
//! use rustle::l2cap::{L2capAtt, SecurityLevel};
//!
//! let link = L2capAtt::connect(None, false, "AA:BB:CC:DD:EE:FF", true, SecurityLevel::Low, 5)?;
//! let mut client = GattClient::new(link);
//! client.exchange_mtu(247)?;
//! for service in client.discover_all()? {
//!     println!("{} ({} characteristics)", service.service.uuid, service.characteristics.len());
//! }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! # Permissions
//!
//! The raw HCI and L2CAP sockets need `CAP_NET_RAW` (or root). A raw HCI
//! socket opens without it, but the kernel then refuses the scan commands,
//! which surfaces as [`scan::ScanError::Write`] with
//! [`std::io::ErrorKind::PermissionDenied`].
//!
//! An active scan also needs `CAP_NET_ADMIN`. The kernel reads an active scan
//! as the start of a device discovery that never ends, which blocks new
//! discoveries and the kernel's own LE connections on the adapter, so
//! [`scan::HciScanner`] ends it through [`mgmt`] around every active scan.
//! Without the capability, starting an active scan fails with
//! [`scan::ScanError::Discovery`].
//!
//! [`scan::HciScanner`] programs the controller directly, without telling the
//! kernel or `bluetoothd`, and turns off any scan already running on it,
//! including one the kernel runs for `bluetoothd`. After a passive scan, a
//! device discovery that was in progress never finishes. Run the scanner on
//! an adapter nothing else scans on: stop `bluetoothd`, or give rustle an
//! adapter of its own.

pub mod adapter;
pub mod att;
pub mod client;
pub mod conn;
pub mod gatt;
pub mod hci;
pub mod l2cap;
pub mod mgmt;
pub mod scan;
pub mod scan_filter;
pub mod scan_merge;

#[cfg(target_os = "linux")]
mod sys;

mod hci_io;

// Compile the code blocks in USAGE.md under `cargo test`, so the guide
// cannot drift from the API.
#[cfg(doctest)]
#[doc = include_str!("../USAGE.md")]
mod usage_guide {}
