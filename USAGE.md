# Using rustle

This guide walks through the tasks rustle supports, in the order a program
performs them. The [README](README.md) gives the overview and the module
map. [INSTALL.md](INSTALL.md) covers the toolchain, socket permissions and
the adapter.

Every Rust block in this file is compiled by `cargo test`, so the examples
match the current API.

## Layering

Each module has a pure layer and, where one is needed, a socket layer. The
pure layer encodes and decodes bytes and works on any OS. The socket layer
talks to the kernel and exists only on Linux. On other platforms the socket
types are still declared, but their constructors return an unsupported
error. Code that uses them compiles everywhere and fails at runtime off
Linux.

## Choose an adapter

`adapter::enumerate` lists the controllers the kernel knows about.
`adapter::choose` picks one by name and falls back to the first. The second
value it returns says whether the name matched. The index is what the
scanner binds.

```rust,no_run
use rustle::adapter;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let adapters = adapter::enumerate()?;
    let (i, matched) = adapter::choose(&adapters, "hci1");
    let info = adapters.get(i).ok_or("no Bluetooth adapter")?;
    if !matched {
        eprintln!("hci1 not found, using {}", info.name);
    }
    println!("{} {} up={}", info.name, info.address, info.up);
    Ok(())
}
```

When enumeration is not available and the name can be trusted,
`adapter::index_from_name("hci1")` turns it into the index directly.

## Scan for advertisements

`HciScanner::open` takes a controller index and a receive timeout. The
timeout makes `read` return `WouldBlock` when nothing arrives, so a loop
can check a shutdown flag between reads. `Duration::ZERO` disables it, and
reads then block for as long as it takes.

`ScanParams::default()` is a passive scan. The controller listens and sends
nothing. `start` tries the Bluetooth 5 extended scan commands first, so
extended advertisements are reported too. A controller that rejects them
gets the legacy commands instead. The returned `ScanStart` says which set
took effect.

```rust,no_run
use rustle::hci::parse_hci_packet;
use rustle::scan::{HciScanner, ScanParams};
use std::io::ErrorKind;
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut scanner = HciScanner::open(0, Duration::from_secs(1))?;
    let start = scanner.start(ScanParams::default())?;
    println!("scanning with the {:?} commands", start.mode);

    let mut buf = [0u8; 512];
    loop {
        match scanner.read(&mut buf) {
            Ok(n) => {
                for report in parse_hci_packet(&buf[..n]) {
                    println!(
                        "{} rssi={:?} name={:?}",
                        report.address, report.rssi, report.ad.local_name
                    );
                }
            }
            // Receive timeout or signal: nothing arrived yet.
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) => continue,
            Err(e) => return Err(e.into()),
        }
    }
}
```

Each datagram from `read` is one HCI event. `parse_hci_packet` turns it
into zero or more `AdvReport` values. A report carries the address, its
type, the RSSI and the decoded advertising data: local name, service
UUIDs, manufacturer data, service data, appearance and TX power.

Dropping the scanner stops the scan and closes the socket. Call `stop` to
end the scan and keep the socket open for another `start`.

## Active scans and scan responses

An active scan answers scannable advertisements with a scan request, so
the controller transmits. `OwnAddrType` chooses the address that request
carries. `Random` needs an address programmed beforehand, which the
scanner does not do.

A device then shows up twice: once for its advertisement and once for its
scan response. `ScanMerger` holds the first for a short time and emits the
pair as one `MergedAdv`. Call `flush_stale` on every pass so a device that
never answers is still emitted.

```rust,no_run
use rustle::hci::parse_hci_packet;
use rustle::scan::{HciScanner, OwnAddrType, ScanParams, ScanType};
use rustle::scan_merge::ScanMerger;
use std::io::ErrorKind;
use std::time::{Duration, Instant};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut scanner = HciScanner::open(0, Duration::from_millis(200))?;
    scanner.start(ScanParams::new(ScanType::Active, OwnAddrType::Public))?;
    let mut merger = ScanMerger::new(Duration::from_millis(100));

    let mut buf = [0u8; 512];
    loop {
        let read = scanner.read(&mut buf);
        let now = Instant::now();
        let mut ready = Vec::new();
        match read {
            Ok(n) => {
                for report in parse_hci_packet(&buf[..n]) {
                    ready.extend(merger.offer(report, now));
                }
            }
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) => {}
            Err(e) => return Err(e.into()),
        }
        ready.extend(merger.flush_stale(now));
        for adv in ready {
            println!("{} rssi={:?} name={:?}", adv.address, adv.rssi, adv.ad.local_name);
        }
    }
}
```

## Filter advertisements

A scan delivers every advertisement the controller hears. `ScanFilter`
narrows the stream in software. Each criterion that is set must match. A
criterion with several entries matches on any one of them. An empty
criterion is ignored, so the default filter matches everything.

Service UUIDs must be in the lowercase 128 bit form the parsers emit.
`normalize_uuid` expands a 16 or 32 bit shorthand to that form.

```rust,no_run
use rustle::hci::AdvReport;
use rustle::scan_filter::{normalize_uuid, ScanFilter};

/// Keep heart rate monitors from one vendor.
fn heart_rate_filter() -> ScanFilter {
    ScanFilter {
        service_uuids: vec![normalize_uuid("180d").expect("valid UUID")],
        manufacturer_ids: vec![0x006b],
        ..ScanFilter::default()
    }
}

fn wanted(filter: &ScanFilter, report: &AdvReport) -> bool {
    filter.matches_report(report)
}
```

`matches` tests a decoded `ParsedAd`. `matches_report` tests the whole
`AdvReport`. Either works on a `MergedAdv` through its `ad` field.

## Connect to a device

`L2capAtt` opens an ATT channel to a peer over L2CAP. The kernel drives the
LE connection. `connect` blocks until the link is up or the kernel gives
up, which can take tens of seconds for a peer that is out of range.
`connect_timeout` bounds the attempt and fails with `TimedOut`. Prefer it
in anything interactive.

```rust,no_run
use rustle::client::GattClient;
use rustle::l2cap::{L2capAtt, SecurityLevel};
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let link = L2capAtt::connect_timeout(
        None,                // local adapter address, None for the default
        false,               // the local address is public
        "AA:BB:CC:DD:EE:FF", // peer address
        true,                // the peer address is random
        SecurityLevel::Low,
        5,                   // receive timeout in seconds
        Duration::from_secs(10),
    )?;
    let client = GattClient::new(link);
    println!("connected, ATT MTU {}", client.mtu());
    Ok(())
}
```

| Argument | Meaning |
|---|---|
| `local` | Address of the local adapter, or `None` for the default adapter. |
| `local_random` | True when the local address is a random address. |
| `peer` | Address of the device, written as `AA:BB:CC:DD:EE:FF`. |
| `peer_random` | True when the peer uses a random address. The `addr_type` of its scan report says which. |
| `security` | Requested link security. `Low` needs no pairing. |
| `recv_timeout_secs` | Receive timeout in seconds. A notification loop uses it to check a shutdown flag. |
| `timeout` | Only on `connect_timeout`. Upper bound on the connection attempt. |

Dropping the channel closes it. The kernel drops the link once nothing
else uses it.

## Talk GATT

`GattClient` wraps the channel. Start with `exchange_mtu`. The server may
answer with a smaller value, and the result is what both sides agreed. A
larger MTU means fewer round trips for long values.

`discover_all` walks the whole tree: every primary service, its
characteristics and each characteristic's descriptors. The parts are also
available on their own as `discover_services`, `discover_characteristics`
and `discover_descriptors`.

Reads and writes address a characteristic by its value handle. `read`
issues one Read Request. `read_long` follows it with Read Blob requests
until the value ends. `write` waits for the server's response.
`write_without_response` sends a Write Command and returns at once, so the
value must fit in the MTU less three bytes.

```rust,no_run
use rustle::client::GattClient;
use rustle::l2cap::{L2capAtt, SecurityLevel};
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let link = L2capAtt::connect_timeout(
        None, false, "AA:BB:CC:DD:EE:FF", true, SecurityLevel::Low, 5, Duration::from_secs(10),
    )?;
    let mut client = GattClient::new(link);
    let mtu = client.exchange_mtu(247)?;
    println!("ATT MTU {mtu}");

    for service in client.discover_all()? {
        println!("service {}", service.service.uuid);
        for c in &service.characteristics {
            let ch = &c.characteristic;
            println!("  {} value handle {:#06x} props {:#04x}", ch.uuid, ch.value_handle, ch.properties);
            for d in &c.descriptors {
                println!("    descriptor {} handle {:#06x}", d.uuid, d.handle);
            }
        }
    }

    let value = client.read(0x0010)?;
    println!("handle 0x0010 holds {value:?}");
    client.write(0x0012, &[0x01])?;
    client.write_without_response(0x0014, &[0x02])?;
    Ok(())
}
```

## Notifications

A server pushes values to the client through notifications and
indications. Both are enabled by writing the characteristic's Client
Characteristic Configuration Descriptor, which `subscribe` does. Check
`can_notify` or `can_indicate` on the characteristic first.

`next_event` returns the next pushed value and confirms indications on its
own. It returns `Ok(None)` when the receive timeout elapses, so a loop can
check a flag between events. Values that arrive while the client waits for
a request's response are queued. `next_event` returns those first, and
`take_notifications` drains them all at once.

```rust,no_run
use rustle::client::GattClient;
use rustle::gatt::CCCD_UUID;
use rustle::l2cap::{L2capAtt, SecurityLevel};
use std::time::{Duration, Instant};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let link = L2capAtt::connect_timeout(
        None, false, "AA:BB:CC:DD:EE:FF", true, SecurityLevel::Low, 1, Duration::from_secs(10),
    )?;
    let mut client = GattClient::new(link);

    let heart_rate = "00002a37-0000-1000-8000-00805f9b34fb";
    let found = client
        .discover_all()?
        .into_iter()
        .flat_map(|s| s.characteristics)
        .find(|c| c.characteristic.uuid == heart_rate)
        .ok_or("no heart rate measurement characteristic")?;
    if !found.characteristic.can_notify() {
        return Err("characteristic does not notify".into());
    }
    let cccd = found
        .descriptors
        .iter()
        .find(|d| d.uuid == CCCD_UUID)
        .ok_or("characteristic has no CCCD")?;

    client.subscribe(cccd.handle, true, false)?;
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        // `None` is the one second receive timeout: nothing arrived.
        if let Some((handle, value)) = client.next_event()? {
            println!("{handle:#06x}: {value:?}");
        }
    }
    client.subscribe(cccd.handle, false, false)?;
    Ok(())
}
```

Unsubscribe by calling `subscribe` with both flags false.

## Read a connection's RSSI

`conn::read_rssi` asks the controller for the signal strength of an
established connection. It looks the connection up by peer address on the
given adapter, so the `L2capAtt` to that peer must still be open. `Ok(None)`
means the controller has no reading yet. Advertisements carry their own
RSSI in the scan report, so this call is only for connected peers.

```rust,no_run
use rustle::conn::read_rssi;
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    match read_rssi(0, "AA:BB:CC:DD:EE:FF", Duration::from_secs(1))? {
        Some(dbm) => println!("{dbm} dBm"),
        None => println!("RSSI not available"),
    }
    Ok(())
}
```

## Bring your own transport

`GattClient` is generic over the `AttIo` trait. One `send` or `recv` moves
exactly one ATT PDU. `recv` blocks until a PDU arrives or the transport's
own timeout passes, which it reports as `WouldBlock` or `TimedOut`. Any
framed transport fits: the Linux L2CAP channel, a serial link to a
controller, or a scripted mock.

The mock below answers an MTU exchange from a list of canned replies. It
runs without a radio, which is how the crate tests its own client.

```rust
use rustle::client::{AttIo, GattClient};
use std::collections::VecDeque;
use std::io;

/// Records what the client sends and answers from a script.
struct Scripted {
    sent: Vec<Vec<u8>>,
    replies: VecDeque<Vec<u8>>,
}

impl AttIo for Scripted {
    fn send(&mut self, pdu: &[u8]) -> io::Result<()> {
        self.sent.push(pdu.to_vec());
        Ok(())
    }

    fn recv(&mut self) -> io::Result<Vec<u8>> {
        self.replies
            .pop_front()
            .ok_or_else(|| io::Error::from(io::ErrorKind::TimedOut))
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Exchange MTU Response: opcode 0x03, then the server MTU as two
    // little endian bytes. 185 fits in one.
    let io = Scripted {
        sent: Vec::new(),
        replies: VecDeque::from(vec![vec![0x03, 185, 0]]),
    };
    let mut client = GattClient::new(io);
    let mtu = client.exchange_mtu(247)?;
    assert_eq!(mtu, 185);
    Ok(())
}
```

## Errors

| Error | Cause | Fix |
|---|---|---|
| `ScanError::Socket`, `RssiError::Socket` | The raw socket could not be opened. | Grant `CAP_NET_RAW` or run as root. |
| `ScanError::Bind`, `RssiError::Bind` | No controller at that index, or it is down. | Check `adapter::enumerate` and bring the adapter up. |
| `ScanError::Rejected { status: 0x0C, .. }` | Command Disallowed. Another stack holds the adapter. | Stop `bluetoothd`. |
| `ScanError::NoResponse`, `RssiError::NoResponse` | The controller did not answer within the wait. | Watch `btmon` and reset the adapter. |
| `Unsupported` from any socket type | The program is not running on Linux. | Only the pure layer is available there. |
| `GattError::Io` with `TimedOut` or `WouldBlock` | The receive timeout passed during a request. | The peer is slow or gone. Retry, then reconnect. |
| `GattError::Att { error, .. }` | The server refused the request. | `0x02` and `0x03` mean not readable or not writable. `0x05` and `0x0F` want a higher `SecurityLevel`. `0x0A` means no such handle. |
| `GattError::Protocol` | The response could not be decoded or was not the one expected. | Report it with the PDU bytes. |
| `RssiError::NoConnection` | No LE connection to that peer on that adapter. | Connect first. |
| `TimedOut` from `connect_timeout` | The peer did not answer in time. | See below. |

## Troubleshooting

- **Command Disallowed when starting a scan.** `bluetoothd` holds the
  adapter. Stop it as [INSTALL.md](INSTALL.md) describes.
- **Permission denied when opening a socket.** The binary lacks
  `CAP_NET_RAW`. Run `setcap` again after every rebuild.
- **Bind fails.** There is no controller at that index, or it is down.
  `hciconfig` or `btmgmt info` shows the state.
- **The scan starts but nothing arrives.** Every read ends in `WouldBlock`.
  Nearby devices may be silent, or the controller may be down. `btmon`
  shows the traffic the kernel sees.
- **`connect_timeout` times out.** The peer is out of range, not
  connectable, or already connected to another host. Scan first to
  confirm it is visible, and check `peer_random` against the report's
  `addr_type`.
- **Unsupported errors.** The program runs on a platform other than Linux.
  Only the pure layer works there.
- **A read never returns.** The receive timeout is zero. Give `open` or
  `connect` a timeout.
