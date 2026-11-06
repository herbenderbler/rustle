# Using rustle

This guide walks through the tasks rustle supports, in the order a program
performs them. The [README](README.md) gives the overview and the module
map. [INSTALL.md](INSTALL.md) covers the toolchain, socket permissions and
the adapter.

Every Rust block in this file is compiled by `cargo test`, so the examples
match the current API. If BLE itself is new to you, start with Concepts
and then run the first program.

## Concepts

BLE splits into a **controller** and a **host**. The controller is the
radio chip. The host is the software that drives it, over an interface
called **HCI**. On Linux the kernel owns the HCI link and exposes it as
sockets. rustle talks to those sockets, so nothing else sits between your
program and the radio.

A device that wants to be found sends **advertisements**: small broadcast
packets with a name, the services it offers, or vendor data. A **scan**
listens for them. A **passive** scan only listens. An **active** scan also
asks each device for a **scan response**, a second packet with more data.
Many devices put their name in the scan response only.

Every device has a 48 bit **address**, written `AA:BB:CC:DD:EE:FF`. A
**public** address is fixed in hardware. A **random** address is chosen by
the device, and some devices change it over time for privacy. Connecting
needs the address and its kind. Both come from a scan report.

A **connection** is a timed link between the host and one device. The
kernel establishes it. Over the link runs **L2CAP**, a thin multiplexing
layer, and on a fixed L2CAP channel runs **ATT**, the Attribute Protocol.
ATT is a request and response protocol over a table of attributes on the
device. Each attribute has a **handle**, a 16 bit index into the table, a
**UUID** that says what it is, and a value.

**GATT** gives that table a structure. A **service** groups related
**characteristics**. A characteristic is one value, such as a battery
level, plus properties that say whether it can be read, written or pushed
to the client. A characteristic may own **descriptors** that configure it.
Standard services and characteristics have 16 bit UUIDs assigned by the
Bluetooth SIG. Vendor ones have 128 bit UUIDs. rustle writes every UUID in
the 128 bit form, so Battery Level `0x2A19` appears as
`00002a19-0000-1000-8000-00805f9b34fb`.

Handles are not fixed by the UUID. They differ from device to device, so a
client **discovers** the table first and then reads or writes by handle.
The **MTU** is the largest ATT packet both sides accept. It starts at 23
bytes, and the client can ask for more.

A device can push a characteristic's value to the client. A
**notification** is sent and forgotten. An **indication** must be
confirmed. Both are switched on by writing the **Client Characteristic
Configuration Descriptor**, or **CCCD**, that sits next to the
characteristic.

**RSSI** is received signal strength in dBm. Numbers closer to zero mean a
stronger signal. Scan reports carry it, and a connection can be asked for
it.

## First program

`examples/battery.rs` is a complete program that does the four things most
BLE clients do. It scans until it hears a device whose name starts with a
prefix, connects to it, discovers its attribute table, and reads the
standard Battery Level characteristic. Build it, grant the capability and
run it with the start of your device's name:

```bash
cargo build --example battery
```

```bash
sudo setcap cap_net_raw+ep target/debug/examples/battery
```

```bash
target/debug/examples/battery Polar
```

The sections below explain each step in the order the program takes
them.

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

### Long range scanning

The extended commands can listen on the LE Coded PHY, which long range
advertisers use. `ScanParams::phys` selects LE 1M (the default), Coded, or
both. Legacy scanning is LE 1M only, so a Coded-only request fails on a
controller without extended scanning instead of listening on the wrong
PHY.

```rust,no_run
use rustle::scan::{HciScanner, ScanParams, ScanPhys};
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut scanner = HciScanner::open(0, Duration::from_secs(1))?;
    let params = ScanParams {
        phys: ScanPhys::M1AndCoded,
        ..ScanParams::default()
    };
    scanner.start(params)?;
    Ok(())
}
```

## Active scans and scan responses

An active scan answers scannable advertisements with a scan request, so
the controller transmits. `OwnAddrType` chooses the address that request
carries. `Random` needs an address programmed beforehand, which the
scanner does not do.

An active scan also needs `CAP_NET_ADMIN`. The kernel reads it as the
start of a device discovery, and until that discovery ends the kernel
refuses new ones and does not make LE connections on the adapter.
`start` ends any discovery in progress first, and `stop` ends the one the
scan started. Without the capability, `start` fails with
`ScanError::Discovery` before the controller is touched. Call `stop`
yourself before connecting, so a failure is reported: dropping the
scanner does the same work but cannot return an error.

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

Scan first to get the two things a connection needs. The report for your
device carries its address, and its `addr_type` says whether that address
is random. Pass `report.addr_type == AddrType::Random` as `peer_random`.
A wrong flag makes the kernel look for a device that does not exist, and
the connect times out.

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
| `local` | Address of the local adapter, or `None` for the kernel's default, usually `hci0`. With more than one adapter, pass the address of the one you scanned on: `adapter::info(dev)` gives it. |
| `local_random` | True when the local address is a random address. |
| `peer` | Address of the device, written as `AA:BB:CC:DD:EE:FF`. |
| `peer_random` | True when the peer uses a random address. The `addr_type` of its scan report says which. |
| `security` | Link security to wait for. `Low` needs no pairing; the higher levels are described below. |
| `recv_timeout_secs` | Receive timeout in seconds. A notification loop uses it to check a shutdown flag. |
| `timeout` | Only on `connect_timeout`. Upper bound on the connection attempt. |

`SecurityLevel::Low` needs no pairing and works with most devices. `Medium`
asks for an encrypted link, and `High` for one whose key is protected
against man-in-the-middle attacks, for example by a passkey. For either,
the kernel connects first and pairs afterwards, so `connect` waits until
the link reaches the level and fails if it does not. The channel's
`security()` reports the level the link reached.

The kernel asks for every pairing to be approved, even one that needs no
passkey. Normally `bluetoothd` passes the request to a registered pairing
agent, such as a desktop's Bluetooth applet or `bluetoothctl`, which asks
the user; they have about 30 seconds to answer. Without an agent nothing
approves it and the pairing stalls. About 30 seconds in, the kernel
abandons the pairing and drops the link, and `connect` fails with
`ConnectionAborted`. A `connect_timeout` shorter than that fails with
`TimedOut` first. `High` fails the same way with a device that has no
display or keyboard, because such a device cannot authenticate a key.
Stay on `Low` unless the device answers reads or writes with ATT error
`0x05` or `0x0F`.

Some devices ask to pair as soon as the link is up, whatever the security
level. If such a device wants a passkey, nothing can answer it without
`bluetoothd`: the pairing fails, the device closes the link, and the next
request fails with `GattError::Io` of kind `PermissionDenied`. A Flipper
Zero behaves this way. `btmon` shows the device's `SMP: Security Request`
and a disconnect with reason Authentication Failure.

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

Reads and writes address a characteristic by its value handle. The handle
comes from discovery, never from the UUID, because every device lays its
table out differently. Find the characteristic by UUID first, then use
its `value_handle`. Standard UUIDs are listed in the Bluetooth SIG
assigned numbers; see Further reading.

`read` issues one Read Request. `read_long` follows it with Read Blob
requests until the value ends. `write` waits for the server's response.
`write_without_response` sends a Write Command and returns at once, so the
value must fit in the MTU less three bytes. Both writes take the same
value handle and a byte slice.

```rust,no_run
use rustle::client::GattClient;
use rustle::l2cap::{L2capAtt, SecurityLevel};
use std::time::Duration;

// Battery Service 0x180F and its Battery Level characteristic 0x2A19.
const BATTERY_SERVICE: &str = "0000180f-0000-1000-8000-00805f9b34fb";
const BATTERY_LEVEL: &str = "00002a19-0000-1000-8000-00805f9b34fb";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let link = L2capAtt::connect_timeout(
        None, false, "AA:BB:CC:DD:EE:FF", true, SecurityLevel::Low, 5, Duration::from_secs(10),
    )?;
    let mut client = GattClient::new(link);
    let mtu = client.exchange_mtu(247)?;
    println!("ATT MTU {mtu}");

    // Discover the whole table and print it, to see what the device offers.
    let services = client.discover_all()?;
    for service in &services {
        println!("service {}", service.service.uuid);
        for c in &service.characteristics {
            let ch = &c.characteristic;
            println!("  {} value handle {:#06x} props {:#04x}", ch.uuid, ch.value_handle, ch.properties);
        }
    }

    // Find Battery Level inside the Battery Service and read it by handle.
    let battery = services
        .iter()
        .find(|s| s.service.uuid == BATTERY_SERVICE)
        .and_then(|s| s.characteristics.iter().find(|c| c.characteristic.uuid == BATTERY_LEVEL))
        .ok_or("device has no Battery Level characteristic")?;
    let level = client.read(battery.characteristic.value_handle)?;
    println!("battery {}%", level.first().copied().unwrap_or(0));
    Ok(())
}
```

## Notifications

A server pushes values to the client through notifications and
indications. Both are off until the client asks for them by writing the
characteristic's CCCD, a two byte descriptor that sits next to it.
`subscribe` finds nothing on its own; give it the CCCD handle from
discovery, as below. Check `can_notify` or `can_indicate` on the
characteristic first.

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
| `ScanError::Socket`, `RssiError::Socket` | The raw socket could not be opened. The kernel probably has no Bluetooth support. | Use a kernel with Bluetooth. Permissions are not the cause: the socket opens without them. |
| `ScanError::Bind`, `RssiError::Bind` | No controller at that index. | Check `adapter::enumerate` or `btmgmt info`. |
| `ScanError::Write` with `PermissionDenied` | The binary lacks `CAP_NET_RAW`. The kernel refuses the scan commands. | Grant `CAP_NET_RAW` or run as root. |
| `ScanError::Write` with `NetworkDown` | The controller is down. | Bring it up with `btmgmt power on`. |
| `ScanError::Discovery`, with `is_permission_denied()` true | An active scan needs `CAP_NET_ADMIN`, to end the discovery the kernel believes it starts. | Grant `CAP_NET_ADMIN` as well, or scan passively. |
| `ScanError::Discovery` from `stop` | The scan is off, but the kernel's discovery did not end. New discoveries and connections on the adapter stay blocked. | `btmgmt stop-find`, as [INSTALL.md](INSTALL.md) describes. |
| `ScanError::Rejected { status: 0x0C, .. }` | Command Disallowed. The controller refused the command in its current state, for example because something restarted a scan while rustle was setting one up. | Stop `bluetoothd`, or use an adapter nothing else scans on. |
| `ScanError::NoResponse`, `RssiError::NoResponse` | The controller did not answer within the wait. | Watch `btmon` and reset the adapter. |
| `Unsupported` from any socket type | The program is not running on Linux. | Only the pure layer is available there. |
| `GattError::Io` with `TimedOut` or `WouldBlock` | The receive timeout passed during a request. | The peer is slow or gone. Retry, then reconnect. |
| `GattError::Io` with `PermissionDenied` | The link closed because pairing failed. The device probably asked to pair and wants a passkey. | Pair through `bluetoothd`, or use a device that pairs without a passkey. |
| `GattError::Att { error, .. }` | The server refused the request. | `0x02` and `0x03` mean not readable or not writable. `0x05` and `0x0F` want a higher `SecurityLevel`. `0x0A` means no such handle. |
| `GattError::Protocol` | The response could not be decoded or was not the one expected. | Report it with the PDU bytes. |
| `RssiError::NoConnection` | No LE connection to that peer on that adapter. | Connect first. |
| `TimedOut` from `connect_timeout` | The peer did not answer in time. | See below. |
| `ConnectionAborted` from a connect at `Medium` or `High`, saying the link closed before reaching that security, or `TimedOut` saying pairing did not finish | The link came up, but nothing approved the pairing, or the device cannot reach that level. | Run `bluetoothd` with a pairing agent, or connect at a lower level. |

## Troubleshooting

- **`btmgmt find` fails with `Busy` after a scan.** A discovery is stuck:
  a passive scan cut off one `bluetoothd` was running, or an active scan's
  program was killed before it could stop. Until it ends, `bluetoothd`
  finds nothing and connections on that adapter time out. Stop it with
  `btmgmt stop-find`, adding `-l` if that reports Invalid Parameters, or
  power the adapter off and on. To avoid it, stop `bluetoothd` first, as
  [INSTALL.md](INSTALL.md) describes.
- **An active scan fails with `Discovery`.** The binary lacks
  `CAP_NET_ADMIN`. Grant `cap_net_raw,cap_net_admin+ep`.
- **`Write` fails with `PermissionDenied`.** The binary lacks
  `CAP_NET_RAW`. The socket opens without it, so the error only shows when
  the scan starts. Run `setcap` again after every rebuild.
- **`Write` fails with `NetworkDown`.** The controller is down.
  `btmgmt info` shows its state, and `btmgmt power on` brings it up.
- **Bind fails.** There is no controller at that index. `btmgmt info`
  lists the ones there are.
- **The scan starts but nothing arrives.** Every read ends in `WouldBlock`.
  Nearby devices may be silent, or the controller may be down. `btmon`
  shows the traffic the kernel sees.
- **`connect_timeout` times out.** The peer is out of range, not
  connectable, or already connected to another host. Scan first to
  confirm it is visible, and check `peer_random` against the report's
  `addr_type`. If `btmgmt find` reports `Busy` on that adapter, a stuck
  discovery is holding the kernel back; see the first entry.
- **A connect at `Medium` or `High` fails after about 30 seconds.** The
  error says the link closed before reaching that security, or that
  pairing did not finish. The kernel paired as far as asking for approval,
  and nothing approved: `btmon` shows `SMP: Pairing Random`, then `MGMT
  Event: User Confirmation Request` with no reply. Register a pairing
  agent, for example by running `bluetoothctl` and entering
  `default-agent`, and approve the request when it asks. At `High`, the
  device may be unable to authenticate a key at all. See "Connect to a
  device".
- **Requests fail with `PermissionDenied` right after connecting.** The
  device asked to pair and nothing could answer its passkey; see "Connect
  to a device".
- **Unsupported errors.** The program runs on a platform other than Linux.
  Only the pure layer works there.
- **A read never returns.** The receive timeout is zero. Give `open` or
  `connect` a timeout.

## Further reading

- The Bluetooth SIG [assigned numbers](https://www.bluetooth.com/specifications/assigned-numbers/)
  list every standard service, characteristic and descriptor UUID, and the
  company identifiers used in manufacturer data.
- The Bluetooth [Core Specification](https://www.bluetooth.com/specifications/specs/)
  has the ATT and GATT chapters in the Host volume and the HCI commands in
  the Host Controller Interface volume.
- `btmon` from BlueZ prints every HCI packet the kernel sees. It is the
  fastest way to learn what a device actually sends.
