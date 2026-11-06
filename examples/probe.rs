//! Connect to one device and run the connection checks from USAGE.md:
//! discovery, connection RSSI, notifications and security levels.
//!
//! Usage:
//!
//! ```text
//! probe <address> <public|random> [--adapter hciN] [--security low|medium|high]
//!       [--listen seconds] [--notify uuid]
//! ```
//!
//! Scan first with `examples/scan.rs` to find the address and whether it is
//! random. The defaults are `hci0`, `low` and a ten second listen. `--notify`
//! picks the characteristic to subscribe to, as a 16 bit (`2a37`) or 128 bit
//! UUID; without it the first one that notifies or indicates is used. Both
//! sockets need `CAP_NET_RAW`; see INSTALL.md.
//!
//! The steps, each reported as it runs:
//!
//! 1. Connect through the named adapter at the requested security level.
//! 2. Exchange the MTU and print the whole attribute table.
//! 3. Read the connection's RSSI while the link is open.
//! 4. Read every readable characteristic. ATT error `0x05` or `0x0F` means
//!    the characteristic needs a higher security level.
//! 5. Subscribe, print each value and count the receive timeouts, then
//!    unsubscribe.
//! 6. Close the link and read the RSSI until it fails with `NoConnection`.

use rustle::adapter::{self, index_from_name};
use rustle::client::{DiscoveredCharacteristic, DiscoveredService, GattClient, GattError};
use rustle::conn::{read_rssi, RssiError};
use rustle::gatt::CCCD_UUID;
use rustle::l2cap::{L2capAtt, SecurityLevel};
use std::error::Error;
use std::thread::sleep;
use std::time::{Duration, Instant};

/// Service Changed only indicates when the attribute table changes, so it is
/// never a useful default to listen to.
const SERVICE_CHANGED: &str = "00002a05-0000-1000-8000-00805f9b34fb";

const USAGE: &str = "usage: probe <address> <public|random> [--adapter hciN] \
                     [--security low|medium|high] [--listen seconds] [--notify uuid]";

struct Args {
    address: String,
    random: bool,
    dev: u16,
    security: SecurityLevel,
    listen: Duration,
    notify: Option<String>,
}

fn parse_args() -> Result<Args, Box<dyn Error>> {
    let mut args = std::env::args().skip(1);
    let address = args.next().ok_or(USAGE)?;
    let random = match args.next().as_deref() {
        Some("public") => false,
        Some("random") => true,
        _ => return Err(USAGE.into()),
    };
    let mut parsed = Args {
        address,
        random,
        dev: 0,
        security: SecurityLevel::Low,
        listen: Duration::from_secs(10),
        notify: None,
    };
    while let Some(flag) = args.next() {
        let value = args.next().ok_or(USAGE)?;
        match flag.as_str() {
            "--adapter" => {
                parsed.dev =
                    index_from_name(&value).ok_or_else(|| format!("{value} is not an hciN name"))?
            }
            "--security" => {
                parsed.security = match value.as_str() {
                    "low" => SecurityLevel::Low,
                    "medium" => SecurityLevel::Medium,
                    "high" => SecurityLevel::High,
                    _ => return Err(USAGE.into()),
                }
            }
            "--listen" => parsed.listen = Duration::from_secs(value.parse()?),
            "--notify" => parsed.notify = Some(full_uuid(&value)?),
            _ => return Err(USAGE.into()),
        }
    }
    Ok(parsed)
}

/// Expand a 16 bit UUID such as `2a37` to the 128 bit form rustle uses, and
/// lowercase a 128 bit one.
fn full_uuid(uuid: &str) -> Result<String, String> {
    let uuid = uuid.to_ascii_lowercase();
    if uuid.len() == 4 && uuid.chars().all(|c| c.is_ascii_hexdigit()) {
        Ok(format!("0000{uuid}-0000-1000-8000-00805f9b34fb"))
    } else if uuid.len() == 36 {
        Ok(uuid)
    } else {
        Err(format!("{uuid} is not a 16 bit or 128 bit UUID"))
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = parse_args()?;
    let local = adapter::info(args.dev)?.address;

    // Step 1. Pairing for Medium or High happens during the connect, and the
    // kernel gives up on it after 30 s, so allow longer than that.
    let timeout = match args.security {
        SecurityLevel::Low => Duration::from_secs(10),
        _ => Duration::from_secs(40),
    };
    let started = Instant::now();
    let link = L2capAtt::connect_timeout(
        Some(&local),
        false,
        &args.address,
        args.random,
        args.security,
        1, // one second receive timeout: the listen loop's tick
        timeout,
    )
    .map_err(|e| {
        format!(
            "connect at {:?} failed after {} ms: {e}",
            args.security,
            started.elapsed().as_millis()
        )
    })?;
    println!(
        "connected to {} through hci{} at {:?} in {} ms",
        args.address,
        args.dev,
        args.security,
        started.elapsed().as_millis()
    );

    // Step 2.
    let mut client = GattClient::new(link);
    println!("ATT MTU {}", client.exchange_mtu(247)?);
    let services = client.discover_all()?;
    print_table(&services);

    // Step 3.
    match read_rssi(args.dev, &args.address, Duration::from_secs(1)) {
        Ok(Some(dbm)) => println!("RSSI while connected: {dbm} dBm"),
        Ok(None) => println!("RSSI while connected: not available"),
        Err(e) => println!("RSSI while connected failed: {e}"),
    }

    // Step 4.
    let characteristics: Vec<&DiscoveredCharacteristic> =
        services.iter().flat_map(|s| &s.characteristics).collect();
    for c in characteristics
        .iter()
        .filter(|c| c.characteristic.can_read())
    {
        let ch = &c.characteristic;
        match client.read(ch.value_handle) {
            Ok(value) => println!("read {:#06x}: {}", ch.value_handle, hex(&value)),
            Err(GattError::Att { error, .. }) => {
                let hint = match error {
                    0x05 | 0x0F => " (needs a higher security level)",
                    _ => "",
                };
                println!(
                    "read {:#06x}: ATT error {error:#04x}{hint}",
                    ch.value_handle
                );
            }
            Err(e) => return Err(e.into()),
        }
    }

    // Step 5.
    let target = characteristics.iter().find(|c| {
        let ch = &c.characteristic;
        match &args.notify {
            Some(uuid) => ch.uuid == *uuid,
            None => (ch.can_notify() || ch.can_indicate()) && ch.uuid != SERVICE_CHANGED,
        }
    });
    match target {
        Some(c) => listen(&mut client, c, args.listen)?,
        None => println!("no characteristic to subscribe to"),
    }

    // Step 6. The kernel closes the LE link once the channel is gone, which
    // takes a round trip to the controller.
    drop(client);
    let closed = Instant::now();
    loop {
        match read_rssi(args.dev, &args.address, Duration::from_secs(1)) {
            Err(RssiError::NoConnection(_)) => {
                println!(
                    "RSSI after closing: NoConnection after {} ms",
                    closed.elapsed().as_millis()
                );
                break;
            }
            other if closed.elapsed() > Duration::from_secs(5) => {
                println!("RSSI after closing: still {other:?} after 5 s");
                break;
            }
            _ => sleep(Duration::from_millis(100)),
        }
    }
    Ok(())
}

fn print_table(services: &[DiscoveredService]) {
    for service in services {
        println!("service {}", service.service.uuid);
        for c in &service.characteristics {
            let ch = &c.characteristic;
            println!(
                "  characteristic {} value handle {:#06x} properties {:#04x}",
                ch.uuid, ch.value_handle, ch.properties
            );
            for d in &c.descriptors {
                println!("    descriptor {} handle {:#06x}", d.uuid, d.handle);
            }
        }
    }
}

/// Subscribe to `c`, print what arrives for `duration`, then unsubscribe.
fn listen(
    client: &mut GattClient<L2capAtt>,
    c: &DiscoveredCharacteristic,
    duration: Duration,
) -> Result<(), GattError> {
    let ch = &c.characteristic;
    let Some(cccd) = c.descriptors.iter().find(|d| d.uuid == CCCD_UUID) else {
        println!("{} has no CCCD, so it cannot be subscribed to", ch.uuid);
        return Ok(());
    };
    // Prefer notifications; use indications only when that is all it offers.
    let notify = ch.can_notify();
    let indicate = !notify && ch.can_indicate();
    if let Err(e) = client.subscribe(cccd.handle, notify, indicate) {
        println!("subscribe to {} failed: {e}", ch.uuid);
        return Ok(());
    }
    println!("subscribed to {} for {} s", ch.uuid, duration.as_secs());

    let deadline = Instant::now() + duration;
    let (mut values, mut ticks) = (0u32, 0u32);
    while Instant::now() < deadline {
        match client.next_event()? {
            Some((handle, value)) => {
                values += 1;
                println!("  {handle:#06x}: {}", hex(&value));
            }
            // The one second receive timeout passed with nothing to report.
            None => ticks += 1,
        }
    }
    println!(
        "{values} values and {ticks} receive timeouts in {} s",
        duration.as_secs()
    );
    client.subscribe(cccd.handle, false, false)
}
