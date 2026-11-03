//! Find a device by name, connect to it and read its battery level.
//!
//! Usage: `battery <name prefix> [hciN] [seconds]`. The scan runs on `hci0`
//! for up to ten seconds by default. Both sockets need `CAP_NET_RAW`; see
//! INSTALL.md. USAGE.md explains each step.

use rustle::adapter::index_from_name;
use rustle::client::GattClient;
use rustle::hci::{parse_hci_packet, AddrType};
use rustle::l2cap::{L2capAtt, SecurityLevel};
use rustle::scan::{HciScanner, OwnAddrType, ScanParams, ScanType};
use std::error::Error;
use std::io::ErrorKind;
use std::time::{Duration, Instant};

/// The standard Battery Level characteristic, 0x2A19, in the 128 bit form
/// rustle uses for every UUID.
const BATTERY_LEVEL: &str = "00002a19-0000-1000-8000-00805f9b34fb";

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args().skip(1);
    let prefix = args
        .next()
        .ok_or("usage: battery <name prefix> [hciN] [seconds]")?;
    let iface = args.next().unwrap_or_else(|| "hci0".to_string());
    let seconds: u64 = match args.next() {
        Some(s) => s.parse()?,
        None => 10,
    };
    let dev = index_from_name(&iface).ok_or_else(|| format!("{iface} is not an hciN name"))?;

    // Step 1: scan until a device whose name starts with the prefix is heard.
    let (address, random) = find_device(dev, &prefix, Duration::from_secs(seconds))?
        .ok_or_else(|| format!("no device named {prefix}* heard in {seconds} s"))?;
    println!("found {address} (random address: {random})");

    // Step 2: connect. The scanner was dropped inside find_device, so the
    // controller is no longer scanning while the kernel connects.
    let link = L2capAtt::connect_timeout(
        None,
        false,
        &address,
        random,
        SecurityLevel::Low,
        5,
        Duration::from_secs(10),
    )?;
    let mut client = GattClient::new(link);
    client.exchange_mtu(247)?;

    // Step 3: discover the attribute table and find Battery Level by UUID.
    // Handles differ from device to device, so they cannot be hard coded.
    let battery = client
        .discover_all()?
        .into_iter()
        .flat_map(|s| s.characteristics)
        .find(|c| c.characteristic.uuid == BATTERY_LEVEL)
        .ok_or("device has no Battery Level characteristic")?;

    // Step 4: read it by value handle. The value is one byte, a percentage.
    let value = client.read(battery.characteristic.value_handle)?;
    match value.first() {
        Some(percent) => println!("battery {percent}%"),
        None => println!("battery level is empty"),
    }
    Ok(())
}

/// Scan for up to `timeout` and return the first matching device's address
/// and whether that address is random. An active scan asks each device for
/// its scan response, which is where many devices put their name.
fn find_device(
    dev: u16,
    prefix: &str,
    timeout: Duration,
) -> Result<Option<(String, bool)>, Box<dyn Error>> {
    let mut scanner = HciScanner::open(dev, Duration::from_millis(500))?;
    scanner.start(ScanParams::new(ScanType::Active, OwnAddrType::Public))?;

    let deadline = Instant::now() + timeout;
    let mut buf = [0u8; 512];
    while Instant::now() < deadline {
        let n = match scanner.read(&mut buf) {
            Ok(n) => n,
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) => {
                continue
            }
            Err(e) => return Err(e.into()),
        };
        for report in parse_hci_packet(&buf[..n]) {
            let name = report.ad.local_name.as_deref().unwrap_or("");
            if name.starts_with(prefix) {
                let random = report.addr_type == AddrType::Random;
                return Ok(Some((report.address, random)));
            }
        }
    }
    Ok(None)
}
