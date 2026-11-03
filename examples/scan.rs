//! Passive scan on one adapter for a fixed time, printing every
//! advertisement heard.
//!
//! Usage: `scan [hciN] [seconds]`. The defaults are `hci0` and ten seconds.
//! The socket needs `CAP_NET_RAW`; see INSTALL.md.

use rustle::adapter::index_from_name;
use rustle::hci::parse_hci_packet;
use rustle::scan::{HciScanner, ScanParams};
use std::io::ErrorKind;
use std::time::{Duration, Instant};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let iface = args.next().unwrap_or_else(|| "hci0".to_string());
    let seconds: u64 = match args.next() {
        Some(s) => s.parse()?,
        None => 10,
    };
    let dev = index_from_name(&iface).ok_or_else(|| format!("{iface} is not an hciN name"))?;

    // The receive timeout bounds each read, so the deadline is checked often.
    let mut scanner = HciScanner::open(dev, Duration::from_millis(500))?;
    let start = scanner.start(ScanParams::default())?;
    println!(
        "{iface}: passive scan with the {:?} commands for {seconds} s",
        start.mode
    );

    let deadline = Instant::now() + Duration::from_secs(seconds);
    let mut buf = [0u8; 512];
    let mut reports = 0usize;
    while Instant::now() < deadline {
        let n = match scanner.read(&mut buf) {
            Ok(n) => n,
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) => {
                continue
            }
            Err(e) => return Err(e.into()),
        };
        for report in parse_hci_packet(&buf[..n]) {
            reports += 1;
            let rssi = match report.rssi {
                Some(r) => format!("{r} dBm"),
                None => "n/a".to_string(),
            };
            let name = report.ad.local_name.as_deref().unwrap_or("");
            println!("{} {rssi} {name}", report.address);
        }
    }
    // Dropping the scanner stops the scan and closes the socket.
    println!("{reports} advertisement reports in {seconds} s");
    Ok(())
}
