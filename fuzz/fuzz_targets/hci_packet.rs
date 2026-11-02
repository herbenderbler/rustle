#![no_main]
use libfuzzer_sys::fuzz_target;

// The top-level HCI datagram parser — the exact function the raw-HCI scanner
// feeds untrusted socket bytes into (`ble_hci::run_read_loop`). It dispatches to
// the legacy and extended LE-Advertising-Report parsers and the AD-structure
// decoder, so this one target exercises most of the scan decode surface.
fuzz_target!(|data: &[u8]| {
    let _ = rustle::hci::parse_hci_packet(data);
});
