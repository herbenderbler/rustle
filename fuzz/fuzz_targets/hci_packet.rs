#![no_main]
use libfuzzer_sys::fuzz_target;

// The top-level HCI packet parser. Callers feed it each datagram that
// `HciScanner::read` returns. It hands legacy and extended advertising reports
// to their parsers and to the advertising data decoder, so this one target
// covers most of the scan decoding.
fuzz_target!(|data: &[u8]| {
    let _ = rustle::hci::parse_hci_packet(data);
});
