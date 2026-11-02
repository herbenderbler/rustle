#![no_main]
use libfuzzer_sys::fuzz_target;

// The advertisement-data (AD structure) decoder in isolation: local names,
// 16/128-bit service UUIDs, manufacturer-specific data, service data, TX power.
// It is reached through `parse_hci_packet` too, but fuzzing it directly drops
// the HCI-framing gate so far more inputs land inside the AD state machine.
fuzz_target!(|data: &[u8]| {
    let _ = rustle::hci::parse_ad_structures(data);
});
