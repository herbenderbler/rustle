#![no_main]
use libfuzzer_sys::fuzz_target;

// The ATT PDU parser. `GattClient` runs it on every PDU a connected peripheral
// sends over the L2CAP channel: responses, notifications and indications. The
// peripheral may be hostile.
fuzz_target!(|data: &[u8]| {
    let _ = rustle::att::parse(data);
});
