#![no_main]
use libfuzzer_sys::fuzz_target;

// The ATT PDU parser: bytes a connected — and possibly hostile — peripheral
// sends back over the L2CAP channel during `--interact` / `--interact-stream`
// (responses, notifications, indications).
fuzz_target!(|data: &[u8]| {
    let _ = rustle::att::parse(data);
});
