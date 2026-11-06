//! Checks that the byte parsers never panic on hostile input.
//!
//! rustle decodes advertisements and ATT PDUs sent by devices it does not
//! control. The parsers are safe Rust, but safe code can still panic when a
//! slice index is out of bounds or an integer overflows. A nearby device could
//! send such bytes on purpose and crash the program that scans or connects.
//!
//! This test feeds every public parser a large mix of random bytes and
//! mutated copies of valid frames. It uses a fixed seed, so a failure can be
//! reproduced. A panic in any parser fails the test.
//!
//! The test needs only the stable toolchain and runs on every CI build. The
//! `cargo fuzz` targets in `fuzz/` search deeper, but they need nightly Rust.
//! See `fuzz/README.md`.

use rustle::{att, conn, hci, mgmt};

/// Tiny deterministic PRNG (xorshift64*), so any failure reproduces from the
/// fixed seed rather than being a heisenbug.
struct Rng(u64);

impl Rng {
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn byte(&mut self) -> u8 {
        (self.next_u64() >> 33) as u8
    }
    /// Uniform-ish value in `0..n` (`n` must be non-zero).
    fn below(&mut self, n: usize) -> usize {
        (self.next_u64() as usize) % n
    }
}

/// Push `buf` through every public byte-taking parser. A panic in any of them
/// fails the test — that is the whole assertion.
fn feed_all(buf: &[u8]) {
    let _ = hci::parse_hci_packet(buf);
    let _ = hci::parse_ad_structures(buf);
    let _ = hci::ad_structures(buf).count();
    let _ = hci::parse_le_advertising_report(buf);
    let _ = hci::parse_le_extended_advertising_report(buf);
    let _ = hci::is_adv_report_packet(buf);
    let _ = hci::parse_command_event(buf);
    let _ = hci::parse_command_complete(buf);
    let _ = hci::command_outcome(0x200C, buf);
    let _ = att::parse(buf);
    let _ = conn::parse_read_rssi_complete(buf);
    let _ = conn::read_rssi_outcome(0x0040, buf);
    let _ = conn::parse_conn_info_handle(buf);
    let _ = conn::parse_conn_list(buf);
    let _ = mgmt::parse_command_reply(buf);
}

/// Valid-ish frames worth mutating around, so the fuzzer spends time near the
/// real state machine rather than only in the "too short / wrong opcode" reject
/// paths: a legacy LE Advertising Report HCI packet plus a few ATT PDUs.
fn seeds() -> Vec<Vec<u8>> {
    vec![
        // [0x04 HCI event][0x3E LE Meta][plen][0x02 adv-report subevent][num=1]
        // [evt_type][addr_type][6-byte addr][ad_len][ad…][rssi]
        vec![
            0x04, 0x3E, 0x0C, 0x02, 0x01, 0x00, 0x00, 0xcc, 0xbb, 0xaa, 0x4e, 0xc9, 0x70, 0x00,
            0xd0,
        ],
        // Same, extended-advertising subevent (0x0D) with a name AD structure.
        vec![
            0x04, 0x3E, 0x12, 0x0D, 0x01, 0x00, 0x00, 0x01, 0x00, 0xcc, 0xbb, 0xaa, 0x4e, 0xc9,
            0x70, 0x00, 0x00, 0x00, 0xd0, 0x03, 0x09, b'F', b'S',
        ],
        // ATT Error Response / Exchange MTU Response / Read Response /
        // Handle Value Notification.
        vec![0x01, 0x08, 0x03, 0x00, 0x0a],
        vec![0x03, 0xf7, 0x00],
        vec![0x0b, 0xde, 0xad, 0xbe, 0xef],
        vec![0x1b, 0x03, 0x00, 0x01, 0x02, 0x03],
    ]
}

#[test]
fn parsers_never_panic_on_random_bytes() {
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    for _ in 0..50_000 {
        let len = rng.below(320);
        let mut buf = Vec::with_capacity(len);
        for _ in 0..len {
            buf.push(rng.byte());
        }
        feed_all(&buf);
    }
}

#[test]
fn parsers_never_panic_on_mutated_seeds() {
    let mut rng = Rng(0xD1B5_4A32_D192_ED03);
    let seeds = seeds();
    for _ in 0..50_000 {
        let mut buf = seeds[rng.below(seeds.len())].clone();
        // A handful of mutations per iteration: bit flips, byte sets, truncation,
        // extension. Guard every index against an empty buffer.
        let muts = 1 + rng.below(6);
        for _ in 0..muts {
            if buf.is_empty() {
                buf.push(rng.byte());
                continue;
            }
            match rng.below(4) {
                0 => {
                    let i = rng.below(buf.len());
                    buf[i] ^= 1u8 << rng.below(8);
                }
                1 => {
                    let i = rng.below(buf.len());
                    buf[i] = rng.byte();
                }
                2 => {
                    let n = rng.below(buf.len() + 1);
                    buf.truncate(n);
                }
                _ => buf.push(rng.byte()),
            }
        }
        feed_all(&buf);
    }
}
