# Fuzzing the rustle byte parsers

The BLE stack decodes attacker-controlled advertisement and ATT bytes in **safe
Rust**, with no C library behind a D-Bus binding in the path. These
coverage-guided [`cargo fuzz`][cf] targets hunt for any input that
makes a parser **panic**: a panic on a hostile advertisement or ATT PDU is a
remote DoS of the scanner / interact client, not just a bug.

This crate is **detached from the workspace** (its own empty `[workspace]` in
`Cargo.toml`), so the stable build, CI, `cargo-deny`, and `cargo-machete` never
see it — the same way `firmware/flock-node` stays out of the tree. Fuzzing needs
**nightly** plus `cargo-fuzz`:

```bash
rustup toolchain install nightly
cargo install cargo-fuzz
```

## Targets

| Target | Function | Surface |
|---|---|---|
| `hci_packet`    | `hci::parse_hci_packet`    | raw HCI datagrams off the scan socket (dispatches to the legacy + extended advertising-report parsers) |
| `ad_structures` | `hci::parse_ad_structures` | advertisement-data decode (names, UUIDs, manufacturer / service data) in isolation |
| `att_pdu`       | `att::parse`               | ATT PDUs from a connected peripheral over L2CAP |

## Run

```bash
cd fuzz
cargo +nightly fuzz run hci_packet
cargo +nightly fuzz run ad_structures
cargo +nightly fuzz run att_pdu
```

A crash writes a reproducer under `artifacts/<target>/`; replay it with
`cargo +nightly fuzz run <target> artifacts/<target>/<crash>`.

## Always-on complement

`cargo fuzz` needs nightly and isn't a per-PR gate. The stable-toolchain
`tests/parser_no_panic.rs` integration test feeds these same
parsers a large deterministic mix of random and seed-mutated bytes on **every**
CI run, so the no-panic property is regression-gated even without a fuzz job.

[cf]: https://rust-fuzz.github.io/book/cargo-fuzz.html
