# Fuzzing the rustle byte parsers

rustle decodes advertisements and ATT PDUs sent by devices it does not
control. The parsers are safe Rust, but safe code can still panic. The
[`cargo fuzz`][cf] targets here search for input that makes a parser panic.
Such a panic is more than a bug. A nearby device could send those bytes on
purpose and crash any program that scans or connects with rustle.

This crate is its own workspace. Its `Cargo.toml` declares an empty
`[workspace]`, so the main build and CI never build it. Fuzzing needs nightly
Rust and `cargo-fuzz`:

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
