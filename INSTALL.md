# Installing rustle

rustle is a Rust library. Nothing needs installing on the system beyond a
Rust toolchain. The steps below take a fresh machine to a passing test run
and a working scan.

## Requirements

- Rust 1.88 or newer on the stable channel.
- Linux with the BlueZ kernel sockets, to reach a radio. Any other OS
  builds the crate and runs the pure tests.
- A Bluetooth controller that supports Low Energy.

The crate has no dependencies. It needs no C libraries, no D-Bus daemon and
no other crates.

Install or update the toolchain with rustup:

```bash
rustup toolchain install stable
```

## Add the crate to a project

rustle is not on crates.io, because that name belongs to another crate.
Depend on the repository instead. Pin a commit so builds stay reproducible.
There are no release tags yet.

```toml
[dependencies]
rustle = { git = "https://github.com/herbenderbler/rustle", rev = "<commit>" }
```

Replace `<commit>` with the hash you want to track.

## Build from source

Clone the repository and run the tests. The suite includes a parser harness
that feeds the decoders a large mix of random bytes, so it takes a few
seconds.

```bash
git clone https://github.com/herbenderbler/rustle
```

```bash
cd rustle
```

```bash
cargo test
```

The tests pass on any OS. Only a Linux build can talk to hardware.

## Grant socket permissions

The raw HCI socket and the L2CAP socket need the `CAP_NET_RAW` capability.
Give it to the binary that uses rustle. A rebuild writes a new file, so run
the command again after every build.

```bash
sudo setcap cap_net_raw+ep target/debug/myapp
```

Running the program as root works too.

## Free the adapter

rustle sends scan commands straight to the controller. The kernel lets
only one host stack drive a controller, and `bluetoothd` is that stack on
most desktops. While it runs, raw scan commands fail with Command
Disallowed.

Stopping the daemon frees the controller. It also disconnects everything
else on that adapter, such as a mouse or headphones, until the daemon is
started again. Use a second adapter, such as a USB dongle, if you need
both at once.

Stop the daemon before scanning:

```bash
sudo systemctl stop bluetooth
```

If the controller is down afterwards, bring it up:

```bash
sudo hciconfig hci0 up
```

`btmgmt power on` from the newer BlueZ tools does the same. If the radio is
blocked in software, unblock it first:

```bash
sudo rfkill unblock bluetooth
```

Start the daemon again when you are done:

```bash
sudo systemctl start bluetooth
```

## Check the install

Build the example scanner, grant it the capability and run it. It listens
on `hci0` for ten seconds and prints every advertisement it hears.

```bash
cargo build --example scan
```

```bash
sudo setcap cap_net_raw+ep target/debug/examples/scan
```

```bash
target/debug/examples/scan hci0 10
```

Each line shows an address, the RSSI and the local name when the device
sends one. A summary line gives the report count at the end. Pass another
interface name or another number of seconds as needed.

To go one step further, build `examples/battery.rs` the same way and run
it with the start of a nearby device's name. It connects to the device
and reads its battery level. [USAGE.md](USAGE.md) explains each step.

## Test in a container

The repository's `Dockerfile` builds rustle and both examples on the latest
Ubuntu LTS, with the BlueZ tools installed. It is a quick way to try the
examples against a real adapter without touching the toolchain on the
machine. Build the image from the repository root:

```bash
docker build -t rustle .
```

The container needs three things to reach a controller. Bluetooth sockets
belong to the network namespace, so it must share the machine's with
`--net=host`. `NET_RAW` opens the raw sockets. `NET_ADMIN` lets `btmgmt`
power the adapter on. The machine's `bluetoothd` still owns the controller
from inside the container, so stop it first, as described above.

```bash
docker run --rm -it --net=host --cap-add=NET_RAW --cap-add=NET_ADMIN rustle
```

Inside the container you are root, so `setcap` is not needed. Bring the
adapter up and run the examples:

```bash
btmgmt power on
```

```bash
target/debug/examples/scan hci0 10
```

```bash
target/debug/examples/battery Polar
```

`btmgmt --index 1 power on` targets a second adapter. `cargo test --locked`
inside the container runs the suite on Ubuntu's libc. Pass
`--build-arg UBUNTU_VERSION=24.04` to `docker build` to try another
release.

## Contributor checks

CI runs three checks beyond the tests. Run them before opening a pull
request.

Formatting:

```bash
cargo fmt --all -- --check
```

Lints, with warnings treated as errors:

```bash
cargo clippy --all-targets -- -D warnings
```

Documentation, with broken links treated as errors:

```bash
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps
```

## Fuzzing

The byte parsers have `cargo-fuzz` targets under `fuzz/`. They need a
nightly toolchain. See [fuzz/README.md](fuzz/README.md).
