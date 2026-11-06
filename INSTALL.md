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

Running the program as root works too. Without the capability the raw
socket still opens, but the kernel refuses the scan commands, so the error
is a `Write` error of kind `PermissionDenied`.

## Free the adapter

rustle sends scan commands straight to the controller. Neither the kernel
nor `bluetoothd`, the Bluetooth daemon on most desktops, is told about
them, and rustle is not told about theirs.

Starting a scan first turns off any scan already running on the
controller, including one the kernel runs for `bluetoothd`. The kernel
does not notice. If that scan belonged to a device discovery, the
discovery never finishes, and the kernel refuses new ones on that adapter
until the stuck one is stopped. "Recover a stuck discovery" below shows
how.

An idle `bluetoothd` does not get in the way, but stopping it is the only
way to be sure nothing else scans on the adapter. Stopping it also
disconnects everything else on that adapter, such as a mouse or
headphones, until the daemon is started again. If you need both at once,
give rustle an adapter of its own, such as a USB dongle, and do not start
discoveries on it.

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

### Recover a stuck discovery

If `bluetoothd` stops finding devices after a rustle scan, and
`btmgmt find` fails with `Busy`, stop the discovery that rustle's scan
interrupted:

```bash
sudo btmgmt --index 0 stop-find
```

If that fails with `Invalid Parameters`, the discovery looked for Low
Energy devices only. Add `-l`:

```bash
sudo btmgmt --index 0 stop-find -l
```

Powering the adapter off and on also clears it.

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

The repository's `Dockerfile` builds rustle and its examples on the latest
Ubuntu LTS, with the BlueZ tools installed. It is a quick way to try the
examples against a real adapter without touching the toolchain on the
machine.

Run the container with Docker Engine on the Linux machine the adapter is
plugged into. Docker Desktop, on any operating system, runs containers in
a virtual machine with no Bluetooth, so the examples and `btmgmt` cannot
reach an adapter there. Build the image from the repository root:

```bash
docker build -t rustle .
```

The container needs three things to reach a controller. Bluetooth sockets
belong to the network namespace, so it must share the machine's with
`--net=host`. `NET_RAW` is the capability from "Grant socket permissions"
above. Docker grants it to every container by default, and the flag keeps
the command working under runtimes that do not. `NET_ADMIN` lets `btmgmt` power the adapter on. The
machine's `bluetoothd` still runs beside the container, so stop it first,
as described above.

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
