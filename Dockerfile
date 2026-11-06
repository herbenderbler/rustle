# rustle on the latest Ubuntu LTS, for trying the examples against a real
# adapter from a container. INSTALL.md, under "Test in a container", has the
# build and run commands.
#
# Bluetooth sockets belong to the network namespace, so the container must
# share the host's with --net=host. NET_RAW lets the examples send commands
# to the controller. NET_ADMIN lets btmgmt power the adapter on, and lets an
# active scan end the device discovery the kernel believes it started. The
# host's bluetoothd still runs beside the container, so stop it on the host.

ARG UBUNTU_VERSION=26.04
FROM ubuntu:${UBUNTU_VERSION}

ARG RUST_TOOLCHAIN=stable
ENV DEBIAN_FRONTEND=noninteractive \
    RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH

# bluez brings btmgmt and btmon. usbutils brings lsusb, to find a USB
# dongle. The rest builds Rust code and fetches rustup.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bluez \
        build-essential \
        ca-certificates \
        curl \
        usbutils \
    && rm -rf /var/lib/apt/lists/*

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --profile minimal --default-toolchain "${RUST_TOOLCHAIN}"

WORKDIR /src
COPY . .

# Build the library, the tests and the three examples now, so a container starts
# with everything ready to run.
RUN cargo build --locked --all-targets

CMD ["bash"]
