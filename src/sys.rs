//! Linux libc bindings shared by the socket layers ([`crate::adapter`],
//! [`crate::conn`], [`crate::l2cap`], [`crate::mgmt`], [`crate::scan`]).
//!
//! Declared by hand — a few `extern "C"` symbols, the socket constants and the
//! `#[repr(C)]` structs the BlueZ sockets take — so the crate stays
//! dependency-free. [`Socket`] owns a descriptor and wraps the calls every
//! layer makes; the L2CAP layer keeps its own sockaddr and options.

use crate::hci_io::HciIo;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::raw::{c_int, c_long, c_ulong, c_void};
use std::time::Duration;

pub(crate) const AF_BLUETOOTH: c_int = 31;
pub(crate) const SOCK_RAW: c_int = 3;
pub(crate) const SOCK_SEQPACKET: c_int = 5;
pub(crate) const BTPROTO_L2CAP: c_int = 0;
pub(crate) const BTPROTO_HCI: c_int = 1;
pub(crate) const SOL_SOCKET: c_int = 1;
pub(crate) const SO_RCVTIMEO: c_int = 20;
pub(crate) const SO_ERROR: c_int = 4;
pub(crate) const EINPROGRESS: i32 = 115;

/// HCI socket channels: raw HCI packets, and the management interface.
pub(crate) const HCI_CHANNEL_RAW: u16 = 0;
pub(crate) const HCI_CHANNEL_CONTROL: u16 = 3;
/// The controller index a management socket binds to: none in particular.
pub(crate) const HCI_DEV_NONE: u16 = 0xFFFF;
const SOL_HCI: c_int = 0;
const HCI_FILTER: c_int = 2;
/// `HCI_FILTER` type-mask bit for event packets (`HCI_EVENT_PKT` = 4).
const HCI_FILTER_EVENTS: u32 = 1 << 4;

// `fcntl` file-status flags. Like the socket constants above, these are the
// asm-generic values shared by x86 / arm / arm64 / riscv.
pub(crate) const F_GETFL: c_int = 3;
pub(crate) const F_SETFL: c_int = 4;
pub(crate) const O_NONBLOCK: c_int = 0o4000;

/// `poll` "writable" event bit (`events` / `revents` are `short`).
pub(crate) const POLLOUT: i16 = 0x0004;
/// `poll` error bit. Always reported in `revents`, even when not requested.
pub(crate) const POLLERR: i16 = 0x0008;
/// `poll` hang-up bit. Always reported in `revents`, even when not requested.
pub(crate) const POLLHUP: i16 = 0x0010;

/// `struct pollfd` for `poll`.
#[repr(C)]
pub(crate) struct PollFd {
    pub fd: c_int,
    pub events: i16,
    pub revents: i16,
}

/// `struct sockaddr_hci`.
#[repr(C)]
struct SockaddrHci {
    hci_family: u16,
    hci_dev: u16,
    hci_channel: u16,
}

/// `struct hci_filter` for the `HCI_FILTER` socket option.
#[repr(C)]
struct HciFilter {
    type_mask: u32,
    event_mask: [u32; 2],
    opcode: u16,
    // The struct is 16 bytes (align 4) but the fields above end at offset 14,
    // so this explicit trailing pad keeps the two padding bytes handed to
    // setsockopt (via `size_of`) initialized rather than crossing the FFI
    // boundary uninitialized. Layout/size are unchanged.
    _pad: u16,
}

/// `struct timeval` for `SO_RCVTIMEO`: two `c_long`s (`time_t` / `suseconds_t`
/// are `long` for the legacy socket option). Using `c_long` keeps the layout
/// correct on both 64-bit and 32-bit targets, where a hardcoded i64 would be an
/// ABI mismatch and the timeout would silently not apply.
#[repr(C)]
pub(crate) struct Timeval {
    pub tv_sec: c_long,
    pub tv_usec: c_long,
}

impl Timeval {
    pub(crate) fn from_duration(d: Duration) -> Self {
        Timeval {
            tv_sec: d.as_secs() as c_long,
            tv_usec: d.subsec_micros() as c_long,
        }
    }
}

extern "C" {
    pub(crate) fn socket(domain: c_int, ty: c_int, protocol: c_int) -> c_int;
    pub(crate) fn bind(fd: c_int, addr: *const c_void, len: u32) -> c_int;
    pub(crate) fn connect(fd: c_int, addr: *const c_void, len: u32) -> c_int;
    pub(crate) fn setsockopt(
        fd: c_int,
        level: c_int,
        optname: c_int,
        optval: *const c_void,
        optlen: u32,
    ) -> c_int;
    pub(crate) fn getsockopt(
        fd: c_int,
        level: c_int,
        optname: c_int,
        optval: *mut c_void,
        optlen: *mut u32,
    ) -> c_int;
    pub(crate) fn ioctl(fd: c_int, request: c_ulong, arg: *mut c_void) -> c_int;
    pub(crate) fn fcntl(fd: c_int, cmd: c_int, ...) -> c_int;
    pub(crate) fn poll(fds: *mut PollFd, nfds: c_ulong, timeout: c_int) -> c_int;
    pub(crate) fn write(fd: c_int, buf: *const c_void, count: usize) -> isize;
    pub(crate) fn read(fd: c_int, buf: *mut c_void, count: usize) -> isize;
}

/// `0` or a positive count from a libc call, or the `errno` it set.
fn check(rc: isize) -> io::Result<usize> {
    usize::try_from(rc).map_err(|_| io::Error::last_os_error())
}

/// Set an option whose value is the `#[repr(C)]` struct `val`.
fn set_option<T>(fd: c_int, level: c_int, name: c_int, val: &T) -> io::Result<()> {
    let rc = unsafe {
        setsockopt(
            fd,
            level,
            name,
            val as *const T as *const c_void,
            std::mem::size_of::<T>() as u32,
        )
    };
    check(rc as isize).map(drop)
}

/// An owned Bluetooth socket, closed on drop. It is also the crate's raw HCI
/// transport, so a driver can own the socket it talks to.
pub(crate) struct Socket(OwnedFd);

impl Socket {
    /// Open an `AF_BLUETOOTH` socket of type `ty` for `protocol`.
    pub(crate) fn open(ty: c_int, protocol: c_int) -> io::Result<Socket> {
        let fd = unsafe { socket(AF_BLUETOOTH, ty, protocol) };
        check(fd as isize)?;
        // SAFETY: `socket` just returned this descriptor, and nothing else owns it.
        Ok(Socket(unsafe { OwnedFd::from_raw_fd(fd) }))
    }

    /// Open a raw HCI socket. It needs binding before it carries anything.
    pub(crate) fn hci() -> io::Result<Socket> {
        Socket::open(SOCK_RAW, BTPROTO_HCI)
    }

    pub(crate) fn fd(&self) -> c_int {
        self.0.as_raw_fd()
    }

    /// Bind an HCI socket to controller `dev` on `channel`.
    pub(crate) fn bind_hci(&self, dev: u16, channel: u16) -> io::Result<()> {
        let addr = SockaddrHci {
            hci_family: AF_BLUETOOTH as u16,
            hci_dev: dev,
            hci_channel: channel,
        };
        let rc = unsafe {
            bind(
                self.fd(),
                &addr as *const SockaddrHci as *const c_void,
                std::mem::size_of::<SockaddrHci>() as u32,
            )
        };
        check(rc as isize).map(drop)
    }

    /// Deliver only HCI event packets, and only the event codes whose bits
    /// `event_mask` sets.
    pub(crate) fn set_hci_event_filter(&self, event_mask: [u32; 2]) -> io::Result<()> {
        let filter = HciFilter {
            type_mask: HCI_FILTER_EVENTS,
            event_mask,
            opcode: 0,
            _pad: 0,
        };
        set_option(self.fd(), SOL_HCI, HCI_FILTER, &filter)
    }

    /// Set `SO_RCVTIMEO`, so a read waits at most `timeout`. Zero disables it.
    pub(crate) fn set_recv_timeout(&self, timeout: Duration) -> io::Result<()> {
        set_option(
            self.fd(),
            SOL_SOCKET,
            SO_RCVTIMEO,
            &Timeval::from_duration(timeout),
        )
    }

    /// One `write`, returning how many bytes went out.
    pub(crate) fn write(&self, buf: &[u8]) -> io::Result<usize> {
        check(unsafe { write(self.fd(), buf.as_ptr() as *const c_void, buf.len()) })
    }

    /// Write all of `pkt` in one call. On a datagram socket a short write is
    /// [`io::ErrorKind::WriteZero`].
    pub(crate) fn write_packet(&self, pkt: &[u8]) -> io::Result<()> {
        if self.write(pkt)? == pkt.len() {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "short socket write",
            ))
        }
    }

    /// One `read`, returning how many bytes arrived. Zero means the other end
    /// closed the socket.
    pub(crate) fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        check(unsafe { read(self.fd(), buf.as_mut_ptr() as *mut c_void, buf.len()) })
    }
}

impl HciIo for Socket {
    fn write_packet(&mut self, pkt: &[u8]) -> io::Result<()> {
        Socket::write_packet(self, pkt)
    }

    fn read_packet(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.read(buf)? {
            0 => Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "controller closed the HCI socket",
            )),
            n => Ok(n),
        }
    }
}
