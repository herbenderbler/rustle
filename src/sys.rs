//! Linux libc bindings shared by the socket layers ([`crate::adapter`],
//! [`crate::l2cap`], [`crate::scan`]).
//!
//! Declared by hand — a few `extern "C"` symbols, the socket constants and the
//! two `#[repr(C)]` structs the BlueZ socket options take — so the crate stays
//! dependency-free. Private to the crate; each socket module keeps only its own
//! protocol-specific constants and sockaddr layouts.

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
pub(crate) const EAGAIN: i32 = 11;
pub(crate) const EINTR: i32 = 4;
pub(crate) const EINPROGRESS: i32 = 115;

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

    pub(crate) fn from_secs(secs: i64) -> Self {
        Timeval {
            tv_sec: secs as c_long,
            tv_usec: 0,
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
    pub(crate) fn close(fd: c_int) -> c_int;
    fn __errno_location() -> *mut c_int;
}

/// The calling thread's `errno`, read immediately after a failed call.
pub(crate) unsafe fn errno() -> i32 {
    *__errno_location()
}

/// Set `SO_RCVTIMEO` on `fd`; `rc < 0` on failure (errno is then set).
pub(crate) fn set_recv_timeout(fd: c_int, tv: &Timeval) -> c_int {
    unsafe {
        setsockopt(
            fd,
            SOL_SOCKET,
            SO_RCVTIMEO,
            tv as *const Timeval as *const c_void,
            std::mem::size_of::<Timeval>() as u32,
        )
    }
}

/// Closes an fd on early return unless disarmed with `mem::forget`.
pub(crate) struct FdGuard(pub c_int);

impl Drop for FdGuard {
    fn drop(&mut self) {
        unsafe { close(self.0) };
    }
}
