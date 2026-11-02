//! Raw-HCI LE scanning: program a controller to scan and read back its
//! advertising reports.
//!
//! Two layers, like the rest of the crate:
//!
//! - **Pure, every platform:** [`ScanParams`] (what to program) and the HCI
//!   parameter encoders behind it, plus [`ScanError`] / [`ScanStart`]. Unit-
//!   tested against the Core-spec layouts with no radio.
//! - **Linux only:** [`HciScanner`], which owns an `AF_BLUETOOTH` raw HCI socket
//!   bound to one controller. It needs `CAP_NET_RAW` (or root) and a controller
//!   that `bluetoothd` is not holding. On other platforms the type exists but
//!   [`HciScanner::open`] returns [`ScanError::Unsupported`].
//!
//! The scanner is deliberately policy-free: it hands back raw HCI datagrams.
//! Feed each one to [`crate::hci::parse_hci_packet`] for the decoded reports
//! and, on an active scan, through a [`crate::scan_merge::ScanMerger`] to pair
//! each scannable advertisement with its `SCAN_RSP`.
//!
//! # Passive vs active
//!
//! [`ScanType::Passive`] programs `scan_type = 0x00`: the controller only
//! listens and transmits nothing. [`ScanType::Active`] programs `0x01`: the
//! controller answers scannable advertisements with a `SCAN_REQ` carrying its
//! own address, and [`OwnAddrType`] selects whether that is the public
//! (hardware) address or the random address previously set on the controller.
//! [`ScanParams::default`] is passive.
//!
//! # Extended vs legacy
//!
//! [`HciScanner::start`] prefers the Bluetooth 5 *extended* scan command set
//! (so extended-advertising PDUs are seen as well as the legacy adverts they
//! wrap) and falls back to the legacy commands on a controller that rejects
//! it; the returned [`ScanStart`] says which one took.

use std::fmt;
use std::io;

// ---------------------------------------------------------------------------
// HCI opcodes (OGF 0x08 = LE Controller), as the u16 the Command Complete /
// Command Status events echo back.
// ---------------------------------------------------------------------------

/// LE Set Scan Parameters (OCF 0x000B).
pub const OPCODE_LE_SET_SCAN_PARAMS: u16 = 0x200B;
/// LE Set Scan Enable (OCF 0x000C).
pub const OPCODE_LE_SET_SCAN_ENABLE: u16 = 0x200C;
/// LE Set Extended Scan Parameters (OCF 0x0041, Bluetooth 5).
pub const OPCODE_LE_SET_EXT_SCAN_PARAMS: u16 = 0x2041;
/// LE Set Extended Scan Enable (OCF 0x0042, Bluetooth 5).
pub const OPCODE_LE_SET_EXT_SCAN_ENABLE: u16 = 0x2042;

/// Default scan interval, in units of 0.625 ms (`0x0010` = 10 ms).
pub const DEFAULT_SCAN_INTERVAL: u16 = 0x0010;
/// Default scan window, in units of 0.625 ms. Equal to the interval, so the
/// controller listens continuously rather than duty-cycling.
pub const DEFAULT_SCAN_WINDOW: u16 = 0x0010;

/// Whether the controller transmits while scanning.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScanType {
    /// `scan_type = 0x00`: listen only. No `SCAN_REQ` is ever sent, so the
    /// scan is RF-silent.
    Passive,
    /// `scan_type = 0x01`: answer scannable advertisements with a `SCAN_REQ`
    /// (carrying the address [`OwnAddrType`] selects) to solicit a `SCAN_RSP`.
    Active,
}

impl ScanType {
    /// The HCI `LE_Scan_Type` byte.
    pub fn as_u8(self) -> u8 {
        match self {
            ScanType::Passive => 0x00,
            ScanType::Active => 0x01,
        }
    }
}

/// Which local address an active scan's `SCAN_REQ` carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OwnAddrType {
    /// `0x00`: the controller's public (hardware) address.
    Public,
    /// `0x01`: the random address previously programmed with `LE Set Random
    /// Address`. The scanner does not set one; the caller is responsible for
    /// programming it before starting an active scan with this type.
    Random,
}

impl OwnAddrType {
    /// The HCI `Own_Address_Type` byte.
    pub fn as_u8(self) -> u8 {
        match self {
            OwnAddrType::Public => 0x00,
            OwnAddrType::Random => 0x01,
        }
    }
}

/// What to program the controller with. `interval` and `window` are in units
/// of 0.625 ms; `window <= interval`, and equal values request a continuous
/// listen. The filter policy is always "accept all" and duplicate filtering is
/// always off, so every advertisement is reported.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScanParams {
    pub scan_type: ScanType,
    pub own_addr_type: OwnAddrType,
    pub interval: u16,
    pub window: u16,
}

impl Default for ScanParams {
    /// A passive scan from the public address at the default continuous
    /// interval / window — the RF-silent choice.
    fn default() -> Self {
        ScanParams::new(ScanType::Passive, OwnAddrType::Public)
    }
}

impl ScanParams {
    /// `scan_type` / `own_addr_type` with the default continuous interval and
    /// window.
    pub fn new(scan_type: ScanType, own_addr_type: OwnAddrType) -> Self {
        ScanParams {
            scan_type,
            own_addr_type,
            interval: DEFAULT_SCAN_INTERVAL,
            window: DEFAULT_SCAN_WINDOW,
        }
    }

    /// Parameters for `LE Set Scan Parameters`:
    /// `scan_type, interval(2), window(2), own_addr_type, filter_policy`.
    pub fn legacy_params(&self) -> [u8; 7] {
        let iv = self.interval.to_le_bytes();
        let win = self.window.to_le_bytes();
        [
            self.scan_type.as_u8(),
            iv[0],
            iv[1],
            win[0],
            win[1],
            self.own_addr_type.as_u8(),
            0x00, // filter_policy = accept all
        ]
    }

    /// Parameters for `LE Set Extended Scan Parameters` on the LE 1M PHY only:
    /// `own_addr_type, filter_policy, scanning_PHYs, scan_type, interval(2),
    /// window(2)`.
    pub fn extended_params(&self) -> [u8; 8] {
        let iv = self.interval.to_le_bytes();
        let win = self.window.to_le_bytes();
        [
            self.own_addr_type.as_u8(),
            0x00, // filter_policy = accept all
            0x01, // scanning_PHYs = LE 1M
            self.scan_type.as_u8(),
            iv[0],
            iv[1],
            win[0],
            win[1],
        ]
    }
}

/// Parameters for `LE Set Scan Enable`: `enable, filter_duplicates` (off).
pub fn legacy_enable_params(enable: bool) -> [u8; 2] {
    [enable as u8, 0x00]
}

/// Parameters for `LE Set Extended Scan Enable`:
/// `enable, filter_duplicates (off), duration(2) = 0 (until disabled),
/// period(2) = 0 (no periodic scanning)`.
pub fn extended_enable_params(enable: bool) -> [u8; 6] {
    [enable as u8, 0x00, 0x00, 0x00, 0x00, 0x00]
}

/// Which command set a scan was programmed with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScanMode {
    /// The Bluetooth 5 extended scan commands: extended-advertising PDUs are
    /// reported as well as legacy ones.
    Extended,
    /// The legacy scan commands: only legacy advertising PDUs are reported.
    Legacy,
}

/// Why opening the socket or talking to the controller failed. The `open`
/// stages are distinguished so a caller can give a precise hint (permissions
/// vs. a missing adapter).
#[derive(Debug)]
pub enum ScanError {
    /// `socket()` failed — usually missing `CAP_NET_RAW` / not root.
    Socket(io::Error),
    /// `bind()` to the controller index failed — the adapter is absent or down.
    Bind(io::Error),
    /// Setting the HCI event filter failed; without it no events are delivered.
    Filter(io::Error),
    /// Setting the receive timeout failed.
    RecvTimeout(io::Error),
    /// An HCI command could not be written in full.
    ShortWrite,
    /// The controller answered a command with a non-zero status (`0x01` =
    /// Unknown HCI Command, `0x0C` = Command Disallowed, …).
    Rejected { opcode: u16, status: u8 },
    /// A read error while waiting for a command's completion event.
    Io(io::Error),
    /// No Command Complete / Command Status event arrived for the command
    /// within the bounded wait.
    NoResponse,
    /// This platform has no raw HCI socket.
    Unsupported,
}

impl fmt::Display for ScanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScanError::Socket(e) => write!(f, "cannot open raw HCI socket ({e})"),
            ScanError::Bind(e) => write!(f, "cannot bind controller ({e})"),
            ScanError::Filter(e) => write!(f, "cannot set HCI event filter ({e})"),
            ScanError::RecvTimeout(e) => write!(f, "cannot set receive timeout ({e})"),
            ScanError::ShortWrite => write!(f, "short write to HCI socket"),
            ScanError::Rejected { opcode, status } => write!(
                f,
                "controller rejected command 0x{opcode:04x} (status 0x{status:02x})"
            ),
            ScanError::Io(e) => write!(f, "read error awaiting command response ({e})"),
            ScanError::NoResponse => write!(f, "no Command Complete/Status from controller"),
            ScanError::Unsupported => write!(f, "raw HCI scanning is only supported on Linux"),
        }
    }
}

impl std::error::Error for ScanError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ScanError::Socket(e)
            | ScanError::Bind(e)
            | ScanError::Filter(e)
            | ScanError::RecvTimeout(e)
            | ScanError::Io(e) => Some(e),
            _ => None,
        }
    }
}

/// A started scan: which command set took, and — when the controller rejected
/// the extended set and the legacy one was used instead — why.
#[derive(Debug)]
pub struct ScanStart {
    pub mode: ScanMode,
    pub fallback: Option<ScanError>,
}

// ===========================================================================
// Linux-only raw HCI socket
// ===========================================================================

#[cfg(target_os = "linux")]
pub use linux_impl::HciScanner;

#[cfg(target_os = "linux")]
mod linux_impl {
    use super::*;
    use crate::hci::{build_command, parse_command_event};
    use crate::sys::{
        bind, close, read, set_recv_timeout, setsockopt, socket, write, FdGuard, Timeval,
        AF_BLUETOOTH, BTPROTO_HCI, SOCK_RAW,
    };
    use std::os::raw::{c_int, c_void};
    use std::time::Duration;

    const HCI_CHANNEL_RAW: u16 = 0;
    const SOL_HCI: c_int = 0;
    const HCI_FILTER: c_int = 2;

    #[repr(C)]
    struct SockaddrHci {
        hci_family: u16,
        hci_dev: u16,
        hci_channel: u16,
    }

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

    /// A raw HCI socket bound to one controller, programmed for LE scanning.
    ///
    /// Dropping the scanner stops any scan it may have started (best-effort,
    /// in both command sets) and closes the socket, so a controller is never
    /// left scanning after its handle goes away.
    pub struct HciScanner {
        fd: c_int,
        dev: u16,
        /// Set once [`HciScanner::start`] has sent an enable command, whether or
        /// not it was confirmed; cleared by [`HciScanner::stop`].
        scanning: bool,
    }

    impl Drop for HciScanner {
        fn drop(&mut self) {
            self.stop();
            unsafe { close(self.fd) };
        }
    }

    impl HciScanner {
        /// Open a raw HCI socket bound to controller index `dev` (`hciN` → `N`),
        /// filtered to deliver every HCI event, with `recv_timeout` applied as
        /// `SO_RCVTIMEO` so [`HciScanner::read`] returns
        /// [`io::ErrorKind::WouldBlock`] when nothing arrives in time (and a
        /// read loop can poll a shutdown flag). `Duration::ZERO` disables the
        /// timeout and makes reads block indefinitely.
        pub fn open(dev: u16, recv_timeout: Duration) -> Result<Self, ScanError> {
            let fd = unsafe { socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI) };
            if fd < 0 {
                return Err(ScanError::Socket(io::Error::last_os_error()));
            }
            let guard = FdGuard(fd);

            let addr = SockaddrHci {
                hci_family: AF_BLUETOOTH as u16,
                hci_dev: dev,
                hci_channel: HCI_CHANNEL_RAW,
            };
            let rc = unsafe {
                bind(
                    fd,
                    &addr as *const SockaddrHci as *const c_void,
                    std::mem::size_of::<SockaddrHci>() as u32,
                )
            };
            if rc < 0 {
                return Err(ScanError::Bind(io::Error::last_os_error()));
            }

            // Receive all event packets (type_mask bit for HCI_EVENT_PKT = 1<<4),
            // every event code (event_mask all ones).
            let filter = HciFilter {
                type_mask: 1 << 4,
                event_mask: [0xffff_ffff, 0xffff_ffff],
                opcode: 0,
                _pad: 0,
            };
            let rc = unsafe {
                setsockopt(
                    fd,
                    SOL_HCI,
                    HCI_FILTER,
                    &filter as *const HciFilter as *const c_void,
                    std::mem::size_of::<HciFilter>() as u32,
                )
            };
            if rc < 0 {
                return Err(ScanError::Filter(io::Error::last_os_error()));
            }

            let rc = set_recv_timeout(fd, &Timeval::from_duration(recv_timeout));
            if rc < 0 {
                return Err(ScanError::RecvTimeout(io::Error::last_os_error()));
            }

            std::mem::forget(guard); // success — ownership moves to HciScanner
            Ok(HciScanner {
                fd,
                dev,
                scanning: false,
            })
        }

        /// The controller index this scanner is bound to.
        pub fn dev(&self) -> u16 {
            self.dev
        }

        /// Program and enable scanning. Any scan already in progress (in either
        /// command set) is disabled first. The extended command set is tried
        /// first; if the controller rejects it the legacy set is programmed
        /// instead and the rejection is reported as [`ScanStart::fallback`].
        /// An error means neither set could be *confirmed* enabled (typically
        /// another process owns the controller); the scanner still sends the
        /// disables on [`HciScanner::stop`] / drop, in case an enable was
        /// accepted but its completion event lost.
        pub fn start(&mut self, params: ScanParams) -> Result<ScanStart, ScanError> {
            // Best-effort pre-clear: the status of a disable is uninteresting.
            self.write_command(OPCODE_LE_SET_SCAN_ENABLE, &legacy_enable_params(false));
            self.write_command(
                OPCODE_LE_SET_EXT_SCAN_ENABLE,
                &extended_enable_params(false),
            );
            // From here on the controller may be scanning even if this call
            // fails — an enable can be accepted while its completion event is
            // lost under a flood of queued reports — so `stop()` / Drop must
            // send the disables regardless of the outcome.
            self.scanning = true;
            let start = match self.start_extended(&params) {
                Ok(()) => ScanStart {
                    mode: ScanMode::Extended,
                    fallback: None,
                },
                Err(ext_err) => {
                    self.start_legacy(&params)?;
                    ScanStart {
                        mode: ScanMode::Legacy,
                        fallback: Some(ext_err),
                    }
                }
            };
            Ok(start)
        }

        fn start_extended(&mut self, params: &ScanParams) -> Result<(), ScanError> {
            self.command(OPCODE_LE_SET_EXT_SCAN_PARAMS, &params.extended_params())?;
            self.command(OPCODE_LE_SET_EXT_SCAN_ENABLE, &extended_enable_params(true))
        }

        fn start_legacy(&mut self, params: &ScanParams) -> Result<(), ScanError> {
            self.command(OPCODE_LE_SET_SCAN_PARAMS, &params.legacy_params())?;
            self.command(OPCODE_LE_SET_SCAN_ENABLE, &legacy_enable_params(true))
        }

        /// Disable scanning if [`HciScanner::start`] was attempted (best-effort,
        /// in both command sets — the unused one is a harmless no-op). Also run
        /// on drop; calling it explicitly just makes the stop point visible.
        pub fn stop(&mut self) {
            if self.scanning {
                self.write_command(OPCODE_LE_SET_SCAN_ENABLE, &legacy_enable_params(false));
                self.write_command(
                    OPCODE_LE_SET_EXT_SCAN_ENABLE,
                    &extended_enable_params(false),
                );
                self.scanning = false;
            }
        }

        /// Read one HCI datagram into `buf`, returning its length (always > 0).
        /// A 512-byte buffer holds any HCI event.
        ///
        /// Errors: [`io::ErrorKind::WouldBlock`] when the receive timeout
        /// elapsed and [`io::ErrorKind::Interrupted`] on a signal — both mean
        /// "nothing yet, read again"; [`io::ErrorKind::UnexpectedEof`] when the
        /// controller closed the socket; anything else is a real socket error
        /// (the adapter was unplugged, reset or rfkill'd).
        pub fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let n = unsafe { read(self.fd, buf.as_mut_ptr() as *mut c_void, buf.len()) };
            if n > 0 {
                Ok(n as usize)
            } else if n == 0 {
                Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "controller closed the HCI socket",
                ))
            } else {
                Err(io::Error::last_os_error())
            }
        }

        /// Send one HCI command and wait for its Command Complete / Command
        /// Status event, returning `Ok(())` only if the controller accepted it
        /// (status `0x00`). Events for other opcodes (advertising reports
        /// included) are skipped. Bounded to a handful of reads, each limited
        /// by the receive timeout, so a controller that never answers can't
        /// hang the caller.
        pub fn command(&mut self, opcode: u16, params: &[u8]) -> Result<(), ScanError> {
            if !self.write_command(opcode, params) {
                return Err(ScanError::ShortWrite);
            }
            const MAX_WAIT: u32 = 8;
            let mut buf = [0u8; 512];
            for _ in 0..MAX_WAIT {
                match self.read(&mut buf) {
                    Ok(n) => {
                        if let Some((op, status)) = parse_command_event(&buf[..n]) {
                            if op == opcode {
                                return if status == 0 {
                                    Ok(())
                                } else {
                                    Err(ScanError::Rejected { opcode, status })
                                };
                            }
                        }
                    }
                    Err(e)
                        if matches!(
                            e.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                        ) =>
                    {
                        continue;
                    }
                    Err(e) => return Err(ScanError::Io(e)),
                }
            }
            Err(ScanError::NoResponse)
        }

        /// Write one HCI command without waiting for its completion event;
        /// `false` on a short or failed write.
        fn write_command(&mut self, opcode: u16, params: &[u8]) -> bool {
            let pkt = build_command(opcode, params);
            let n = unsafe { write(self.fd, pkt.as_ptr() as *const c_void, pkt.len()) };
            n == pkt.len() as isize
        }
    }
}

// ===========================================================================
// Every other platform: the type exists so downstream code compiles, but it
// can never be constructed.
// ===========================================================================

#[cfg(not(target_os = "linux"))]
pub use other_impl::HciScanner;

#[cfg(not(target_os = "linux"))]
mod other_impl {
    use super::*;
    use std::convert::Infallible;
    use std::time::Duration;

    /// Raw-HCI scanner handle. This platform has no raw HCI socket, so
    /// [`HciScanner::open`] always fails with [`ScanError::Unsupported`] and no
    /// value of this type can exist; the other methods match the Linux
    /// signatures so platform-generic code type-checks.
    pub struct HciScanner(Infallible);

    impl HciScanner {
        /// Always [`ScanError::Unsupported`] on this platform.
        pub fn open(_dev: u16, _recv_timeout: Duration) -> Result<Self, ScanError> {
            Err(ScanError::Unsupported)
        }

        pub fn dev(&self) -> u16 {
            match self.0 {}
        }

        pub fn start(&mut self, _params: ScanParams) -> Result<ScanStart, ScanError> {
            match self.0 {}
        }

        pub fn stop(&mut self) {
            match self.0 {}
        }

        pub fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            match self.0 {}
        }

        pub fn command(&mut self, _opcode: u16, _params: &[u8]) -> Result<(), ScanError> {
            match self.0 {}
        }
    }
}

// ===========================================================================
// Tests for the pure layer (run on every platform)
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_a_passive_scan_from_the_public_address() {
        let p = ScanParams::default();
        assert_eq!(p.scan_type, ScanType::Passive);
        assert_eq!(p.own_addr_type, OwnAddrType::Public);
        assert_eq!(p.interval, DEFAULT_SCAN_INTERVAL);
        assert_eq!(p.window, DEFAULT_SCAN_WINDOW);
        // Continuous listen: window == interval.
        assert_eq!(p.interval, p.window);
    }

    #[test]
    fn scan_and_address_type_bytes_follow_the_spec() {
        // The passive/active distinction is the RF-silence guarantee, so pin
        // the exact byte values rather than trusting the enum order.
        assert_eq!(ScanType::Passive.as_u8(), 0x00);
        assert_eq!(ScanType::Active.as_u8(), 0x01);
        assert_eq!(OwnAddrType::Public.as_u8(), 0x00);
        assert_eq!(OwnAddrType::Random.as_u8(), 0x01);
    }

    #[test]
    fn legacy_params_layout() {
        // scan_type, interval LE, window LE, own_addr_type, filter_policy.
        let p = ScanParams {
            scan_type: ScanType::Active,
            own_addr_type: OwnAddrType::Random,
            interval: 0x1234,
            window: 0x0010,
        };
        assert_eq!(
            p.legacy_params(),
            [0x01, 0x34, 0x12, 0x10, 0x00, 0x01, 0x00]
        );
        // Passive from the public address: both selector bytes are zero.
        let p = ScanParams::default();
        assert_eq!(p.legacy_params()[0], 0x00);
        assert_eq!(p.legacy_params()[5], 0x00);
    }

    #[test]
    fn extended_params_layout() {
        // own_addr_type, filter_policy, PHYs = LE 1M, then the per-PHY triple.
        let p = ScanParams {
            scan_type: ScanType::Active,
            own_addr_type: OwnAddrType::Random,
            interval: 0x1234,
            window: 0x0010,
        };
        assert_eq!(
            p.extended_params(),
            [0x01, 0x00, 0x01, 0x01, 0x34, 0x12, 0x10, 0x00]
        );
        let p = ScanParams::default();
        assert_eq!(p.extended_params()[0], 0x00); // public
        assert_eq!(p.extended_params()[3], 0x00); // passive
    }

    #[test]
    fn enable_params_never_filter_duplicates() {
        assert_eq!(legacy_enable_params(true), [0x01, 0x00]);
        assert_eq!(legacy_enable_params(false), [0x00, 0x00]);
        // Extended: enable, no dup filter, duration 0 (until disabled),
        // period 0 (no periodic scanning).
        assert_eq!(extended_enable_params(true), [0x01, 0, 0, 0, 0, 0]);
        assert_eq!(extended_enable_params(false), [0x00, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn opcodes_are_the_le_controller_ogf() {
        // OGF 0x08 occupies the top six bits: every LE opcode is 0x20xx.
        for op in [
            OPCODE_LE_SET_SCAN_PARAMS,
            OPCODE_LE_SET_SCAN_ENABLE,
            OPCODE_LE_SET_EXT_SCAN_PARAMS,
            OPCODE_LE_SET_EXT_SCAN_ENABLE,
        ] {
            assert_eq!(op >> 10, 0x08, "opcode 0x{op:04x}");
        }
    }

    #[test]
    fn error_display_names_the_rejected_opcode_and_status() {
        let e = ScanError::Rejected {
            opcode: OPCODE_LE_SET_EXT_SCAN_PARAMS,
            status: 0x01,
        };
        assert_eq!(
            e.to_string(),
            "controller rejected command 0x2041 (status 0x01)"
        );
        assert!(ScanError::Unsupported.to_string().contains("Linux"));
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn open_is_unsupported_off_linux() {
        assert!(matches!(
            HciScanner::open(0, std::time::Duration::from_secs(1)),
            Err(ScanError::Unsupported)
        ));
    }
}
