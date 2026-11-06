//! Raw-HCI LE scanning: program a controller to scan and read back its
//! advertising reports.
//!
//! Two layers, like the rest of the crate:
//!
//! - **Pure, every platform:** [`ScanParams`] (what to program) and the HCI
//!   parameter encoders behind it, plus [`ScanError`] / [`ScanStart`]. Unit-
//!   tested against the Core-spec layouts with no radio. The programming
//!   protocol itself (pre-clear, extended with legacy fallback, disable on stop
//!   and on drop) is a driver over the crate's HCI transport trait, so it is
//!   tested on an in-memory transport as well.
//! - **Linux only:** [`HciScanner`], which owns an `AF_BLUETOOTH` raw HCI socket
//!   bound to one controller. It needs `CAP_NET_RAW` (or root) and a controller
//!   nothing else scans on: [`HciScanner::start`] turns off any scan already
//!   running, including one the kernel runs for `bluetoothd`. An active scan
//!   also needs `CAP_NET_ADMIN`, to end the discovery the kernel believes it
//!   starts (see [`HciScanner::start`]). On other platforms the type exists
//!   but [`HciScanner::open`] returns [`ScanError::Unsupported`].
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
//! The kernel reads an active scan as the start of a device discovery, so an
//! active scan needs `CAP_NET_ADMIN` as well, for [`crate::mgmt`] to end that
//! discovery again. A passive scan needs only `CAP_NET_RAW`.
//!
//! # Extended vs legacy
//!
//! [`HciScanner::start`] prefers the Bluetooth 5 *extended* scan command set
//! (so extended-advertising PDUs are seen as well as the legacy adverts they
//! wrap) and falls back to the legacy commands on a controller that rejects
//! it; the returned [`ScanStart`] says which one took. [`ScanPhys`] selects
//! which PHYs an extended scan listens on: LE 1M (the default), the long
//! range LE Coded PHY, or both. Legacy scanning is LE 1M only, so a
//! Coded-only request does not fall back.

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

/// Which PHYs an extended scan listens on. The legacy command set is LE 1M
/// only; the extended set can also listen on the long range LE Coded PHY.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScanPhys {
    /// LE 1M only, the default.
    M1,
    /// The LE Coded (long range) PHY only. Legacy scanning cannot cover
    /// this, so a controller that rejects the extended commands fails the
    /// scan instead of silently listening on the wrong PHY.
    Coded,
    /// Both LE 1M and LE Coded.
    M1AndCoded,
}

impl ScanPhys {
    /// The HCI `Scanning_PHYs` bitmask: bit 0 is LE 1M, bit 2 is LE Coded.
    pub fn as_mask(self) -> u8 {
        match self {
            ScanPhys::M1 => 0x01,
            ScanPhys::Coded => 0x04,
            ScanPhys::M1AndCoded => 0x05,
        }
    }

    /// Whether a legacy 1M scan still covers part of this request, which is
    /// what makes the legacy fallback meaningful when a controller rejects
    /// the extended commands.
    pub fn legacy_fallback_covers(self) -> bool {
        !matches!(self, ScanPhys::Coded)
    }
}

/// What to program the controller with. `interval` and `window` are in units
/// of 0.625 ms; `window <= interval`, and equal values request a continuous
/// listen. The filter policy is always "accept all" and duplicate filtering is
/// always off, so every advertisement is reported. `phys` applies to the
/// extended command set only; legacy scanning is always LE 1M.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScanParams {
    pub scan_type: ScanType,
    pub own_addr_type: OwnAddrType,
    pub interval: u16,
    pub window: u16,
    pub phys: ScanPhys,
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
    /// window, listening on LE 1M.
    pub fn new(scan_type: ScanType, own_addr_type: OwnAddrType) -> Self {
        ScanParams {
            scan_type,
            own_addr_type,
            interval: DEFAULT_SCAN_INTERVAL,
            window: DEFAULT_SCAN_WINDOW,
            phys: ScanPhys::M1,
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

    /// Parameters for `LE Set Extended Scan Parameters`:
    /// `own_addr_type, filter_policy, scanning_PHYs`, then one
    /// `scan_type, interval(2), window(2)` triple per selected PHY, in
    /// ascending bit order. The same type, interval and window are
    /// programmed on every selected PHY.
    pub fn extended_params(&self) -> Vec<u8> {
        let iv = self.interval.to_le_bytes();
        let win = self.window.to_le_bytes();
        let mask = self.phys.as_mask();
        let mut p = vec![
            self.own_addr_type.as_u8(),
            0x00, // filter_policy = accept all
            mask,
        ];
        for _ in 0..mask.count_ones() {
            p.extend_from_slice(&[self.scan_type.as_u8(), iv[0], iv[1], win[0], win[1]]);
        }
        p
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

/// Why opening the socket or talking to the controller failed. The stages are
/// distinguished so a caller can give a precise hint: a missing adapter fails
/// at [`ScanError::Bind`], while missing permissions and a powered-off adapter
/// only show at the first command, as [`ScanError::Write`].
#[derive(Debug)]
pub enum ScanError {
    /// `socket()` failed, typically because the kernel has no Bluetooth
    /// support. The raw HCI socket opens without `CAP_NET_RAW`.
    Socket(io::Error),
    /// `bind()` to the controller index failed: there is no controller at that
    /// index. Binding succeeds for a controller that is down.
    Bind(io::Error),
    /// Setting the HCI event filter failed; without it no events are delivered.
    Filter(io::Error),
    /// Setting the receive timeout failed.
    RecvTimeout(io::Error),
    /// An HCI command could not be written. The kernel refuses the scan
    /// commands with [`io::ErrorKind::PermissionDenied`] when the process
    /// lacks `CAP_NET_RAW`, and every command with
    /// [`io::ErrorKind::NetworkDown`] when the controller is down. A partial
    /// write is [`io::ErrorKind::WriteZero`].
    Write(io::Error),
    /// The controller answered a command with a non-zero status (`0x01` =
    /// Unknown HCI Command, `0x0C` = Command Disallowed, …).
    Rejected { opcode: u16, status: u8 },
    /// A read error while waiting for a command's completion event.
    Io(io::Error),
    /// Ending the kernel's record of a discovery failed, around an active
    /// scan; see [`HciScanner::start`]. [`crate::mgmt::MgmtError::is_permission_denied`]
    /// means the process lacks `CAP_NET_ADMIN`, which active scans need.
    Discovery(crate::mgmt::MgmtError),
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
            ScanError::Write(e) => write!(f, "cannot write HCI command ({e})"),
            ScanError::Rejected { opcode, status } => write!(
                f,
                "controller rejected command 0x{opcode:04x} (status 0x{status:02x})"
            ),
            ScanError::Io(e) => write!(f, "read error awaiting command response ({e})"),
            ScanError::Discovery(e) => write!(f, "cannot end the kernel's discovery: {e}"),
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
            | ScanError::Write(e)
            | ScanError::Io(e) => Some(e),
            ScanError::Discovery(e) => Some(e),
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
// The scan driver: the programming protocol over any HCI transport
// ===========================================================================

// Off Linux there is no socket to drive this with, but it is still compiled
// and tested there, so the dead code lint is silenced for that build only.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod driver {
    use super::{
        extended_enable_params, legacy_enable_params, ScanError, ScanMode, ScanParams, ScanStart,
        OPCODE_LE_SET_EXT_SCAN_ENABLE, OPCODE_LE_SET_EXT_SCAN_PARAMS, OPCODE_LE_SET_SCAN_ENABLE,
        OPCODE_LE_SET_SCAN_PARAMS,
    };
    use crate::hci_io::{self, CommandError, HciIo};
    use std::io;

    /// One command as the driver sends it: the opcode and its parameters.
    type Command = (u16, Vec<u8>);

    /// The extended command set for `params`, in send order.
    fn extended_commands(params: &ScanParams) -> [Command; 2] {
        [
            (OPCODE_LE_SET_EXT_SCAN_PARAMS, params.extended_params()),
            (
                OPCODE_LE_SET_EXT_SCAN_ENABLE,
                extended_enable_params(true).to_vec(),
            ),
        ]
    }

    /// The legacy command set for `params`, in send order.
    fn legacy_commands(params: &ScanParams) -> [Command; 2] {
        [
            (OPCODE_LE_SET_SCAN_PARAMS, params.legacy_params().to_vec()),
            (
                OPCODE_LE_SET_SCAN_ENABLE,
                legacy_enable_params(true).to_vec(),
            ),
        ]
    }

    /// The disables for both command sets. The set not in use ignores its
    /// disable, so sending both is harmless.
    fn disable_commands() -> [Command; 2] {
        [
            (
                OPCODE_LE_SET_SCAN_ENABLE,
                legacy_enable_params(false).to_vec(),
            ),
            (
                OPCODE_LE_SET_EXT_SCAN_ENABLE,
                extended_enable_params(false).to_vec(),
            ),
        ]
    }

    impl ScanError {
        /// A failed command exchange, with the opcode it was for.
        fn from_command(opcode: u16, err: CommandError) -> Self {
            match err {
                CommandError::Write(e) => ScanError::Write(e),
                CommandError::Rejected(status) => ScanError::Rejected { opcode, status },
                CommandError::Io(e) => ScanError::Io(e),
                CommandError::NoResponse => ScanError::NoResponse,
            }
        }
    }

    /// The scan programming protocol over an [`HciIo`] transport: pre-clear
    /// both command sets, program the extended set with a legacy fallback, and
    /// disable on stop and on drop. The Linux scanner runs it on a raw HCI
    /// socket; the tests run it on an in-memory transport.
    pub(crate) struct ScanDriver<T: HciIo> {
        io: T,
        /// Set once `start` has sent an enable command, whether or not it was
        /// confirmed; cleared by `stop`.
        scanning: bool,
    }

    impl<T: HciIo> ScanDriver<T> {
        pub(crate) fn new(io: T) -> Self {
            ScanDriver {
                io,
                scanning: false,
            }
        }

        /// Program and enable scanning: pre-clear, then the extended set, then
        /// the legacy set if the controller rejected the extended one and a
        /// legacy scan still covers the request.
        pub(crate) fn start(&mut self, params: ScanParams) -> Result<ScanStart, ScanError> {
            // Best-effort pre-clear: the status of a disable is uninteresting.
            self.disable();
            // From here on the controller may be scanning even if this call
            // fails. An enable can be accepted while its completion event is
            // lost under a flood of queued reports, so `stop` and Drop must
            // send the disables regardless of the outcome.
            self.scanning = true;
            match self.program(&extended_commands(&params)) {
                Ok(()) => Ok(ScanStart {
                    mode: ScanMode::Extended,
                    fallback: None,
                }),
                // Only a controller that rejects the extended set gets the
                // legacy one. A write or read failure, or a missing answer,
                // would fail the legacy set the same way, so it is returned
                // as is. A Coded-only request has no legacy equivalent: a 1M
                // legacy scan would listen on the wrong PHY, so its rejection
                // is surfaced instead of narrowing the request.
                Err(ext_err @ ScanError::Rejected { .. })
                    if params.phys.legacy_fallback_covers() =>
                {
                    self.program(&legacy_commands(&params))?;
                    Ok(ScanStart {
                        mode: ScanMode::Legacy,
                        fallback: Some(ext_err),
                    })
                }
                Err(ext_err) => Err(ext_err),
            }
        }

        /// Disable scanning if `start` was attempted, in both command sets,
        /// and wait for the controller to confirm each. The driver's own
        /// transport can hold a backlog of advertising reports ahead of a
        /// completion, long enough to exhaust the bounded wait, so each
        /// disable goes out on a transport `confirm` opens, which should
        /// deliver command completions only. When `confirm` cannot open one,
        /// that disable goes out unconfirmed on the driver's own transport.
        ///
        /// Nothing is reported: a rejection is the command set the scan did
        /// not use, and any other failure means the controller is gone.
        /// Idempotent.
        pub(crate) fn stop<C: HciIo>(&mut self, mut confirm: impl FnMut() -> Option<C>) {
            if !std::mem::take(&mut self.scanning) {
                return;
            }
            for (opcode, params) in disable_commands() {
                match confirm() {
                    Some(mut io) => {
                        let _ = hci_io::command(&mut io, opcode, &params);
                    }
                    None => {
                        let _ = hci_io::send_command(&mut self.io, opcode, &params);
                    }
                }
            }
        }

        /// Read one HCI datagram into `buf`.
        pub(crate) fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.io.read_packet(buf)
        }

        /// Send one command and wait for the controller to accept it.
        pub(crate) fn command(&mut self, opcode: u16, params: &[u8]) -> Result<(), ScanError> {
            hci_io::command(&mut self.io, opcode, params)
                .map_err(|err| ScanError::from_command(opcode, err))
        }

        /// Send each command in turn, stopping at the first the controller does
        /// not accept.
        fn program(&mut self, commands: &[Command]) -> Result<(), ScanError> {
            commands
                .iter()
                .try_for_each(|(opcode, params)| self.command(*opcode, params))
        }

        /// Send both disables without waiting for their completion events.
        fn disable(&mut self) {
            for (opcode, params) in disable_commands() {
                // Best effort: there is nothing to do about a failed disable.
                let _ = hci_io::send_command(&mut self.io, opcode, &params);
            }
        }
    }

    /// The owner normally stops the driver first, confirming the disables.
    /// If it did not, they still go out, unconfirmed, before the transport
    /// closes.
    impl<T: HciIo> Drop for ScanDriver<T> {
        fn drop(&mut self) {
            if std::mem::take(&mut self.scanning) {
                self.disable();
            }
        }
    }
}

// ===========================================================================
// Linux-only raw HCI socket
// ===========================================================================

#[cfg(target_os = "linux")]
pub use linux_impl::HciScanner;

#[cfg(target_os = "linux")]
mod linux_impl {
    use super::driver::ScanDriver;
    use super::*;
    use crate::hci::{HCI_EV_CMD_COMPLETE, HCI_EV_CMD_STATUS};
    use crate::mgmt;
    use crate::sys::{Socket, HCI_CHANNEL_RAW};
    use std::time::Duration;

    /// Bound on each wait for the management interface's answer.
    const MGMT_TIMEOUT: Duration = Duration::from_secs(2);
    /// Receive timeout of the sockets [`HciScanner::stop`] confirms the
    /// disables on.
    const CONFIRM_TIMEOUT: Duration = Duration::from_millis(500);

    /// A raw HCI socket bound to one controller, programmed for LE scanning.
    ///
    /// Dropping the scanner stops any scan it may have started (best-effort,
    /// in both command sets), ends the kernel's discovery after an active
    /// scan, and closes the socket, so a controller is never left scanning
    /// after its handle goes away. A drop cannot report errors; call
    /// [`HciScanner::stop`] first to see them.
    pub struct HciScanner {
        dev: u16,
        /// The scan protocol over the socket. The socket lives inside the
        /// driver, so it is still open while [`HciScanner::stop`] runs on
        /// drop, and closes after.
        driver: ScanDriver<Socket>,
        /// Set when [`HciScanner::start`] programmed an active scan, so
        /// [`HciScanner::stop`] ends the discovery the kernel then believes
        /// is running.
        active: bool,
    }

    impl Drop for HciScanner {
        fn drop(&mut self) {
            let _ = self.stop();
        }
    }

    /// Open a raw HCI socket bound to controller `dev`, delivering the HCI
    /// events `event_mask` selects, with `recv_timeout` as `SO_RCVTIMEO`.
    fn open_raw(
        dev: u16,
        event_mask: [u32; 2],
        recv_timeout: Duration,
    ) -> Result<Socket, ScanError> {
        let sock = Socket::hci().map_err(ScanError::Socket)?;
        sock.bind_hci(dev, HCI_CHANNEL_RAW)
            .map_err(ScanError::Bind)?;
        sock.set_hci_event_filter(event_mask)
            .map_err(ScanError::Filter)?;
        sock.set_recv_timeout(recv_timeout)
            .map_err(ScanError::RecvTimeout)?;
        Ok(sock)
    }

    impl HciScanner {
        /// Open a raw HCI socket bound to controller index `dev` (`hciN` → `N`),
        /// filtered to deliver every HCI event, with `recv_timeout` applied as
        /// `SO_RCVTIMEO` so [`HciScanner::read`] returns
        /// [`io::ErrorKind::WouldBlock`] when nothing arrives in time (and a
        /// read loop can poll a shutdown flag). `Duration::ZERO` disables the
        /// timeout and makes reads block indefinitely.
        pub fn open(dev: u16, recv_timeout: Duration) -> Result<Self, ScanError> {
            let sock = open_raw(dev, [0xffff_ffff, 0xffff_ffff], recv_timeout)?;
            Ok(HciScanner {
                dev,
                driver: ScanDriver::new(sock),
                active: false,
            })
        }

        /// The controller index this scanner is bound to.
        pub fn dev(&self) -> u16 {
            self.dev
        }

        /// Program and enable scanning. Any scan already in progress (in either
        /// command set) is disabled first, which recovers a controller left
        /// scanning by a process that died before its scanner was dropped.
        ///
        /// The kernel takes an active scan for the start of a device
        /// discovery, and once the scan is disabled that discovery never ends:
        /// it blocks new discoveries and the kernel's own LE connections on
        /// the adapter (see [`crate::mgmt`]). So for an active scan, `start`
        /// first ends any discovery in progress, and [`HciScanner::stop`] ends
        /// the one the scan starts. Both need `CAP_NET_ADMIN`; without it
        /// `start` fails with [`ScanError::Discovery`] before touching the
        /// controller. A passive scan needs neither, but it still stops a scan
        /// the kernel runs for `bluetoothd`, and a discovery in progress then
        /// never finishes: stop `bluetoothd` first.
        ///
        /// The extended command set is tried first; if the controller rejects
        /// it the legacy set is programmed instead and the rejection is
        /// reported as [`ScanStart::fallback`]. An error means neither set
        /// could be *confirmed* enabled: a command could not be written
        /// ([`ScanError::Write`]) or the controller refused it. The scanner
        /// still sends the disables on [`HciScanner::stop`] / drop, in case an
        /// enable was accepted but its completion event lost.
        pub fn start(&mut self, params: ScanParams) -> Result<ScanStart, ScanError> {
            let active = params.scan_type == ScanType::Active;
            if active {
                // Fails fast when CAP_NET_ADMIN is missing, before the scan
                // could leave the kernel's discovery stuck, and ends a real
                // discovery cleanly instead of cutting its scan off.
                mgmt::end_discovery(self.dev, MGMT_TIMEOUT).map_err(ScanError::Discovery)?;
            }
            // A passive restart must not forget an earlier active scan whose
            // discovery stop() still has to end.
            self.active |= active;
            self.driver.start(params)
        }

        /// Disable scanning if [`HciScanner::start`] was attempted, in both
        /// command sets (the unused one is a harmless no-op), and wait for the
        /// controller to confirm each. After an active scan, then end the
        /// discovery the kernel believes the scan started. The order matters:
        /// a Stop Discovery that arrives while the kernel still thinks the
        /// scan is on makes the kernel disable it too, and if that fails the
        /// discovery stays stuck.
        ///
        /// An error is a [`ScanError::Discovery`]: the scan is off, but new
        /// discoveries and LE connections on the adapter stay blocked until
        /// `btmgmt stop-find` or a power cycle. Drop calls this too but
        /// cannot report errors.
        pub fn stop(&mut self) -> Result<(), ScanError> {
            // Each disable is confirmed on a socket that receives only
            // command completions.
            let dev = self.dev;
            let completions = (1u32 << HCI_EV_CMD_COMPLETE) | (1u32 << HCI_EV_CMD_STATUS);
            self.driver
                .stop(|| open_raw(dev, [completions, 0], CONFIRM_TIMEOUT).ok());

            if std::mem::take(&mut self.active) {
                mgmt::end_discovery(self.dev, MGMT_TIMEOUT).map_err(ScanError::Discovery)?;
            }
            Ok(())
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
            self.driver.read(buf)
        }

        /// Send one HCI command and wait for its Command Complete / Command
        /// Status event, returning `Ok(())` only if the controller accepted it
        /// (status `0x00`). Events for other opcodes (advertising reports
        /// included) are skipped. Bounded to a handful of reads, each limited
        /// by the receive timeout, so a controller that never answers can't
        /// hang the caller.
        pub fn command(&mut self, opcode: u16, params: &[u8]) -> Result<(), ScanError> {
            self.driver.command(opcode, params)
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

        pub fn stop(&mut self) -> Result<(), ScanError> {
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
    use super::driver::ScanDriver;
    use super::*;
    use crate::hci::build_command;
    use crate::hci_io::mock::MockHci;
    use crate::hci_io::MAX_WAIT;

    #[test]
    fn default_is_a_passive_scan_from_the_public_address() {
        let p = ScanParams::default();
        assert_eq!(p.scan_type, ScanType::Passive);
        assert_eq!(p.own_addr_type, OwnAddrType::Public);
        assert_eq!(p.interval, DEFAULT_SCAN_INTERVAL);
        assert_eq!(p.window, DEFAULT_SCAN_WINDOW);
        assert_eq!(p.phys, ScanPhys::M1);
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
            phys: ScanPhys::M1,
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
            phys: ScanPhys::M1,
        };
        assert_eq!(
            p.extended_params(),
            vec![0x01, 0x00, 0x01, 0x01, 0x34, 0x12, 0x10, 0x00]
        );
        let p = ScanParams::default();
        assert_eq!(p.extended_params()[0], 0x00); // public
        assert_eq!(p.extended_params()[3], 0x00); // passive
    }

    #[test]
    fn extended_params_emit_one_triple_per_phy() {
        // Coded only: mask 0x04, a single triple.
        let mut p = ScanParams {
            phys: ScanPhys::Coded,
            ..ScanParams::default()
        };
        assert_eq!(
            p.extended_params(),
            vec![0x00, 0x00, 0x04, 0x00, 0x10, 0x00, 0x10, 0x00]
        );
        // Both PHYs: mask 0x05, the same triple twice (1M first, Coded
        // second, in ascending bit order).
        p.phys = ScanPhys::M1AndCoded;
        assert_eq!(
            p.extended_params(),
            vec![
                0x00, 0x00, 0x05, // header
                0x00, 0x10, 0x00, 0x10, 0x00, // LE 1M triple
                0x00, 0x10, 0x00, 0x10, 0x00, // LE Coded triple
            ]
        );
    }

    #[test]
    fn scan_phys_masks_follow_the_spec() {
        // Bit 0 is LE 1M and bit 2 is LE Coded; bit 1 (LE 2M) is not valid
        // for scanning, so no variant may ever set it.
        assert_eq!(ScanPhys::M1.as_mask(), 0x01);
        assert_eq!(ScanPhys::Coded.as_mask(), 0x04);
        assert_eq!(ScanPhys::M1AndCoded.as_mask(), 0x05);
        for phys in [ScanPhys::M1, ScanPhys::Coded, ScanPhys::M1AndCoded] {
            assert_eq!(phys.as_mask() & 0x02, 0);
        }
    }

    #[test]
    fn only_requests_covering_1m_allow_the_legacy_fallback() {
        assert!(ScanPhys::M1.legacy_fallback_covers());
        assert!(ScanPhys::M1AndCoded.legacy_fallback_covers());
        assert!(!ScanPhys::Coded.legacy_fallback_covers());
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

    // The driver over an in-memory transport. The transport is lent to the
    // driver so it can be inspected after the driver is dropped.

    fn accepted(opcode: u16) -> Vec<u8> {
        MockHci::command_complete(opcode, 0x00)
    }

    /// The two disables sent before a start and again on stop.
    const DISABLES: [u16; 2] = [OPCODE_LE_SET_SCAN_ENABLE, OPCODE_LE_SET_EXT_SCAN_ENABLE];

    #[test]
    fn driver_pre_clears_both_sets_then_programs_the_extended_set() {
        let mut io = MockHci::replaying(vec![
            accepted(OPCODE_LE_SET_EXT_SCAN_PARAMS),
            accepted(OPCODE_LE_SET_EXT_SCAN_ENABLE),
        ]);
        let mut driver = ScanDriver::new(&mut io);
        let start = driver.start(ScanParams::default()).unwrap();
        assert_eq!(start.mode, ScanMode::Extended);
        assert!(start.fallback.is_none());
        drop(driver);
        assert_eq!(
            io.written_opcodes(),
            vec![
                OPCODE_LE_SET_SCAN_ENABLE,     // pre-clear, legacy
                OPCODE_LE_SET_EXT_SCAN_ENABLE, // pre-clear, extended
                OPCODE_LE_SET_EXT_SCAN_PARAMS,
                OPCODE_LE_SET_EXT_SCAN_ENABLE,
                OPCODE_LE_SET_SCAN_ENABLE,     // stop on drop, legacy
                OPCODE_LE_SET_EXT_SCAN_ENABLE, // stop on drop, extended
            ]
        );
        // The bytes are the pure encoders' output, framed by `build_command`.
        assert_eq!(
            io.written[0],
            build_command(OPCODE_LE_SET_SCAN_ENABLE, &legacy_enable_params(false))
        );
        assert_eq!(
            io.written[2],
            build_command(
                OPCODE_LE_SET_EXT_SCAN_PARAMS,
                &ScanParams::default().extended_params()
            )
        );
        assert_eq!(
            io.written[3],
            build_command(OPCODE_LE_SET_EXT_SCAN_ENABLE, &extended_enable_params(true))
        );
    }

    #[test]
    fn driver_falls_back_to_the_legacy_set_when_extended_is_rejected() {
        let mut io = MockHci::replaying(vec![
            MockHci::command_status(OPCODE_LE_SET_EXT_SCAN_PARAMS, 0x01),
            accepted(OPCODE_LE_SET_SCAN_PARAMS),
            accepted(OPCODE_LE_SET_SCAN_ENABLE),
        ]);
        let mut driver = ScanDriver::new(&mut io);
        let start = driver.start(ScanParams::default()).unwrap();
        assert_eq!(start.mode, ScanMode::Legacy);
        assert!(matches!(
            start.fallback,
            Some(ScanError::Rejected {
                opcode: OPCODE_LE_SET_EXT_SCAN_PARAMS,
                status: 0x01
            })
        ));
        drop(driver);
        assert_eq!(
            io.written_opcodes()[2..5],
            [
                OPCODE_LE_SET_EXT_SCAN_PARAMS,
                OPCODE_LE_SET_SCAN_PARAMS,
                OPCODE_LE_SET_SCAN_ENABLE
            ]
        );
        assert_eq!(
            io.written[3],
            build_command(
                OPCODE_LE_SET_SCAN_PARAMS,
                &ScanParams::default().legacy_params()
            )
        );
    }

    #[test]
    fn driver_does_not_fall_back_for_a_coded_only_request() {
        let mut io = MockHci::replaying(vec![MockHci::command_status(
            OPCODE_LE_SET_EXT_SCAN_PARAMS,
            0x01,
        )]);
        let params = ScanParams {
            phys: ScanPhys::Coded,
            ..ScanParams::default()
        };
        let mut driver = ScanDriver::new(&mut io);
        assert!(matches!(
            driver.start(params),
            Err(ScanError::Rejected {
                opcode: OPCODE_LE_SET_EXT_SCAN_PARAMS,
                status: 0x01
            })
        ));
        drop(driver);
        let opcodes = io.written_opcodes();
        assert!(!opcodes.contains(&OPCODE_LE_SET_SCAN_PARAMS));
        // The attempt may have left the controller scanning, so the drop still
        // sends the disables.
        assert_eq!(opcodes[opcodes.len() - 2..], DISABLES);
    }

    #[test]
    fn driver_disables_on_drop_after_a_start_that_got_no_answer() {
        let mut io = MockHci::replaying(Vec::new());
        let mut driver = ScanDriver::new(&mut io);
        assert!(matches!(
            driver.start(ScanParams::default()),
            Err(ScanError::NoResponse)
        ));
        drop(driver);
        // The pre-clear, the extended parameters that got no answer, then the
        // disables on drop. A missing answer is not a rejection, so the legacy
        // set is not tried.
        assert_eq!(
            io.written_opcodes(),
            vec![
                OPCODE_LE_SET_SCAN_ENABLE,
                OPCODE_LE_SET_EXT_SCAN_ENABLE,
                OPCODE_LE_SET_EXT_SCAN_PARAMS,
                OPCODE_LE_SET_SCAN_ENABLE,
                OPCODE_LE_SET_EXT_SCAN_ENABLE,
            ]
        );
    }

    /// A `confirm` for [`ScanDriver::stop`] that can never open a transport.
    fn unconfirmed() -> Option<MockHci> {
        None
    }

    #[test]
    fn driver_stop_confirms_each_disable_on_a_transport_of_its_own() {
        let mut io = MockHci::replaying(vec![
            accepted(OPCODE_LE_SET_EXT_SCAN_PARAMS),
            accepted(OPCODE_LE_SET_EXT_SCAN_ENABLE),
        ]);
        // The legacy disable is accepted. The extended one is rejected, as a
        // controller without the extended set does, which is not an error.
        let mut confirms = [
            MockHci::replaying(vec![accepted(OPCODE_LE_SET_SCAN_ENABLE)]),
            MockHci::replaying(vec![MockHci::command_status(
                OPCODE_LE_SET_EXT_SCAN_ENABLE,
                0x01,
            )]),
        ];
        let mut driver = ScanDriver::new(&mut io);
        driver.start(ScanParams::default()).unwrap();
        let mut lent = confirms.iter_mut();
        driver.stop(|| lent.next());
        driver.stop(unconfirmed);
        drop(driver);
        // The driver's own transport carried only the pre-clear and the
        // programming; the second stop and the drop add nothing.
        assert_eq!(io.written.len(), 4);
        for (confirm, opcode) in confirms.iter().zip(DISABLES) {
            assert_eq!(confirm.written_opcodes(), [opcode]);
            assert_eq!(confirm.reads, 1);
        }
        assert_eq!(
            confirms[0].written[0],
            build_command(OPCODE_LE_SET_SCAN_ENABLE, &legacy_enable_params(false))
        );
    }

    #[test]
    fn driver_stop_sends_the_disables_itself_when_it_cannot_confirm() {
        let mut io = MockHci::replaying(vec![
            accepted(OPCODE_LE_SET_EXT_SCAN_PARAMS),
            accepted(OPCODE_LE_SET_EXT_SCAN_ENABLE),
        ]);
        let mut driver = ScanDriver::new(&mut io);
        driver.start(ScanParams::default()).unwrap();
        driver.stop(unconfirmed);
        driver.stop(unconfirmed);
        drop(driver);
        // Two for the pre-clear, two to program, two for the first stop. The
        // second stop and the drop add nothing.
        assert_eq!(io.written.len(), 6);
        assert_eq!(io.written_opcodes()[4..], DISABLES);
    }

    #[test]
    fn driver_sends_nothing_on_drop_without_a_start() {
        let mut io = MockHci::replaying(Vec::new());
        drop(ScanDriver::new(&mut io));
        assert!(io.written.is_empty());
    }

    #[test]
    fn driver_command_maps_exchange_failures_with_the_opcode() {
        let opcode = OPCODE_LE_SET_SCAN_PARAMS;
        let mut io = MockHci::replaying(vec![MockHci::command_complete(opcode, 0x0C)]);
        assert!(matches!(
            ScanDriver::new(&mut io).command(opcode, &[]),
            Err(ScanError::Rejected {
                opcode: OPCODE_LE_SET_SCAN_PARAMS,
                status: 0x0C
            })
        ));
        let mut io = MockHci::replaying(Vec::new());
        assert!(matches!(
            ScanDriver::new(&mut io).command(opcode, &[]),
            Err(ScanError::NoResponse)
        ));
        assert_eq!(io.reads, MAX_WAIT as usize);
        let mut io = MockHci::replaying(Vec::new());
        io.fail_writes = true;
        assert!(matches!(
            ScanDriver::new(&mut io).command(opcode, &[]),
            Err(ScanError::Write(e)) if e.kind() == io::ErrorKind::PermissionDenied
        ));
        let mut io = MockHci::new(vec![Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "closed",
        ))]);
        assert!(matches!(
            ScanDriver::new(&mut io).command(opcode, &[]),
            Err(ScanError::Io(_))
        ));
    }

    #[test]
    fn discovery_error_says_which_capability_is_missing() {
        use std::error::Error as _;
        let e = ScanError::Discovery(crate::mgmt::MgmtError::Refused {
            opcode: crate::mgmt::OP_STOP_DISCOVERY,
            status: crate::mgmt::STATUS_PERMISSION_DENIED,
        });
        assert!(e.to_string().ends_with("it needs CAP_NET_ADMIN"));
        assert!(e.source().is_some());
    }

    #[test]
    fn write_error_keeps_the_kernel_error() {
        use std::error::Error as _;
        let e = ScanError::Write(io::Error::from(io::ErrorKind::PermissionDenied));
        assert!(e.to_string().starts_with("cannot write HCI command"));
        let source = e.source().and_then(|s| s.downcast_ref::<io::Error>());
        assert_eq!(
            source.map(io::Error::kind),
            Some(io::ErrorKind::PermissionDenied)
        );
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
