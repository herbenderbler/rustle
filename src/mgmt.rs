//! The kernel's Bluetooth management interface, for the one job rustle needs
//! from it: ending a device discovery the kernel believes is running.
//!
//! # Why a raw-HCI library needs this
//!
//! The kernel watches every command completion on an adapter, including the
//! ones for commands rustle writes to a raw HCI socket. When an active scan is
//! enabled, it concludes that a device discovery has started. When the scan is
//! disabled, it cancels the timer that would have ended that discovery but
//! leaves it marked as running. While a discovery is marked as running, the
//! kernel refuses new ones with `Busy` and does not start the background scan
//! its own LE connections wait for, so [`crate::l2cap::L2capAtt::connect`]
//! times out on that adapter.
//!
//! [`end_discovery`] sends Stop Discovery, the command `btmgmt stop-find` and
//! `bluetoothd` use, which marks the discovery stopped.
//! [`crate::scan::HciScanner`] calls it around every active scan; nothing else
//! in the crate needs it.
//!
//! # Layers
//!
//! Like the rest of the crate, the command encoder and the event decoder are
//! pure and unit-tested on every OS. The socket layer is Linux-only and needs
//! `CAP_NET_ADMIN`: the kernel answers an unprivileged Stop Discovery with
//! [`STATUS_PERMISSION_DENIED`]. On other platforms [`end_discovery`] fails
//! with [`MgmtError::Unsupported`].

use std::fmt;
use std::io;
use std::time::Duration;

/// Stop Discovery command code.
pub const OP_STOP_DISCOVERY: u16 = 0x0024;
/// Command Complete event code.
pub const EV_COMMAND_COMPLETE: u16 = 0x0001;
/// Command Status event code.
pub const EV_COMMAND_STATUS: u16 = 0x0002;

/// Discovery address type for Low Energy only (LE public and LE random).
pub const DISCOVERY_LE: u8 = 0x06;
/// Discovery address type for Low Energy and BR/EDR.
pub const DISCOVERY_DUAL: u8 = 0x07;
/// Discovery address type for BR/EDR only.
pub const DISCOVERY_BREDR: u8 = 0x01;
/// The type the kernel holds for an adapter that has never run a discovery.
pub const DISCOVERY_NONE: u8 = 0x00;

/// The types [`end_discovery`] tries, in order. Stop Discovery must name the
/// type of the discovery it stops, and the kernel does not report it. A
/// discovery that an active scan started inherits the type of the last real
/// discovery on that adapter, or [`DISCOVERY_NONE`] if there was none.
pub const DISCOVERY_TYPES: [u8; 4] = [
    DISCOVERY_LE,
    DISCOVERY_DUAL,
    DISCOVERY_BREDR,
    DISCOVERY_NONE,
];

/// Success.
pub const STATUS_SUCCESS: u8 = 0x00;
/// Rejected. Stop Discovery answers this when no discovery is running.
pub const STATUS_REJECTED: u8 = 0x0B;
/// Invalid Parameters. Stop Discovery answers this when the type does not
/// match the running discovery.
pub const STATUS_INVALID_PARAMS: u8 = 0x0D;
/// Invalid Index: there is no controller at that index.
pub const STATUS_INVALID_INDEX: u8 = 0x11;
/// Permission Denied: the process lacks `CAP_NET_ADMIN`.
pub const STATUS_PERMISSION_DENIED: u8 = 0x14;

/// The name the management interface gives a status code.
pub fn status_name(status: u8) -> &'static str {
    match status {
        0x00 => "Success",
        0x01 => "Unknown Command",
        0x02 => "Not Connected",
        0x03 => "Failed",
        0x04 => "Connect Failed",
        0x05 => "Authentication Failed",
        0x06 => "Not Paired",
        0x07 => "No Resources",
        0x08 => "Timeout",
        0x09 => "Already Connected",
        0x0A => "Busy",
        0x0B => "Rejected",
        0x0C => "Not Supported",
        0x0D => "Invalid Parameters",
        0x0E => "Disconnected",
        0x0F => "Not Powered",
        0x10 => "Cancelled",
        0x11 => "Invalid Index",
        0x12 => "RFKilled",
        0x13 => "Already Paired",
        0x14 => "Permission Denied",
        _ => "Unknown Status",
    }
}

/// Encode a management command: command code, controller index and
/// parameter length (each a little-endian `u16`), then the parameters.
/// `params` must be shorter than 64 KiB; every command rustle sends is a few
/// bytes long.
pub fn encode_command(opcode: u16, index: u16, params: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(6 + params.len());
    out.extend_from_slice(&opcode.to_le_bytes());
    out.extend_from_slice(&index.to_le_bytes());
    out.extend_from_slice(&(params.len() as u16).to_le_bytes());
    out.extend_from_slice(params);
    out
}

/// Stop Discovery for controller `index`, naming the discovery's address
/// type (one of [`DISCOVERY_TYPES`]).
pub fn stop_discovery_command(index: u16, address_type: u8) -> Vec<u8> {
    encode_command(OP_STOP_DISCOVERY, index, &[address_type])
}

/// The kernel's answer to a command: a Command Complete or Command Status
/// event, reduced to what identifies it and its outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommandReply {
    /// The controller index the event names.
    pub index: u16,
    /// The command the event answers.
    pub opcode: u16,
    /// The management status; see [`status_name`].
    pub status: u8,
}

/// Decode a management event as the answer to a command. Returns `None` for
/// every other event, and for a buffer too short for its own header or for
/// the length that header declares.
pub fn parse_command_reply(buf: &[u8]) -> Option<CommandReply> {
    // event(2) index(2) param_len(2), then the parameters.
    let (&[e0, e1, i0, i1, l0, l1], rest) = buf.split_first_chunk::<6>()?;
    let params = rest.get(..u16::from_le_bytes([l0, l1]).into())?;
    if !matches!(
        u16::from_le_bytes([e0, e1]),
        EV_COMMAND_COMPLETE | EV_COMMAND_STATUS
    ) {
        return None;
    }
    // opcode(2) status(1), then any return parameters.
    let &[lo, hi, status, ..] = params else {
        return None;
    };
    Some(CommandReply {
        index: u16::from_le_bytes([i0, i1]),
        opcode: u16::from_le_bytes([lo, hi]),
        status,
    })
}

/// What a Stop Discovery status means for the search over
/// [`DISCOVERY_TYPES`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StopOutcome {
    /// The discovery was running and is now stopped.
    Stopped,
    /// No discovery was running.
    NotRunning,
    /// A discovery is running, but of another type: try the next one.
    WrongType,
    /// The kernel refused the command for another reason.
    Refused,
}

/// Classify a Stop Discovery status.
pub fn classify_stop(status: u8) -> StopOutcome {
    match status {
        STATUS_SUCCESS => StopOutcome::Stopped,
        STATUS_REJECTED => StopOutcome::NotRunning,
        STATUS_INVALID_PARAMS => StopOutcome::WrongType,
        _ => StopOutcome::Refused,
    }
}

/// What [`end_discovery`] found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiscoveryEnd {
    /// No discovery was running.
    NotRunning,
    /// A discovery of this address type was running and is now stopped.
    Stopped(u8),
}

/// Why [`end_discovery`] failed.
#[derive(Debug)]
pub enum MgmtError {
    /// `socket()` failed, typically because the kernel has no Bluetooth
    /// support.
    Socket(io::Error),
    /// `bind()` to the management channel failed.
    Bind(io::Error),
    /// Setting the receive timeout failed.
    RecvTimeout(io::Error),
    /// The command could not be written.
    Write(io::Error),
    /// A read error while waiting for the kernel's answer.
    Io(io::Error),
    /// The kernel answered with a status that ends the attempt.
    /// [`STATUS_PERMISSION_DENIED`] means the process lacks `CAP_NET_ADMIN`,
    /// and [`STATUS_INVALID_INDEX`] that there is no controller at that index.
    Refused { opcode: u16, status: u8 },
    /// No answer arrived within the timeout.
    NoResponse,
    /// A discovery is running, but none of [`DISCOVERY_TYPES`] matched it.
    UnknownDiscoveryType,
    /// This platform has no Bluetooth management socket.
    Unsupported,
}

impl MgmtError {
    /// Whether the kernel refused the command because the process lacks
    /// `CAP_NET_ADMIN`.
    pub fn is_permission_denied(&self) -> bool {
        matches!(
            self,
            MgmtError::Refused {
                status: STATUS_PERMISSION_DENIED,
                ..
            }
        )
    }
}

impl fmt::Display for MgmtError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MgmtError::Socket(e) => write!(f, "cannot open management socket ({e})"),
            MgmtError::Bind(e) => write!(f, "cannot bind management channel ({e})"),
            MgmtError::RecvTimeout(e) => write!(f, "cannot set receive timeout ({e})"),
            MgmtError::Write(e) => write!(f, "cannot write management command ({e})"),
            MgmtError::Io(e) => write!(f, "read error awaiting management reply ({e})"),
            MgmtError::Refused { opcode, status } => {
                write!(
                    f,
                    "management command 0x{opcode:04x} refused: {} (0x{status:02x})",
                    status_name(*status)
                )?;
                if *status == STATUS_PERMISSION_DENIED {
                    write!(f, "; it needs CAP_NET_ADMIN")?;
                }
                Ok(())
            }
            MgmtError::NoResponse => write!(f, "no reply from the management interface"),
            MgmtError::UnknownDiscoveryType => {
                write!(
                    f,
                    "a discovery is running, but its type is not one rustle knows"
                )
            }
            MgmtError::Unsupported => {
                write!(f, "the management interface is only supported on Linux")
            }
        }
    }
}

impl std::error::Error for MgmtError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            MgmtError::Socket(e)
            | MgmtError::Bind(e)
            | MgmtError::RecvTimeout(e)
            | MgmtError::Write(e)
            | MgmtError::Io(e) => Some(e),
            _ => None,
        }
    }
}

// ===========================================================================
// Linux-only management socket
// ===========================================================================

#[cfg(target_os = "linux")]
pub use linux_impl::end_discovery;

/// End any device discovery the kernel believes is running on controller
/// `dev`. This platform has no management socket, so this always fails with
/// [`MgmtError::Unsupported`].
#[cfg(not(target_os = "linux"))]
pub fn end_discovery(_dev: u16, _timeout: Duration) -> Result<DiscoveryEnd, MgmtError> {
    Err(MgmtError::Unsupported)
}

#[cfg(target_os = "linux")]
mod linux_impl {
    use super::*;
    use crate::sys::{
        bind, read, set_recv_timeout, socket, write, FdGuard, Timeval, AF_BLUETOOTH, BTPROTO_HCI,
        SOCK_RAW,
    };
    use std::os::raw::{c_int, c_void};
    use std::time::Instant;

    const HCI_DEV_NONE: u16 = 0xFFFF;
    const HCI_CHANNEL_CONTROL: u16 = 3;

    /// How long each read waits, so the deadline is checked often.
    const READ_TICK: Duration = Duration::from_millis(200);

    #[repr(C)]
    struct SockaddrHci {
        hci_family: u16,
        hci_dev: u16,
        hci_channel: u16,
    }

    /// End any device discovery the kernel believes is running on
    /// controller `dev` (`hciN` → `N`), trying each of [`DISCOVERY_TYPES`]
    /// until one matches. `timeout` bounds the wait for each answer.
    ///
    /// Returns [`DiscoveryEnd::NotRunning`] when there was nothing to stop.
    /// Needs `CAP_NET_ADMIN`: without it the kernel answers
    /// [`STATUS_PERMISSION_DENIED`], reported as [`MgmtError::Refused`].
    pub fn end_discovery(dev: u16, timeout: Duration) -> Result<DiscoveryEnd, MgmtError> {
        let fd = unsafe { socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI) };
        if fd < 0 {
            return Err(MgmtError::Socket(io::Error::last_os_error()));
        }
        let guard = FdGuard(fd);

        let addr = SockaddrHci {
            hci_family: AF_BLUETOOTH as u16,
            hci_dev: HCI_DEV_NONE,
            hci_channel: HCI_CHANNEL_CONTROL,
        };
        let rc = unsafe {
            bind(
                fd,
                &addr as *const SockaddrHci as *const c_void,
                std::mem::size_of::<SockaddrHci>() as u32,
            )
        };
        if rc < 0 {
            return Err(MgmtError::Bind(io::Error::last_os_error()));
        }
        if set_recv_timeout(fd, &Timeval::from_duration(READ_TICK)) < 0 {
            return Err(MgmtError::RecvTimeout(io::Error::last_os_error()));
        }

        for address_type in DISCOVERY_TYPES {
            let cmd = stop_discovery_command(dev, address_type);
            let status = request(guard.0, dev, OP_STOP_DISCOVERY, &cmd, timeout)?;
            match classify_stop(status) {
                StopOutcome::Stopped => return Ok(DiscoveryEnd::Stopped(address_type)),
                StopOutcome::NotRunning => return Ok(DiscoveryEnd::NotRunning),
                StopOutcome::WrongType => continue,
                StopOutcome::Refused => {
                    return Err(MgmtError::Refused {
                        opcode: OP_STOP_DISCOVERY,
                        status,
                    })
                }
            }
        }
        Err(MgmtError::UnknownDiscoveryType)
    }

    /// Write one encoded command and wait for the kernel's answer to it,
    /// returning its status. Other events on the channel (a trusted socket
    /// also receives Device Found and the like) are skipped until
    /// `timeout` passes.
    fn request(
        fd: c_int,
        dev: u16,
        opcode: u16,
        cmd: &[u8],
        timeout: Duration,
    ) -> Result<u8, MgmtError> {
        // Only a negative return is a failed write. When the kernel answers
        // the command itself, without running it (Permission Denied, Invalid
        // Index, Invalid Parameters), it queues that status as the reply and
        // write() returns 0; a command that runs returns its full length.
        // Either way the reply is read below.
        let n = unsafe { write(fd, cmd.as_ptr() as *const c_void, cmd.len()) };
        if n < 0 {
            return Err(MgmtError::Write(io::Error::last_os_error()));
        }

        let deadline = Instant::now() + timeout;
        let mut buf = [0u8; 1024];
        while Instant::now() < deadline {
            let n = unsafe { read(fd, buf.as_mut_ptr() as *mut c_void, buf.len()) };
            if n == 0 {
                return Err(MgmtError::Io(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "management socket closed",
                )));
            }
            if n < 0 {
                let e = io::Error::last_os_error();
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) {
                    continue;
                }
                return Err(MgmtError::Io(e));
            }
            if let Some(reply) = parse_command_reply(&buf[..n as usize]) {
                if reply.index == dev && reply.opcode == opcode {
                    return Ok(reply.status);
                }
            }
        }
        Err(MgmtError::NoResponse)
    }
}

// ===========================================================================
// Tests for the pure layer (run on every platform)
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stop_discovery_encodes_opcode_index_length_and_type() {
        assert_eq!(
            stop_discovery_command(2, DISCOVERY_LE),
            vec![0x24, 0x00, 0x02, 0x00, 0x01, 0x00, 0x06]
        );
    }

    #[test]
    fn parses_command_complete_and_command_status() {
        // Command Complete for Stop Discovery on hci1: Rejected, with the
        // one-byte return parameter (the address type).
        let complete = [0x01, 0x00, 0x01, 0x00, 0x04, 0x00, 0x24, 0x00, 0x0B, 0x06];
        assert_eq!(
            parse_command_reply(&complete),
            Some(CommandReply {
                index: 1,
                opcode: OP_STOP_DISCOVERY,
                status: STATUS_REJECTED,
            })
        );
        // Command Status on hci0: Permission Denied, no return parameters.
        let status = [0x02, 0x00, 0x00, 0x00, 0x03, 0x00, 0x24, 0x00, 0x14];
        assert_eq!(
            parse_command_reply(&status).map(|r| r.status),
            Some(STATUS_PERMISSION_DENIED)
        );
    }

    #[test]
    fn ignores_other_events_and_truncated_buffers() {
        // Discovering (0x0013) is an event, but not a reply.
        let discovering = [0x13, 0x00, 0x01, 0x00, 0x02, 0x00, 0x06, 0x00];
        assert_eq!(parse_command_reply(&discovering), None);
        // Header declares more parameters than the buffer holds.
        let truncated = [0x01, 0x00, 0x01, 0x00, 0x04, 0x00, 0x24, 0x00];
        assert_eq!(parse_command_reply(&truncated), None);
        // Parameters too short for an opcode and a status.
        let short = [0x01, 0x00, 0x01, 0x00, 0x02, 0x00, 0x24, 0x00];
        assert_eq!(parse_command_reply(&short), None);
        assert_eq!(parse_command_reply(&[]), None);
    }

    #[test]
    fn classifies_stop_statuses() {
        assert_eq!(classify_stop(STATUS_SUCCESS), StopOutcome::Stopped);
        assert_eq!(classify_stop(STATUS_REJECTED), StopOutcome::NotRunning);
        assert_eq!(classify_stop(STATUS_INVALID_PARAMS), StopOutcome::WrongType);
        assert_eq!(
            classify_stop(STATUS_PERMISSION_DENIED),
            StopOutcome::Refused
        );
        assert_eq!(classify_stop(STATUS_INVALID_INDEX), StopOutcome::Refused);
    }

    #[test]
    fn permission_denied_names_the_capability() {
        let e = MgmtError::Refused {
            opcode: OP_STOP_DISCOVERY,
            status: STATUS_PERMISSION_DENIED,
        };
        assert!(e.is_permission_denied());
        assert_eq!(
            e.to_string(),
            "management command 0x0024 refused: Permission Denied (0x14); it needs CAP_NET_ADMIN"
        );
        assert!(!MgmtError::NoResponse.is_permission_denied());
    }

    #[test]
    fn tries_low_energy_first_and_none_last() {
        assert_eq!(DISCOVERY_TYPES.first(), Some(&DISCOVERY_LE));
        assert_eq!(DISCOVERY_TYPES.last(), Some(&DISCOVERY_NONE));
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn end_discovery_is_unsupported_off_linux() {
        assert!(matches!(
            end_discovery(0, Duration::from_secs(1)),
            Err(MgmtError::Unsupported)
        ));
    }
}
