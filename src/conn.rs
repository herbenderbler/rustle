//! Connection-level HCI queries for LE links the kernel is carrying.
//!
//! [`read_rssi`] reports the current RSSI of an established LE connection,
//! such as one opened by [`crate::l2cap::L2capAtt`]. The kernel owns the
//! connection; this module only looks up its handle (`HCIGETCONNINFO`) and
//! asks the controller (HCI Read RSSI) over a raw HCI socket of its own.
//! [`connections`] lists the links an adapter currently carries
//! (`HCIGETCONNLIST`), answered from kernel state without touching them.
//!
//! Split like the rest of the crate: the request and response codecs are pure
//! and unit-tested on every OS, while the socket layer is Linux-only and needs
//! `CAP_NET_RAW` (or root). On other platforms [`read_rssi`] returns
//! [`RssiError::Unsupported`] and [`connections`] fails with an error string.

use crate::hci::format_addr_le;
use std::fmt;
use std::io;
use std::time::Duration;

/// HCI Read RSSI (OGF 0x05 Status Parameters, OCF 0x0005).
pub const OPCODE_READ_RSSI: u16 = 0x1405;

// HCI event framing bytes, as in [`crate::hci`].
const HCI_EVENT_PKT: u8 = 0x04;
const HCI_EV_CMD_COMPLETE: u8 = 0x0E;
#[cfg(target_os = "linux")]
const HCI_EV_CMD_STATUS: u8 = 0x0F;

// ---------------------------------------------------------------------------
// `HCIGETCONNINFO` buffer codec (BlueZ ABI). The ioctl takes one buffer that
// is `struct hci_conn_info_req` (bdaddr(6) + type(1), padded to 8) going in,
// with `struct hci_conn_info` (handle(2), bdaddr(6), type(1), out(1),
// state(2), link_mode(4) = 16 bytes) written back after it.
// ---------------------------------------------------------------------------

/// `hci_conn_info_req.type` for an LE link.
const LE_LINK: u8 = 0x80;
/// Size of the padded request header; the kernel writes the info after it.
const CONN_INFO_REQ_LEN: usize = 8;
/// Offset of `hci_conn_info.handle`, the info's first field.
const CONN_INFO_HANDLE: usize = CONN_INFO_REQ_LEN;
/// The whole in/out buffer: padded request header + 16-byte info.
const CONN_INFO_BUF_LEN: usize = CONN_INFO_REQ_LEN + 16;

/// Build the `HCIGETCONNINFO` buffer asking for the LE connection to
/// `peer_le` (a wire-order address, least-significant byte first).
pub fn conn_info_request(peer_le: [u8; 6]) -> Vec<u8> {
    let mut buf = vec![0u8; CONN_INFO_BUF_LEN];
    buf[..6].copy_from_slice(&peer_le);
    buf[6] = LE_LINK;
    buf
}

/// Read the connection handle out of a filled `HCIGETCONNINFO` buffer.
/// `None` if the buffer is too short to hold it.
pub fn parse_conn_info_handle(buf: &[u8]) -> Option<u16> {
    let b = buf.get(CONN_INFO_HANDLE..CONN_INFO_HANDLE + 2)?;
    Some(u16::from_le_bytes([b[0], b[1]]))
}

// ---------------------------------------------------------------------------
// `HCIGETCONNLIST` buffer codec (BlueZ ABI). The ioctl takes one buffer that
// is `struct hci_conn_list_req` (dev_id(2) + conn_num(2)) going in, followed
// by `conn_num` capacity slots of `struct hci_conn_info`; the kernel rewrites
// `conn_num` to the number of entries it filled.
// ---------------------------------------------------------------------------

/// Size of the list header (`dev_id` + `conn_num`).
const CONN_LIST_HDR: usize = 4;
/// Size of one `hci_conn_info` entry: handle(2), bdaddr(6), type(1), out(1),
/// state(2), link_mode(4).
const CONN_INFO_LEN: usize = 16;
/// Entry slots in the request buffer. The kernel's concurrent connection
/// count stays well below this.
const CONN_LIST_MAX: usize = 32;

/// One established connection, as the kernel reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnInfo {
    /// The connection handle that commands like Read RSSI take.
    pub handle: u16,
    /// Peer address in display form.
    pub address: String,
    /// True for an LE link, false for a BR/EDR link.
    pub le: bool,
    /// True when the local side initiated the connection.
    pub outgoing: bool,
}

/// Build the `HCIGETCONNLIST` buffer asking for adapter `dev`'s connections.
pub fn conn_list_request(dev: u16) -> Vec<u8> {
    let mut buf = vec![0u8; CONN_LIST_HDR + CONN_LIST_MAX * CONN_INFO_LEN];
    buf[0..2].copy_from_slice(&dev.to_le_bytes());
    buf[2..4].copy_from_slice(&(CONN_LIST_MAX as u16).to_le_bytes());
    buf
}

/// Decode a filled `HCIGETCONNLIST` buffer. The kernel rewrote the count in
/// the header; a count past the buffer's end, or a truncated trailing entry,
/// stops the decode rather than reading out of bounds.
pub fn parse_conn_list(buf: &[u8]) -> Vec<ConnInfo> {
    let count = match buf.get(2..4) {
        Some(b) => u16::from_le_bytes([b[0], b[1]]) as usize,
        None => return Vec::new(),
    };
    let mut out = Vec::new();
    for i in 0..count {
        let off = CONN_LIST_HDR + i * CONN_INFO_LEN;
        let entry = match buf.get(off..off + CONN_INFO_LEN) {
            Some(e) => e,
            None => break,
        };
        out.push(ConnInfo {
            handle: u16::from_le_bytes([entry[0], entry[1]]),
            address: format_addr_le(&entry[2..8]),
            le: entry[8] == LE_LINK,
            outgoing: entry[9] != 0,
        });
    }
    out
}

/// A decoded Read RSSI Command Complete event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadRssiComplete {
    /// HCI status code (`0x00` = success).
    pub status: u8,
    /// The connection handle the controller echoes back.
    pub handle: u16,
    /// RSSI in dBm, or `None` for the spec's 127 "not available" sentinel.
    pub rssi: Option<i8>,
}

/// Decode a Read RSSI Command Complete from one HCI event packet. `None` for
/// any other packet, a truncated event, or a Command Complete for another
/// opcode.
pub fn parse_read_rssi_complete(buf: &[u8]) -> Option<ReadRssiComplete> {
    // [0x04][0x0E][plen][num_hci_cmd_pkts][opcode(2)][status][handle(2)][rssi]
    if buf.len() < 3 || buf[0] != HCI_EVENT_PKT || buf[1] != HCI_EV_CMD_COMPLETE {
        return None;
    }
    let plen = buf[2] as usize;
    let params = buf.get(3..3 + plen)?;
    if params.len() < 7 {
        return None;
    }
    if u16::from_le_bytes([params[1], params[2]]) != OPCODE_READ_RSSI {
        return None;
    }
    let rssi_byte = params[6];
    Some(ReadRssiComplete {
        status: params[3],
        handle: u16::from_le_bytes([params[4], params[5]]),
        rssi: if rssi_byte == 0x7f {
            None
        } else {
            Some(rssi_byte as i8)
        },
    })
}

/// Why a connection RSSI query failed. The socket stages mirror
/// [`crate::scan::ScanError`], so a caller can give the same permission and
/// adapter hints.
#[derive(Debug)]
pub enum RssiError {
    /// The peer MAC string could not be parsed.
    BadPeer(String),
    /// `socket()` failed, typically because the kernel has no Bluetooth
    /// support. The raw HCI socket opens without `CAP_NET_RAW`.
    Socket(io::Error),
    /// `bind()` to the controller index failed: there is no controller at that
    /// index. Binding succeeds for a controller that is down.
    Bind(io::Error),
    /// Setting the HCI event filter failed; without it no events arrive.
    Filter(io::Error),
    /// Setting the receive timeout failed.
    RecvTimeout(io::Error),
    /// `HCIGETCONNINFO` found no LE connection to the peer on this adapter.
    NoConnection(io::Error),
    /// The Read RSSI command could not be written. The [`io::Error`] carries
    /// the kernel's reason; a partial write is [`io::ErrorKind::WriteZero`].
    Write(io::Error),
    /// The controller answered Read RSSI with a non-zero status.
    Rejected { status: u8 },
    /// A read error while waiting for the command's completion event.
    Io(io::Error),
    /// No Command Complete arrived within the bounded wait.
    NoResponse,
    /// This platform has no raw HCI socket.
    Unsupported,
}

impl fmt::Display for RssiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RssiError::BadPeer(mac) => write!(f, "bad peer MAC '{mac}'"),
            RssiError::Socket(e) => write!(f, "cannot open raw HCI socket ({e})"),
            RssiError::Bind(e) => write!(f, "cannot bind controller ({e})"),
            RssiError::Filter(e) => write!(f, "cannot set HCI event filter ({e})"),
            RssiError::RecvTimeout(e) => write!(f, "cannot set receive timeout ({e})"),
            RssiError::NoConnection(e) => write!(f, "no LE connection to the peer ({e})"),
            RssiError::Write(e) => write!(f, "cannot write Read RSSI command ({e})"),
            RssiError::Rejected { status } => {
                write!(f, "controller rejected Read RSSI (status 0x{status:02x})")
            }
            RssiError::Io(e) => write!(f, "read error awaiting command response ({e})"),
            RssiError::NoResponse => write!(f, "no Command Complete from controller"),
            RssiError::Unsupported => {
                write!(f, "connection RSSI queries are only supported on Linux")
            }
        }
    }
}

impl std::error::Error for RssiError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            RssiError::Socket(e)
            | RssiError::Bind(e)
            | RssiError::Filter(e)
            | RssiError::RecvTimeout(e)
            | RssiError::NoConnection(e)
            | RssiError::Write(e)
            | RssiError::Io(e) => Some(e),
            _ => None,
        }
    }
}

// ===========================================================================
// Linux-only raw HCI socket
// ===========================================================================

#[cfg(target_os = "linux")]
pub use linux_impl::{connections, read_rssi};

/// Read the RSSI of an established LE connection. This platform has no raw
/// HCI socket, so this always fails with [`RssiError::Unsupported`].
/// List the connections established on an adapter. This platform has no HCI
/// ioctl interface, so this always fails.
#[cfg(not(target_os = "linux"))]
pub fn connections(_dev: u16) -> Result<Vec<ConnInfo>, String> {
    Err("connection listing is only supported on Linux".to_string())
}

#[cfg(not(target_os = "linux"))]
pub fn read_rssi(_dev: u16, _peer: &str, _recv_timeout: Duration) -> Result<Option<i8>, RssiError> {
    Err(RssiError::Unsupported)
}

#[cfg(target_os = "linux")]
mod linux_impl {
    use super::*;
    use crate::hci::{build_command, parse_command_event};
    use crate::l2cap::mac_str_to_le;
    use crate::sys::{
        bind, errno, ioctl, read, set_recv_timeout, setsockopt, socket, write, FdGuard, Timeval,
        AF_BLUETOOTH, BTPROTO_HCI, EAGAIN, EINTR, SOCK_RAW,
    };
    use std::os::raw::{c_int, c_ulong, c_void};

    // The raw HCI channel and its filter option, as in [`crate::scan`]'s
    // socket layer; this module owns its own copies so the two stay
    // independently readable.
    const HCI_CHANNEL_RAW: u16 = 0;
    const SOL_HCI: c_int = 0;
    const HCI_FILTER: c_int = 2;

    /// BlueZ ioctl `_IOR('H', 213, int)` in the asm-generic `_IOC` encoding
    /// shared by x86 / arm / arm64 / riscv (see [`crate::adapter`] for the
    /// field breakdown of sibling requests 210 and 211).
    const HCIGETCONNINFO: c_ulong = 0x8004_48D5;
    /// Its list-everything sibling, `_IOR('H', 212, int)`.
    const HCIGETCONNLIST: c_ulong = 0x8004_48D4;

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
        // Explicit trailing pad, as in the scanner's copy: the two padding
        // bytes handed to setsockopt stay initialized.
        _pad: u16,
    }

    /// List the connections currently established on adapter `dev` via
    /// `HCIGETCONNLIST`. The kernel answers from its own state: no HCI
    /// command is sent and the connections themselves are untouched.
    pub fn connections(dev: u16) -> Result<Vec<ConnInfo>, String> {
        let fd = unsafe { socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI) };
        if fd < 0 {
            return Err(format!(
                "cannot open HCI control socket (errno {}); is Bluetooth in the kernel?",
                unsafe { errno() }
            ));
        }
        let _guard = FdGuard(fd);
        let mut buf = conn_list_request(dev);
        let rc = unsafe { ioctl(fd, HCIGETCONNLIST, buf.as_mut_ptr() as *mut c_void) };
        if rc < 0 {
            return Err(format!(
                "HCIGETCONNLIST failed for hci{dev} (errno {})",
                unsafe { errno() }
            ));
        }
        Ok(parse_conn_list(&buf))
    }

    /// Read the RSSI of the established LE connection to `peer` (a display
    /// MAC) on controller index `dev` (`hciN` means `N`). `Ok(None)` means the
    /// controller answered with the "RSSI not available" sentinel.
    /// `recv_timeout` paces each read while awaiting the Command Complete, so
    /// a controller that never answers cannot hang the caller.
    ///
    /// The connection itself is untouched: its handle is looked up with
    /// `HCIGETCONNINFO`, and a connection that does not exist surfaces as
    /// [`RssiError::NoConnection`].
    pub fn read_rssi(
        dev: u16,
        peer: &str,
        recv_timeout: Duration,
    ) -> Result<Option<i8>, RssiError> {
        let peer_le = mac_str_to_le(peer).ok_or_else(|| RssiError::BadPeer(peer.to_string()))?;

        let fd = unsafe { socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI) };
        if fd < 0 {
            return Err(RssiError::Socket(io::Error::last_os_error()));
        }
        let _guard = FdGuard(fd);

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
            return Err(RssiError::Bind(io::Error::last_os_error()));
        }

        // Receive event packets, but only Command Complete (0x0E) and Command
        // Status (0x0F). The kernel tests the event code against event_mask
        // bit by bit, so accepting everything would deliver advertising
        // reports too when the adapter is scanning, and a flood of them could
        // exhaust the bounded wait below before the completion arrives.
        let filter = HciFilter {
            type_mask: 1 << 4,
            event_mask: [
                (1u32 << HCI_EV_CMD_COMPLETE) | (1u32 << HCI_EV_CMD_STATUS),
                0,
            ],
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
            return Err(RssiError::Filter(io::Error::last_os_error()));
        }

        let rc = set_recv_timeout(fd, &Timeval::from_duration(recv_timeout));
        if rc < 0 {
            return Err(RssiError::RecvTimeout(io::Error::last_os_error()));
        }

        // Ask the kernel for the connection's handle.
        let mut info = conn_info_request(peer_le);
        let rc = unsafe { ioctl(fd, HCIGETCONNINFO, info.as_mut_ptr() as *mut c_void) };
        if rc < 0 {
            return Err(RssiError::NoConnection(io::Error::last_os_error()));
        }
        let handle = parse_conn_info_handle(&info).ok_or(RssiError::NoResponse)?;

        // Ask the controller for the RSSI on that handle.
        let cmd = build_command(OPCODE_READ_RSSI, &handle.to_le_bytes());
        let n = unsafe { write(fd, cmd.as_ptr() as *const c_void, cmd.len()) };
        if n < 0 {
            return Err(RssiError::Write(io::Error::last_os_error()));
        }
        if n as usize != cmd.len() {
            return Err(RssiError::Write(io::Error::new(
                io::ErrorKind::WriteZero,
                "short write to HCI socket",
            )));
        }

        // Await the Command Complete, skipping unrelated events. Bounded to a
        // handful of reads, each limited by the receive timeout.
        const MAX_WAIT: u32 = 8;
        let mut buf = [0u8; 512];
        for _ in 0..MAX_WAIT {
            let n = unsafe { read(fd, buf.as_mut_ptr() as *mut c_void, buf.len()) };
            if n == 0 {
                return Err(RssiError::Io(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "controller closed the HCI socket",
                )));
            }
            if n < 0 {
                let e = unsafe { errno() };
                if e == EAGAIN || e == EINTR {
                    continue;
                }
                return Err(RssiError::Io(io::Error::from_raw_os_error(e)));
            }
            let pkt = &buf[..n as usize];
            if let Some(rsp) = parse_read_rssi_complete(pkt) {
                if rsp.status != 0 {
                    return Err(RssiError::Rejected { status: rsp.status });
                }
                if rsp.handle == handle {
                    return Ok(rsp.rssi);
                }
            } else if let Some((op, status)) = parse_command_event(pkt) {
                // A controller that does not implement the command answers
                // with a Command Status error instead of a Command Complete.
                if op == OPCODE_READ_RSSI && status != 0 {
                    return Err(RssiError::Rejected { status });
                }
            }
        }
        Err(RssiError::NoResponse)
    }
}

// ===========================================================================
// Tests for the pure layer (run on every platform)
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conn_list_request_names_the_adapter_and_capacity() {
        let buf = conn_list_request(1);
        assert_eq!(buf.len(), 4 + 32 * 16);
        assert_eq!(&buf[0..2], &[0x01, 0x00]); // dev_id 1, little-endian
        assert_eq!(&buf[2..4], &[32, 0x00]); // capacity in slots
        assert!(buf[4..].iter().all(|&b| b == 0)); // kernel-filled area
    }

    /// One 16-byte `hci_conn_info` entry.
    fn conn_entry(handle: u16, addr_le: [u8; 6], link_type: u8, out: u8) -> Vec<u8> {
        let mut e = Vec::with_capacity(16);
        e.extend_from_slice(&handle.to_le_bytes());
        e.extend_from_slice(&addr_le);
        e.push(link_type);
        e.push(out);
        e.extend_from_slice(&[0; 6]); // state(2) + link_mode(4)
        e
    }

    #[test]
    fn conn_list_decodes_entries_and_link_types() {
        let mut buf = vec![0x00, 0x00, 0x02, 0x00]; // dev 0, count 2
        buf.extend(conn_entry(
            0x0040,
            [0xCC, 0xBB, 0xAA, 0x4E, 0xC9, 0x70],
            0x80, // LE link
            1,    // outgoing
        ));
        buf.extend(conn_entry(
            0x0002,
            [0x06, 0x05, 0x04, 0x03, 0x02, 0x01],
            0x01, // ACL (BR/EDR)
            0,    // incoming
        ));
        let conns = parse_conn_list(&buf);
        assert_eq!(
            conns,
            vec![
                ConnInfo {
                    handle: 0x0040,
                    address: "70:C9:4E:AA:BB:CC".to_string(),
                    le: true,
                    outgoing: true,
                },
                ConnInfo {
                    handle: 0x0002,
                    address: "01:02:03:04:05:06".to_string(),
                    le: false,
                    outgoing: false,
                },
            ]
        );
    }

    #[test]
    fn conn_list_stops_at_a_truncated_entry() {
        // The header claims three entries but the buffer holds one full entry
        // and a truncated second; only the full one is decoded.
        let mut buf = vec![0x00, 0x00, 0x03, 0x00];
        buf.extend(conn_entry(0x0040, [0; 6], 0x80, 0));
        buf.extend_from_slice(&[0xAA; 5]);
        assert_eq!(parse_conn_list(&buf).len(), 1);
        // A buffer too short for the header decodes to nothing.
        assert!(parse_conn_list(&[0x00]).is_empty());
        assert!(parse_conn_list(&[]).is_empty());
    }

    #[test]
    fn conn_info_request_sets_address_and_le_link() {
        let buf = conn_info_request([0xCC, 0xBB, 0xAA, 0x4E, 0xC9, 0x70]);
        assert_eq!(buf.len(), 24);
        assert_eq!(&buf[..6], &[0xCC, 0xBB, 0xAA, 0x4E, 0xC9, 0x70]);
        assert_eq!(buf[6], 0x80); // LE link type
        assert!(buf[7..].iter().all(|&b| b == 0)); // kernel-filled area
    }

    #[test]
    fn conn_info_handle_is_read_after_the_padded_request() {
        let mut buf = conn_info_request([0; 6]);
        buf[8] = 0x40; // handle 0x0040, little-endian at offset 8
        buf[9] = 0x00;
        assert_eq!(parse_conn_info_handle(&buf), Some(0x0040));
        // Too short to hold the info: no handle.
        assert_eq!(parse_conn_info_handle(&buf[..9]), None);
    }

    #[test]
    fn read_rssi_complete_decodes_status_handle_and_rssi() {
        // Command Complete, plen 7, opcode 0x1405, status 0, handle 0x0040,
        // rssi 0xc4 (-60 dBm).
        let pkt = [0x04, 0x0E, 0x07, 0x01, 0x05, 0x14, 0x00, 0x40, 0x00, 0xC4];
        assert_eq!(
            parse_read_rssi_complete(&pkt),
            Some(ReadRssiComplete {
                status: 0,
                handle: 0x0040,
                rssi: Some(-60),
            })
        );
    }

    #[test]
    fn read_rssi_complete_maps_the_unavailable_sentinel() {
        // rssi byte 0x7F means "not available" and must not read as +127 dBm.
        let pkt = [0x04, 0x0E, 0x07, 0x01, 0x05, 0x14, 0x00, 0x40, 0x00, 0x7F];
        assert_eq!(parse_read_rssi_complete(&pkt).unwrap().rssi, None);
    }

    #[test]
    fn read_rssi_complete_rejects_other_packets() {
        // Another opcode (LE Set Scan Enable).
        let other = [0x04, 0x0E, 0x07, 0x01, 0x0C, 0x20, 0x00, 0x40, 0x00, 0xC4];
        assert_eq!(parse_read_rssi_complete(&other), None);
        // Command Status event, not Command Complete.
        let status = [0x04, 0x0F, 0x04, 0x00, 0x01, 0x05, 0x14];
        assert_eq!(parse_read_rssi_complete(&status), None);
        // Truncated return parameters.
        let short = [0x04, 0x0E, 0x04, 0x01, 0x05, 0x14, 0x00];
        assert_eq!(parse_read_rssi_complete(&short), None);
        // Not an event packet at all.
        assert_eq!(parse_read_rssi_complete(&[0x02, 0x00, 0x00]), None);
        assert_eq!(parse_read_rssi_complete(&[]), None);
    }

    #[test]
    fn opcode_is_the_status_parameters_ogf() {
        assert_eq!(OPCODE_READ_RSSI >> 10, 0x05);
        assert_eq!(OPCODE_READ_RSSI & 0x03FF, 0x0005);
    }

    #[test]
    fn error_display_names_the_failure() {
        let e = RssiError::Rejected { status: 0x02 };
        assert_eq!(e.to_string(), "controller rejected Read RSSI (status 0x02)");
        assert!(RssiError::Unsupported.to_string().contains("Linux"));
    }

    #[test]
    fn write_error_keeps_the_kernel_error() {
        use std::error::Error as _;
        let e = RssiError::Write(io::Error::from(io::ErrorKind::NetworkDown));
        assert!(e.to_string().starts_with("cannot write Read RSSI command"));
        let source = e.source().and_then(|s| s.downcast_ref::<io::Error>());
        assert_eq!(
            source.map(io::Error::kind),
            Some(io::ErrorKind::NetworkDown)
        );
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn read_rssi_is_unsupported_off_linux() {
        assert!(matches!(
            read_rssi(0, "AA:BB:CC:DD:EE:FF", Duration::from_secs(1)),
            Err(RssiError::Unsupported)
        ));
    }
}
