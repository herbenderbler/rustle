//! Linux L2CAP ATT socket — the real transport behind [`crate::client::AttIo`].
//!
//! Connects a `SOCK_SEQPACKET` L2CAP socket to a peer on the ATT fixed channel
//! (CID `0x0004`). The kernel performs the LE link + L2CAP setup, and because
//! the channel is sequential-packet each `recv` yields exactly one ATT PDU. The
//! socket layer is Linux-only (needs elevated perms and `bluetoothd` to not own
//! the controller); on other platforms [`L2capAtt::connect`] fails with
//! [`std::io::ErrorKind::Unsupported`]. The pure address helper and
//! [`SecurityLevel`] exist everywhere.

/// L2CAP security level requested via `BT_SECURITY` before connecting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecurityLevel {
    Low = 1,
    Medium = 2,
    High = 3,
}

/// Parse a display MAC (`"AA:BB:CC:DD:EE:FF"`) into the 6 little-endian bytes a
/// BlueZ sockaddr expects (least-significant byte first — the reverse of the
/// display order). Returns `None` on a malformed address.
pub fn mac_str_to_le(mac: &str) -> Option<[u8; 6]> {
    let mut out = [0u8; 6];
    let mut count = 0usize;
    for (i, part) in mac.split(':').enumerate() {
        if i >= 6 {
            return None; // too many octets
        }
        out[5 - i] = u8::from_str_radix(part, 16).ok()?;
        count += 1;
    }
    if count == 6 {
        Some(out)
    } else {
        None
    }
}

// ===========================================================================
// Linux-only socket layer
// ===========================================================================

#[cfg(target_os = "linux")]
pub use linux_impl::L2capAtt;

#[cfg(target_os = "linux")]
mod linux_impl {
    use super::{mac_str_to_le, SecurityLevel};
    use crate::client::AttIo;
    use crate::sys::{
        bind, close, connect, errno, read, set_recv_timeout, setsockopt, socket, write, FdGuard,
        Timeval, AF_BLUETOOTH, BTPROTO_L2CAP, EAGAIN, EINTR, SOCK_SEQPACKET,
    };
    use std::io;
    use std::os::raw::{c_int, c_void};

    const SOL_BLUETOOTH: c_int = 274;
    const BT_SECURITY: c_int = 4;

    /// ATT protocol's fixed L2CAP channel identifier.
    const ATT_CID: u16 = 0x0004;
    const BDADDR_LE_PUBLIC: u8 = 1;
    const BDADDR_LE_RANDOM: u8 = 2;

    #[repr(C)]
    struct SockaddrL2 {
        l2_family: u16,
        l2_psm: u16,
        l2_bdaddr: [u8; 6],
        l2_cid: u16,
        l2_bdaddr_type: u8,
        // The struct is 14 bytes (align 2) but the fields above end at offset 13,
        // so this explicit trailing pad keeps the one padding byte handed to
        // bind()/connect() (via `size_of`) initialized rather than crossing the
        // FFI boundary uninitialized. Layout/size are unchanged.
        _pad: u8,
    }

    #[repr(C)]
    struct BtSecurity {
        level: u8,
        key_size: u8,
    }

    fn sockaddr(bdaddr: [u8; 6], is_random: bool) -> SockaddrL2 {
        SockaddrL2 {
            l2_family: AF_BLUETOOTH as u16,
            l2_psm: 0,
            l2_bdaddr: bdaddr,
            l2_cid: ATT_CID,
            l2_bdaddr_type: if is_random {
                BDADDR_LE_RANDOM
            } else {
                BDADDR_LE_PUBLIC
            },
            _pad: 0,
        }
    }

    /// A connected L2CAP ATT channel. Implements [`AttIo`]; closes the socket on
    /// drop.
    pub struct L2capAtt {
        fd: c_int,
    }

    impl Drop for L2capAtt {
        fn drop(&mut self) {
            unsafe { close(self.fd) };
        }
    }

    impl L2capAtt {
        /// Open an ATT channel to `peer` (a display MAC), sourced from adapter
        /// address `local` (`None` binds `BDADDR_ANY` / the default adapter).
        /// `*_random` selects random vs public addressing for each side.
        /// `recv_timeout_secs` sets `SO_RCVTIMEO` so a notify read loop can poll a
        /// shutdown flag. The `connect` itself is blocking (the kernel drives the
        /// LE connection); a non-blocking connect timeout is a later refinement.
        pub fn connect(
            local: Option<&str>,
            local_random: bool,
            peer: &str,
            peer_random: bool,
            security: SecurityLevel,
            recv_timeout_secs: i64,
        ) -> io::Result<Self> {
            let peer_addr = mac_str_to_le(peer).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("bad peer MAC '{peer}'"),
                )
            })?;
            let local_addr = match local {
                Some(m) => mac_str_to_le(m).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, format!("bad local MAC '{m}'"))
                })?,
                None => [0u8; 6], // BDADDR_ANY
            };

            let fd = unsafe { socket(AF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP) };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            let guard = FdGuard(fd);

            // Bind the local side (adapter + own address type) on the ATT CID.
            let la = sockaddr(local_addr, local_random);
            let rc = unsafe {
                bind(
                    fd,
                    &la as *const SockaddrL2 as *const c_void,
                    std::mem::size_of::<SockaddrL2>() as u32,
                )
            };
            if rc < 0 {
                return Err(io::Error::last_os_error());
            }

            // Requested security level (best-effort: some links negotiate it
            // during connect, so a setsockopt failure here isn't fatal).
            let sec = BtSecurity {
                level: security as u8,
                key_size: 0,
            };
            unsafe {
                setsockopt(
                    fd,
                    SOL_BLUETOOTH,
                    BT_SECURITY,
                    &sec as *const BtSecurity as *const c_void,
                    std::mem::size_of::<BtSecurity>() as u32,
                );
            }

            // Receive timeout so a notify read loop stays responsive to shutdown.
            set_recv_timeout(fd, &Timeval::from_secs(recv_timeout_secs));

            // Connect — the kernel performs the LE connection + L2CAP channel setup.
            let pa = sockaddr(peer_addr, peer_random);
            let rc = unsafe {
                connect(
                    fd,
                    &pa as *const SockaddrL2 as *const c_void,
                    std::mem::size_of::<SockaddrL2>() as u32,
                )
            };
            if rc < 0 {
                return Err(io::Error::last_os_error());
            }

            std::mem::forget(guard); // success — ownership moves to L2capAtt
            Ok(L2capAtt { fd })
        }
    }

    impl AttIo for L2capAtt {
        fn send(&mut self, pdu: &[u8]) -> io::Result<()> {
            let n = unsafe { write(self.fd, pdu.as_ptr() as *const c_void, pdu.len()) };
            if n == pdu.len() as isize {
                Ok(())
            } else if n < 0 {
                Err(io::Error::last_os_error())
            } else {
                Err(io::Error::new(io::ErrorKind::WriteZero, "short ATT write"))
            }
        }

        fn recv(&mut self) -> io::Result<Vec<u8>> {
            // One SEQPACKET datagram = one ATT PDU. ATT MTU tops out at 517.
            let mut buf = [0u8; 1024];
            let n = unsafe { read(self.fd, buf.as_mut_ptr() as *mut c_void, buf.len()) };
            if n > 0 {
                Ok(buf[..n as usize].to_vec())
            } else if n == 0 {
                Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "peer closed the ATT channel",
                ))
            } else {
                let e = unsafe { errno() };
                if e == EAGAIN || e == EINTR {
                    // SO_RCVTIMEO elapsed — surfaced as WouldBlock so a notify
                    // loop treats it as "no event yet" rather than a fatal error.
                    Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "ATT recv timed out",
                    ))
                } else {
                    Err(io::Error::from_raw_os_error(e))
                }
            }
        }
    }
}

// ===========================================================================
// Every other platform: the type exists so a `GattClient<L2capAtt>` compiles,
// but it can never be constructed.
// ===========================================================================

#[cfg(not(target_os = "linux"))]
pub use other_impl::L2capAtt;

#[cfg(not(target_os = "linux"))]
mod other_impl {
    use super::SecurityLevel;
    use crate::client::AttIo;
    use std::convert::Infallible;
    use std::io;

    /// An L2CAP ATT channel. This platform has no L2CAP socket, so
    /// [`L2capAtt::connect`] always fails with [`io::ErrorKind::Unsupported`]
    /// and no value of this type can exist.
    pub struct L2capAtt(Infallible);

    impl L2capAtt {
        /// Always [`io::ErrorKind::Unsupported`] on this platform.
        pub fn connect(
            _local: Option<&str>,
            _local_random: bool,
            _peer: &str,
            _peer_random: bool,
            _security: SecurityLevel,
            _recv_timeout_secs: i64,
        ) -> io::Result<Self> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "L2CAP ATT sockets are only supported on Linux",
            ))
        }
    }

    impl AttIo for L2capAtt {
        fn send(&mut self, _pdu: &[u8]) -> io::Result<()> {
            match self.0 {}
        }

        fn recv(&mut self) -> io::Result<Vec<u8>> {
            match self.0 {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_parses_to_little_endian() {
        // Display is MSB-first; the wire form is least-significant byte first.
        assert_eq!(
            mac_str_to_le("70:C9:4E:AA:BB:CC"),
            Some([0xCC, 0xBB, 0xAA, 0x4E, 0xC9, 0x70])
        );
        // Lowercase is accepted too.
        assert_eq!(
            mac_str_to_le("d4:12:34:56:78:9a"),
            Some([0x9a, 0x78, 0x56, 0x34, 0x12, 0xd4])
        );
    }

    #[test]
    fn malformed_mac_is_none() {
        assert!(mac_str_to_le("").is_none());
        assert!(mac_str_to_le("70:C9:4E:AA:BB").is_none()); // too few
        assert!(mac_str_to_le("70:C9:4E:AA:BB:CC:DD").is_none()); // too many
        assert!(mac_str_to_le("70:C9:4E:AA:BB:ZZ").is_none()); // non-hex
    }

    #[test]
    fn security_level_maps_to_bt_security_values() {
        // The discriminants are the `BT_SECURITY` socket-option values.
        assert_eq!(SecurityLevel::Low as u8, 1);
        assert_eq!(SecurityLevel::Medium as u8, 2);
        assert_eq!(SecurityLevel::High as u8, 3);
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn connect_is_unsupported_off_linux() {
        let err = L2capAtt::connect(
            None,
            false,
            "AA:BB:CC:DD:EE:FF",
            false,
            SecurityLevel::Low,
            1,
        )
        .err()
        .expect("no L2CAP socket on this platform");
        assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
    }
}
