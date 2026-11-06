//! Linux L2CAP ATT socket — the real transport behind [`crate::client::AttIo`].
//!
//! Connects a `SOCK_SEQPACKET` L2CAP socket to a peer on the ATT fixed channel
//! (CID `0x0004`). The kernel performs the LE link + L2CAP setup, and because
//! the channel is sequential-packet each `recv` yields exactly one ATT PDU. The
//! socket layer is Linux-only and needs elevated permissions; on other
//! platforms [`L2capAtt::connect`] fails with
//! [`std::io::ErrorKind::Unsupported`]. The pure address helper and
//! [`SecurityLevel`] exist everywhere.
//!
//! # Security
//!
//! Above [`SecurityLevel::Low`] the kernel must pair with the device, and it
//! does so only after it has reported the channel connected. It then asks a
//! pairing agent to approve the pairing, even a Just Works pairing that needs
//! no passkey. Without a program to approve it, such as `bluetoothd` with an
//! agent registered, the pairing never finishes and the link stays
//! unencrypted. [`L2capAtt::connect`] therefore waits for the link to reach
//! the requested level and fails if it does not.

/// Link security for an ATT channel, as the kernel's `BT_SECURITY` levels.
///
/// `Low` leaves the link unencrypted. `Medium` needs an encrypted link, and
/// `High` an encrypted link whose key was authenticated against
/// man-in-the-middle attacks, for example with a passkey. Both make the kernel
/// pair with the device. Levels compare in that order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SecurityLevel {
    Low = 1,
    Medium = 2,
    High = 3,
}

impl SecurityLevel {
    /// The level a raw `BT_SECURITY` value reports. The kernel's FIPS level
    /// (4, Secure Connections with an authenticated key) meets `High`, and
    /// anything below `Low` counts as `Low`.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    fn from_bt_security(raw: u8) -> SecurityLevel {
        match raw {
            0..=1 => SecurityLevel::Low,
            2 => SecurityLevel::Medium,
            _ => SecurityLevel::High,
        }
    }
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
        bind, close, connect, errno, fcntl, getsockopt, poll, read, set_recv_timeout, setsockopt,
        socket, write, FdGuard, PollFd, Timeval, AF_BLUETOOTH, BTPROTO_L2CAP, EAGAIN, EINPROGRESS,
        EINTR, F_GETFL, F_SETFL, O_NONBLOCK, POLLERR, POLLHUP, POLLOUT, SOCK_SEQPACKET, SOL_SOCKET,
        SO_ERROR,
    };
    use std::io;
    use std::os::raw::{c_int, c_void};
    use std::time::{Duration, Instant};

    const SOL_BLUETOOTH: c_int = 274;
    const BT_SECURITY: c_int = 4;

    /// How long [`L2capAtt::connect`] waits for pairing. The kernel abandons
    /// a pairing that makes no progress for 30 s, so this outlasts it.
    const PAIRING_WAIT: Duration = Duration::from_secs(40);
    /// How often the link's security level is checked while waiting.
    const SECURITY_POLL: Duration = Duration::from_millis(50);

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

    /// The socket's pending error (`SO_ERROR`), which reading also clears.
    fn socket_error(fd: c_int) -> io::Result<Option<io::Error>> {
        let mut err: c_int = 0;
        let mut len = std::mem::size_of::<c_int>() as u32;
        let rc = unsafe {
            getsockopt(
                fd,
                SOL_SOCKET,
                SO_ERROR,
                &mut err as *mut c_int as *mut c_void,
                &mut len,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok((err != 0).then(|| io::Error::from_raw_os_error(err)))
    }

    /// Wait up to `ms` for the link to drop. `Ok` means it is still up;
    /// otherwise the error is the one the kernel recorded for the socket.
    fn link_up(fd: c_int, ms: c_int) -> io::Result<()> {
        // With no events requested, poll reports only a hang-up or an error,
        // so data arriving on the channel does not wake it.
        let mut pfd = PollFd {
            fd,
            events: 0,
            revents: 0,
        };
        let rc = unsafe { poll(&mut pfd, 1, ms) };
        if rc < 0 {
            let e = unsafe { errno() };
            return if e == EINTR {
                Ok(())
            } else {
                Err(io::Error::from_raw_os_error(e))
            };
        }
        if pfd.revents & (POLLHUP | POLLERR) == 0 {
            return Ok(());
        }
        Err(socket_error(fd)?
            .unwrap_or_else(|| io::Error::new(io::ErrorKind::ConnectionAborted, "the link closed")))
    }

    /// The raw `BT_SECURITY` level. While the link is up it is the link's
    /// level; once the link is gone the kernel reports the requested level
    /// instead, so callers check [`link_up`] after reading it.
    fn bt_security(fd: c_int) -> io::Result<u8> {
        let mut sec = BtSecurity {
            level: 0,
            key_size: 0,
        };
        let mut len = std::mem::size_of::<BtSecurity>() as u32;
        let rc = unsafe {
            getsockopt(
                fd,
                SOL_BLUETOOTH,
                BT_SECURITY,
                &mut sec as *mut BtSecurity as *mut c_void,
                &mut len,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(sec.level)
    }

    /// Hold a newly connected channel until its link reaches `wanted`.
    ///
    /// The kernel reports an ATT channel connected before it pairs, so a
    /// channel asked to run above `Low` starts out unencrypted. Check the
    /// link's level until it reaches `wanted`, the link drops, or `deadline`
    /// passes.
    fn await_security(
        fd: c_int,
        peer: &str,
        wanted: SecurityLevel,
        deadline: Instant,
    ) -> io::Result<()> {
        if wanted == SecurityLevel::Low {
            return Ok(());
        }
        let begun = Instant::now();
        let closed = |e: io::Error| {
            io::Error::new(
                e.kind(),
                format!("link to {peer} closed before reaching {wanted:?} security: {e}"),
            )
        };
        loop {
            let level = SecurityLevel::from_bt_security(bt_security(fd)?);
            link_up(fd, 0).map_err(closed)?;
            if level >= wanted {
                return Ok(());
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!(
                        "link to {peer} still at {level:?} security after {} ms, short of \
                         {wanted:?}: pairing did not finish. The kernel asks a pairing agent, \
                         such as bluetoothd's, to approve every pairing",
                        begun.elapsed().as_millis()
                    ),
                ));
            }
            let ms = remaining.min(SECURITY_POLL).as_millis() as c_int;
            link_up(fd, ms).map_err(closed)?;
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
        /// Create, bind and configure the ATT socket, stopping just short of
        /// the connect. Returns the guarded fd (closed on early return until
        /// ownership moves) and the peer sockaddr to connect to.
        fn prepare(
            local: Option<&str>,
            local_random: bool,
            peer: &str,
            peer_random: bool,
            security: SecurityLevel,
            recv_timeout_secs: i64,
        ) -> io::Result<(FdGuard, SockaddrL2)> {
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

            // Requested security level. Low is the kernel's default, so only a
            // failure to ask for more matters.
            let sec = BtSecurity {
                level: security as u8,
                key_size: 0,
            };
            let rc = unsafe {
                setsockopt(
                    fd,
                    SOL_BLUETOOTH,
                    BT_SECURITY,
                    &sec as *const BtSecurity as *const c_void,
                    std::mem::size_of::<BtSecurity>() as u32,
                )
            };
            if rc < 0 && security > SecurityLevel::Low {
                return Err(io::Error::last_os_error());
            }

            // Receive timeout so a notify read loop stays responsive to shutdown.
            set_recv_timeout(fd, &Timeval::from_secs(recv_timeout_secs));

            Ok((guard, sockaddr(peer_addr, peer_random)))
        }

        /// Open an ATT channel to `peer` (a display MAC), sourced from adapter
        /// address `local` (`None` binds `BDADDR_ANY` / the default adapter).
        /// `*_random` selects random vs public addressing for each side.
        /// `recv_timeout_secs` sets `SO_RCVTIMEO` so a notify read loop can poll a
        /// shutdown flag. The `connect` itself is blocking (the kernel drives the
        /// LE connection) and runs until the kernel's own connection supervision
        /// gives up; [`connect_timeout`](Self::connect_timeout) bounds it instead.
        ///
        /// Above [`SecurityLevel::Low`] it returns only once the link has
        /// reached `security`, because the kernel connects first and pairs
        /// afterwards. It fails if the link drops first, or with
        /// [`io::ErrorKind::TimedOut`] if pairing has not finished within 40 s,
        /// longer than the kernel's own 30 s pairing timeout. The kernel asks a
        /// pairing agent to approve every pairing, Just Works included, so
        /// without one, such as `bluetoothd` with an agent registered, it fails.
        pub fn connect(
            local: Option<&str>,
            local_random: bool,
            peer: &str,
            peer_random: bool,
            security: SecurityLevel,
            recv_timeout_secs: i64,
        ) -> io::Result<Self> {
            let (guard, pa) = Self::prepare(
                local,
                local_random,
                peer,
                peer_random,
                security,
                recv_timeout_secs,
            )?;

            // Connect — the kernel performs the LE connection + L2CAP channel setup.
            let fd = guard.0;
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
            await_security(fd, peer, security, Instant::now() + PAIRING_WAIT)?;

            std::mem::forget(guard); // success — ownership moves to L2capAtt
            Ok(L2capAtt { fd })
        }

        /// [`connect`](Self::connect) with a deadline on the connection
        /// attempt. The connect is issued in non-blocking mode and awaited
        /// with `poll`, so a peer that is absent or out of range fails with
        /// [`io::ErrorKind::TimedOut`] after `timeout` instead of holding the
        /// caller until the kernel gives up. A zero timeout fails unless the
        /// connect completes immediately. On success the socket returns to
        /// blocking mode, with receives paced by `recv_timeout_secs` exactly
        /// as in [`connect`](Self::connect).
        ///
        /// Above [`SecurityLevel::Low`], `timeout` also covers the pairing:
        /// it fails with [`io::ErrorKind::TimedOut`] if the link has not
        /// reached `security` by then. Allow more than the kernel's 30 s
        /// pairing timeout when a person has to approve the pairing.
        pub fn connect_timeout(
            local: Option<&str>,
            local_random: bool,
            peer: &str,
            peer_random: bool,
            security: SecurityLevel,
            recv_timeout_secs: i64,
            timeout: Duration,
        ) -> io::Result<Self> {
            let (guard, pa) = Self::prepare(
                local,
                local_random,
                peer,
                peer_random,
                security,
                recv_timeout_secs,
            )?;
            let fd = guard.0;
            let deadline = Instant::now() + timeout;

            // Non-blocking, so connect() returns at once with EINPROGRESS.
            let flags = unsafe { fcntl(fd, F_GETFL) };
            if flags < 0 {
                return Err(io::Error::last_os_error());
            }
            if unsafe { fcntl(fd, F_SETFL, flags | O_NONBLOCK) } < 0 {
                return Err(io::Error::last_os_error());
            }

            let rc = unsafe {
                connect(
                    fd,
                    &pa as *const SockaddrL2 as *const c_void,
                    std::mem::size_of::<SockaddrL2>() as u32,
                )
            };
            if rc < 0 {
                let e = unsafe { errno() };
                if e != EINPROGRESS {
                    return Err(io::Error::from_raw_os_error(e));
                }

                // Await writability (the connect's completion) within the
                // deadline, re-polling with the remaining time on EINTR.
                loop {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    let ms = remaining.as_millis().min(c_int::MAX as u128) as c_int;
                    let mut pfd = PollFd {
                        fd,
                        events: POLLOUT,
                        revents: 0,
                    };
                    let rc = unsafe { poll(&mut pfd, 1, ms) };
                    if rc > 0 {
                        break;
                    }
                    if rc == 0 {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            format!("connect to {peer} timed out"),
                        ));
                    }
                    let e = unsafe { errno() };
                    if e != EINTR {
                        return Err(io::Error::from_raw_os_error(e));
                    }
                }

                // The socket is writable; SO_ERROR holds the connect's result.
                if let Some(e) = socket_error(fd)? {
                    return Err(e);
                }
            }

            // Back to blocking; reads are paced by SO_RCVTIMEO as in connect().
            if unsafe { fcntl(fd, F_SETFL, flags) } < 0 {
                return Err(io::Error::last_os_error());
            }
            await_security(fd, peer, security, deadline)?;

            std::mem::forget(guard); // success — ownership moves to L2capAtt
            Ok(L2capAtt { fd })
        }

        /// The link's current security level. After a successful connect it
        /// is at least the level that was requested. Fails once the link is
        /// gone.
        pub fn security(&self) -> io::Result<SecurityLevel> {
            let raw = bt_security(self.fd)?;
            link_up(self.fd, 0)?;
            Ok(SecurityLevel::from_bt_security(raw))
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
    use std::time::Duration;

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

        /// Always [`io::ErrorKind::Unsupported`] on this platform.
        pub fn connect_timeout(
            _local: Option<&str>,
            _local_random: bool,
            _peer: &str,
            _peer_random: bool,
            _security: SecurityLevel,
            _recv_timeout_secs: i64,
            _timeout: Duration,
        ) -> io::Result<Self> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "L2CAP ATT sockets are only supported on Linux",
            ))
        }

        /// Unreachable: no value of this type can exist on this platform.
        pub fn security(&self) -> io::Result<SecurityLevel> {
            match self.0 {}
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

    #[test]
    fn security_levels_order_from_low_to_high() {
        assert!(SecurityLevel::Low < SecurityLevel::Medium);
        assert!(SecurityLevel::Medium < SecurityLevel::High);
    }

    #[test]
    fn raw_bt_security_values_map_to_levels() {
        // 0 is BT_SECURITY_SDP, below Low; 4 is BT_SECURITY_FIPS, above High.
        assert_eq!(SecurityLevel::from_bt_security(0), SecurityLevel::Low);
        assert_eq!(SecurityLevel::from_bt_security(1), SecurityLevel::Low);
        assert_eq!(SecurityLevel::from_bt_security(2), SecurityLevel::Medium);
        assert_eq!(SecurityLevel::from_bt_security(3), SecurityLevel::High);
        assert_eq!(SecurityLevel::from_bt_security(4), SecurityLevel::High);
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

        let err = L2capAtt::connect_timeout(
            None,
            false,
            "AA:BB:CC:DD:EE:FF",
            false,
            SecurityLevel::Low,
            1,
            std::time::Duration::from_secs(5),
        )
        .err()
        .expect("no L2CAP socket on this platform");
        assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
    }
}
