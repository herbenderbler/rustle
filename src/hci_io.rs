//! The HCI command exchange, independent of the socket that carries it.
//!
//! [`HciIo`] is the crate's view of a raw HCI transport: write one packet, read
//! one packet. The Linux socket layers implement it on a file descriptor and
//! the tests implement it on an in-memory queue, so the bounded command and
//! response exchange here, and the drivers built on it ([`crate::scan`]'s scan
//! driver and [`crate::conn`]'s RSSI query), run on every OS without a
//! controller.

// Off Linux nothing opens a socket to drive this with, but the module is
// still compiled and its tests still run there.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use crate::hci::{build_command, command_outcome};
use std::io;

/// A raw HCI transport: one write or read moves exactly one HCI packet.
pub(crate) trait HciIo {
    /// Write one packet in full. A short write is an error like any other.
    fn write_packet(&mut self, pkt: &[u8]) -> io::Result<()>;

    /// Read one packet into `buf` and return its length, which is never zero.
    /// [`io::ErrorKind::WouldBlock`] and [`io::ErrorKind::Interrupted`] mean
    /// nothing arrived within the transport's receive timeout, and the caller
    /// may read again.
    fn read_packet(&mut self, buf: &mut [u8]) -> io::Result<usize>;
}

/// Lets a test lend its transport to a driver and inspect it afterwards.
#[cfg(test)]
impl<T: HciIo + ?Sized> HciIo for &mut T {
    fn write_packet(&mut self, pkt: &[u8]) -> io::Result<()> {
        (**self).write_packet(pkt)
    }

    fn read_packet(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        (**self).read_packet(buf)
    }
}

/// Why a command exchange failed. Each driver maps this into its own public
/// error type, adding the context it has, such as the opcode.
#[derive(Debug)]
pub(crate) enum CommandError {
    /// The command could not be written. The [`io::Error`] carries the
    /// kernel's reason; a partial write is [`io::ErrorKind::WriteZero`].
    Write(io::Error),
    /// The controller answered with this non-zero status.
    Rejected(u8),
    /// A read error while awaiting the response.
    Io(io::Error),
    /// No response arrived within the bounded wait.
    NoResponse,
}

/// Reads attempted while awaiting a response. Each is bounded by the
/// transport's receive timeout, so a controller that never answers cannot
/// hang the caller, while a burst of queued advertising reports still has
/// room to drain ahead of the completion event.
pub(crate) const MAX_WAIT: u32 = 8;

/// A 512-byte buffer holds any HCI event.
const EVENT_BUF_LEN: usize = 512;

/// Frame and write one command without waiting for its completion event.
pub(crate) fn send_command<T: HciIo>(
    io: &mut T,
    opcode: u16,
    params: &[u8],
) -> Result<(), CommandError> {
    io.write_packet(&build_command(opcode, params))
        .map_err(CommandError::Write)
}

/// Read packets until `settle` says one of them answers the outstanding
/// command, skipping everything else, advertising reports included. `settle`
/// returns `None` to keep waiting, `Some(Ok(value))` for an accepted command
/// and `Some(Err(status))` for a rejected one. The wait is bounded by
/// [`MAX_WAIT`] reads; timeouts and interrupted reads count towards it.
pub(crate) fn await_response<T: HciIo, R>(
    io: &mut T,
    mut settle: impl FnMut(&[u8]) -> Option<Result<R, u8>>,
) -> Result<R, CommandError> {
    let mut buf = [0u8; EVENT_BUF_LEN];
    for _ in 0..MAX_WAIT {
        match io.read_packet(&mut buf) {
            Ok(n) => {
                if let Some(outcome) = settle(&buf[..n]) {
                    return outcome.map_err(CommandError::Rejected);
                }
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) => {} // Nothing yet: read again.
            Err(e) => return Err(CommandError::Io(e)),
        }
    }
    Err(CommandError::NoResponse)
}

/// Send one command and wait for the controller to accept it: its Command
/// Complete or Command Status with status `0x00`.
pub(crate) fn command<T: HciIo>(
    io: &mut T,
    opcode: u16,
    params: &[u8],
) -> Result<(), CommandError> {
    send_command(io, opcode, params)?;
    await_response(io, |pkt| command_outcome(opcode, pkt))
}

/// An in-memory transport for the drivers' tests.
#[cfg(test)]
pub(crate) mod mock {
    use super::HciIo;
    use std::collections::VecDeque;
    use std::io;

    /// Records every packet written and replays a queue of read results. An
    /// exhausted queue reads as `WouldBlock`, which is what an elapsed
    /// `SO_RCVTIMEO` looks like to a driver.
    pub(crate) struct MockHci {
        pub(crate) written: Vec<Vec<u8>>,
        pub(crate) incoming: VecDeque<io::Result<Vec<u8>>>,
        /// Reads attempted so far, timeouts included.
        pub(crate) reads: usize,
        /// Fail every write, to exercise the write error paths.
        pub(crate) fail_writes: bool,
    }

    impl MockHci {
        pub(crate) fn new(incoming: Vec<io::Result<Vec<u8>>>) -> Self {
            MockHci {
                written: Vec::new(),
                incoming: incoming.into(),
                reads: 0,
                fail_writes: false,
            }
        }

        /// A transport that replays `packets` in order and then times out.
        pub(crate) fn replaying(packets: Vec<Vec<u8>>) -> Self {
            Self::new(packets.into_iter().map(Ok).collect())
        }

        /// A Command Complete event for `opcode` carrying `status`.
        pub(crate) fn command_complete(opcode: u16, status: u8) -> Vec<u8> {
            let op = opcode.to_le_bytes();
            vec![0x04, 0x0E, 0x04, 0x01, op[0], op[1], status]
        }

        /// A Command Status event for `opcode` carrying `status`.
        pub(crate) fn command_status(opcode: u16, status: u8) -> Vec<u8> {
            let op = opcode.to_le_bytes();
            vec![0x04, 0x0F, 0x04, status, 0x01, op[0], op[1]]
        }

        /// The opcode of every command written so far, in order.
        pub(crate) fn written_opcodes(&self) -> Vec<u16> {
            self.written
                .iter()
                .map(|pkt| u16::from_le_bytes([pkt[1], pkt[2]]))
                .collect()
        }
    }

    impl HciIo for MockHci {
        fn write_packet(&mut self, pkt: &[u8]) -> io::Result<()> {
            if self.fail_writes {
                return Err(io::Error::from(io::ErrorKind::PermissionDenied));
            }
            self.written.push(pkt.to_vec());
            Ok(())
        }

        fn read_packet(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.reads += 1;
            match self.incoming.pop_front() {
                Some(Ok(pkt)) => {
                    buf[..pkt.len()].copy_from_slice(&pkt);
                    Ok(pkt.len())
                }
                Some(Err(e)) => Err(e),
                None => Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "mock receive timeout",
                )),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::mock::MockHci;
    use super::*;

    const OPCODE: u16 = 0x200C;

    #[test]
    fn command_frames_the_packet_and_accepts_a_zero_status() {
        let mut io = MockHci::replaying(vec![MockHci::command_complete(OPCODE, 0x00)]);
        command(&mut io, OPCODE, &[0x01, 0x00]).unwrap();
        assert_eq!(io.written, vec![build_command(OPCODE, &[0x01, 0x00])]);
        assert_eq!(io.reads, 1);
    }

    #[test]
    fn command_reports_the_rejecting_status() {
        // Command Status is how a controller reports an unknown command.
        let mut io = MockHci::replaying(vec![MockHci::command_status(OPCODE, 0x01)]);
        assert!(matches!(
            command(&mut io, OPCODE, &[]),
            Err(CommandError::Rejected(0x01))
        ));
        // A Command Complete can carry a rejection too.
        let mut io = MockHci::replaying(vec![MockHci::command_complete(OPCODE, 0x0C)]);
        assert!(matches!(
            command(&mut io, OPCODE, &[]),
            Err(CommandError::Rejected(0x0C))
        ));
    }

    #[test]
    fn command_skips_packets_that_do_not_answer_it() {
        // An advertising report, another command's completion, a timeout and
        // an interrupted read all go by before the answer.
        let mut io = MockHci::new(vec![
            Ok(vec![0x04, 0x3E, 0x02, 0x02, 0x00]),
            Ok(MockHci::command_complete(0x200B, 0x00)),
            Err(io::Error::new(io::ErrorKind::WouldBlock, "timeout")),
            Err(io::Error::new(io::ErrorKind::Interrupted, "signal")),
            Ok(MockHci::command_complete(OPCODE, 0x00)),
        ]);
        command(&mut io, OPCODE, &[]).unwrap();
        assert_eq!(io.reads, 5);
    }

    #[test]
    fn await_response_gives_up_after_the_bounded_number_of_reads() {
        // Nothing ever arrives: every read times out, and the wait ends after
        // exactly MAX_WAIT of them rather than hanging.
        let mut io = MockHci::replaying(Vec::new());
        assert!(matches!(
            command(&mut io, OPCODE, &[]),
            Err(CommandError::NoResponse)
        ));
        assert_eq!(io.reads, MAX_WAIT as usize);
    }

    #[test]
    fn await_response_surfaces_other_read_errors() {
        let mut io = MockHci::new(vec![Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "controller closed the HCI socket",
        ))]);
        match command(&mut io, OPCODE, &[]) {
            Err(CommandError::Io(e)) => assert_eq!(e.kind(), io::ErrorKind::UnexpectedEof),
            other => panic!("expected Io, got {other:?}"),
        }
    }

    #[test]
    fn send_command_keeps_the_write_error() {
        let mut io = MockHci::replaying(Vec::new());
        io.fail_writes = true;
        match command(&mut io, OPCODE, &[]) {
            Err(CommandError::Write(e)) => assert_eq!(e.kind(), io::ErrorKind::PermissionDenied),
            other => panic!("expected Write, got {other:?}"),
        }
        // Nothing was read: a failed write never waits for an answer.
        assert_eq!(io.reads, 0);
    }

    #[test]
    fn a_mutable_reference_is_a_transport_too() {
        // Drivers own their transport; the tests lend one so they can inspect
        // it after the driver is dropped.
        let mut io = MockHci::replaying(vec![MockHci::command_complete(OPCODE, 0x00)]);
        {
            let mut lent = &mut io;
            command(&mut lent, OPCODE, &[]).unwrap();
        }
        assert_eq!(io.written.len(), 1);
    }
}
