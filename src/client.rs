//! GATT client connection-management driver.
//!
//! Turns the pure ATT codec ([`crate::att`]) and GATT records ([`crate::gatt`])
//! into the operations a central performs over a connected ATT channel: MTU
//! exchange, service / characteristic / descriptor discovery, reads (including
//! long reads via Read Blob), writes, and notification/indication subscription.
//!
//! [`GattClient`] is generic over an [`AttIo`] transport, so this driver logic is
//! unit-tested against an in-memory mock while the real Linux L2CAP socket
//! ([`crate::l2cap`]) implements the same trait. The driver is pure; only the
//! transport does I/O.

use crate::att::{self, AttPdu};
use crate::gatt::{self, Characteristic, Descriptor, Service};
use std::fmt;
use std::io;

/// A framed ATT transport: one `send`/`recv` carries exactly one ATT PDU (an
/// L2CAP SDU on the ATT fixed channel is one PDU). `recv` blocks until a PDU
/// arrives or the transport's own timeout elapses (surfaced as
/// [`io::ErrorKind::WouldBlock`] / [`io::ErrorKind::TimedOut`]).
pub trait AttIo {
    fn send(&mut self, pdu: &[u8]) -> io::Result<()>;
    fn recv(&mut self) -> io::Result<Vec<u8>>;
}

/// A GATT-client operation error.
#[derive(Debug)]
pub enum GattError {
    /// Transport I/O error (including a receive timeout).
    Io(io::Error),
    /// The server answered our request with an ATT Error Response.
    Att {
        req_opcode: u8,
        handle: u16,
        error: u8,
    },
    /// A response that could not be decoded or was not the one expected.
    Protocol(String),
}

impl From<io::Error> for GattError {
    fn from(e: io::Error) -> Self {
        GattError::Io(e)
    }
}

impl fmt::Display for GattError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GattError::Io(e) => write!(f, "ATT transport error: {e}"),
            GattError::Att {
                req_opcode,
                handle,
                error,
            } => write!(
                f,
                "ATT error 0x{error:02x} for request 0x{req_opcode:02x} on handle 0x{handle:04x}"
            ),
            GattError::Protocol(m) => write!(f, "GATT protocol error: {m}"),
        }
    }
}

impl std::error::Error for GattError {}

/// The mandatory default ATT_MTU before any Exchange MTU (BT Core, Vol 3, Part F).
pub const DEFAULT_ATT_MTU: u16 = 23;

/// The maximum length of a GATT attribute value (BT Core, Vol 3, Part F,
/// §3.2.9). A Read Blob offset is a `u16`, so no value can be read past this
/// over ATT; [`read_long`](GattClient::read_long) caps its accumulator here so
/// a hostile peripheral that keeps answering with full chunks can't grow it
/// without bound.
pub const MAX_ATT_VALUE_LEN: usize = 512;

/// A characteristic together with its descriptors (the result of walking one
/// characteristic during a full discovery).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredCharacteristic {
    pub characteristic: Characteristic,
    pub descriptors: Vec<Descriptor>,
}

/// A service together with its characteristics and their descriptors — one
/// branch of the GATT tree produced by [`GattClient::discover_all`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredService {
    pub service: Service,
    pub characteristics: Vec<DiscoveredCharacteristic>,
}

/// Upper bound on notifications/indications queued while awaiting a single
/// request's response. A cooperative peer queues at most a handful before
/// answering; exceeding this means the peer is streaming instead of responding,
/// so the request fails closed rather than growing `pending` without bound.
const MAX_PENDING_VALUES: usize = 256;

/// A GATT client over one connected ATT channel.
pub struct GattClient<T: AttIo> {
    io: T,
    mtu: u16,
    /// Notifications/indications received while awaiting a request's response,
    /// in arrival order, for the caller to drain with [`take_notifications`].
    ///
    /// [`take_notifications`]: GattClient::take_notifications
    pending: Vec<(u16, Vec<u8>)>,
}

impl<T: AttIo> GattClient<T> {
    /// Wrap a connected transport. The MTU starts at the 23-byte default until
    /// [`exchange_mtu`](Self::exchange_mtu) negotiates a larger one.
    pub fn new(io: T) -> Self {
        Self {
            io,
            mtu: DEFAULT_ATT_MTU,
            pending: Vec::new(),
        }
    }

    /// The negotiated ATT MTU (23 until an Exchange MTU succeeds).
    pub fn mtu(&self) -> u16 {
        self.mtu
    }

    /// Send one request and return the server's answer to it, transparently
    /// queuing any notification/indication that arrives first (and confirming
    /// indications). The returned PDU is either the response for `want_opcode`
    /// or an `ErrorResponse` naming the request's opcode.
    fn request(&mut self, req: &[u8], want_opcode: u8) -> Result<AttPdu, GattError> {
        let req_opcode = *req
            .first()
            .ok_or_else(|| GattError::Protocol("empty request".into()))?;
        self.io.send(req)?;
        loop {
            let raw = self.io.recv()?;
            let opcode = *raw
                .first()
                .ok_or_else(|| GattError::Protocol("empty response PDU".into()))?;
            let pdu = att::parse(&raw)
                .ok_or_else(|| GattError::Protocol(format!("undecodable PDU 0x{opcode:02x}")))?;
            // A hostile peripheral could stream notifications/indications
            // forever instead of answering, pinning this loop and growing
            // `pending` without bound. Cap the queue so such a peer errors the
            // request out rather than exhausting memory / never returning.
            match pdu {
                AttPdu::HandleValueNotification { handle, value } => {
                    if self.pending.len() >= MAX_PENDING_VALUES {
                        return Err(GattError::Protocol(
                            "too many queued notifications while awaiting response".into(),
                        ));
                    }
                    self.pending.push((handle, value))
                }
                AttPdu::HandleValueIndication { handle, value } => {
                    if self.pending.len() >= MAX_PENDING_VALUES {
                        return Err(GattError::Protocol(
                            "too many queued indications while awaiting response".into(),
                        ));
                    }
                    self.pending.push((handle, value));
                    self.io.send(&att::handle_value_confirmation())?;
                }
                AttPdu::ErrorResponse { req_opcode: ro, .. } if ro == req_opcode => return Ok(pdu),
                _ if opcode == want_opcode => return Ok(pdu),
                _ => {
                    return Err(GattError::Protocol(format!(
                        "unexpected 0x{opcode:02x} while awaiting response to 0x{req_opcode:02x}"
                    )))
                }
            }
        }
    }

    /// Turn an `ErrorResponse` into a [`GattError::Att`].
    fn att_err(pdu: AttPdu, ctx: &str) -> GattError {
        match pdu {
            AttPdu::ErrorResponse {
                req_opcode,
                handle,
                error,
            } => GattError::Att {
                req_opcode,
                handle,
                error,
            },
            _ => GattError::Protocol(format!("unexpected response to {ctx}")),
        }
    }

    /// Negotiate the ATT MTU. On success the client's MTU becomes
    /// `min(client_rx_mtu, server_mtu)` (never below the 23-byte default); a
    /// server that rejects the request keeps the default.
    pub fn exchange_mtu(&mut self, client_rx_mtu: u16) -> Result<u16, GattError> {
        match self.request(
            &att::exchange_mtu_req(client_rx_mtu),
            att::OP_EXCHANGE_MTU_RSP,
        )? {
            AttPdu::ExchangeMtuResponse { mtu } => {
                self.mtu = client_rx_mtu.min(mtu).max(DEFAULT_ATT_MTU);
                Ok(self.mtu)
            }
            // A server that doesn't support MTU exchange stays at the default.
            AttPdu::ErrorResponse { .. } => Ok(self.mtu),
            other => Err(Self::att_err(other, "Exchange MTU")),
        }
    }

    /// Discover all primary services (Read By Group Type over 0x2800, walking the
    /// whole handle range until the server reports Attribute Not Found).
    pub fn discover_services(&mut self) -> Result<Vec<Service>, GattError> {
        let mut out = Vec::new();
        let mut start = 0x0001u16;
        loop {
            let req = att::read_by_group_type_req(start, 0xFFFF, gatt::PRIMARY_SERVICE_UUID)
                .ok_or_else(|| GattError::Protocol("bad Primary Service UUID".into()))?;
            match self.request(&req, att::OP_READ_BY_GROUP_TYPE_RSP)? {
                AttPdu::ReadByGroupTypeResponse { entries } => {
                    let batch = gatt::parse_services(&entries);
                    let last_end = batch.iter().map(|s| s.end_handle).max();
                    out.extend(batch);
                    match last_end {
                        // Require strict forward progress. The group handles are
                        // taken verbatim from the peer, so a hostile server that
                        // keeps returning a batch whose max end-handle is <=
                        // `start` would otherwise pin the loop forever (and grow
                        // `out` without bound). `end >= start` guarantees `start`
                        // strictly increases, so the walk always terminates.
                        Some(end) if end >= start && end < 0xFFFF => start = end + 1,
                        _ => break, // top of the range, empty batch, or no progress
                    }
                }
                AttPdu::ErrorResponse { error, .. } if error == att::ERR_ATTRIBUTE_NOT_FOUND => {
                    break
                }
                other => return Err(Self::att_err(other, "service discovery")),
            }
        }
        Ok(out)
    }

    /// Discover the characteristics within a service (Read By Type over 0x2803).
    pub fn discover_characteristics(
        &mut self,
        service: &Service,
    ) -> Result<Vec<Characteristic>, GattError> {
        let mut out = Vec::new();
        let mut start = service.start_handle;
        loop {
            if start > service.end_handle {
                break;
            }
            let req = att::read_by_type_req(start, service.end_handle, gatt::CHARACTERISTIC_UUID)
                .ok_or_else(|| GattError::Protocol("bad Characteristic UUID".into()))?;
            match self.request(&req, att::OP_READ_BY_TYPE_RSP)? {
                AttPdu::ReadByTypeResponse { entries } => {
                    let batch = gatt::parse_characteristics(&entries);
                    let last = batch.iter().map(|c| c.decl_handle).max();
                    out.extend(batch);
                    match last {
                        // Forward-progress guard (see `discover_services`): a peer
                        // that never advances the max declaration handle can't
                        // pin this loop.
                        Some(h) if h >= start && h < service.end_handle => start = h + 1,
                        _ => break,
                    }
                }
                AttPdu::ErrorResponse { error, .. } if error == att::ERR_ATTRIBUTE_NOT_FOUND => {
                    break
                }
                other => return Err(Self::att_err(other, "characteristic discovery")),
            }
        }
        Ok(out)
    }

    /// Discover the descriptors in a handle range (Find Information). The range
    /// is a characteristic's value handle + 1 up to the handle before the next
    /// characteristic declaration (or the service's end handle).
    pub fn discover_descriptors(
        &mut self,
        start: u16,
        end: u16,
    ) -> Result<Vec<Descriptor>, GattError> {
        let mut out = Vec::new();
        let mut cur = start;
        loop {
            if cur > end {
                break;
            }
            match self.request(
                &att::find_information_req(cur, end),
                att::OP_FIND_INFORMATION_RSP,
            )? {
                AttPdu::FindInformationResponse { entries } => {
                    let last = entries.iter().map(|(h, _)| *h).max();
                    out.extend(gatt::parse_descriptors(&entries));
                    match last {
                        // Forward-progress guard (see `discover_services`).
                        Some(h) if h >= cur && h < end => cur = h + 1,
                        _ => break,
                    }
                }
                AttPdu::ErrorResponse { error, .. } if error == att::ERR_ATTRIBUTE_NOT_FOUND => {
                    break
                }
                other => return Err(Self::att_err(other, "descriptor discovery")),
            }
        }
        Ok(out)
    }

    /// Read an attribute value by handle (single Read Request — the value is
    /// truncated to MTU-1 if longer; use [`read_long`](Self::read_long) for the
    /// full value).
    pub fn read(&mut self, handle: u16) -> Result<Vec<u8>, GattError> {
        match self.request(&att::read_req(handle), att::OP_READ_RSP)? {
            AttPdu::ReadResponse { value } => Ok(value),
            other => Err(Self::att_err(other, "read")),
        }
    }

    /// Read a possibly-long value: a Read Request followed by Read Blob Requests
    /// until a short chunk (or Invalid Offset) signals the end.
    pub fn read_long(&mut self, handle: u16) -> Result<Vec<u8>, GattError> {
        let mut value = self.read(handle)?;
        let chunk_max = self.mtu as usize - 1;
        // The initial Read Response is the whole value unless it filled the MTU;
        // only a full chunk implies more may follow via Read Blob.
        let mut maybe_more = value.len() == chunk_max;
        while maybe_more {
            // Bound the accumulator so a peripheral that answers every Read Blob
            // with a full chunk can't drive an `--interact` session into an
            // endless loop / OOM. `MAX_ATT_VALUE_LEN` is the ATT ceiling, so this
            // never truncates a spec-conformant value (whose final chunk is short
            // and ends the walk first); it also keeps `value.len()` well within
            // the u16 Read Blob offset space, so `offset` below never wraps.
            if value.len() >= MAX_ATT_VALUE_LEN {
                break;
            }
            let offset = value.len() as u16;
            match self.request(&att::read_blob_req(handle, offset), att::OP_READ_BLOB_RSP)? {
                AttPdu::ReadBlobResponse { value: chunk } => {
                    // A short (or empty) chunk means the whole value has arrived.
                    maybe_more = chunk.len() == chunk_max;
                    value.extend_from_slice(&chunk);
                }
                // Reading past the end returns Invalid Offset — a normal terminator.
                AttPdu::ErrorResponse { error, .. } if error == att::ERR_INVALID_OFFSET => break,
                other => return Err(Self::att_err(other, "read blob")),
            }
        }
        Ok(value)
    }

    /// Write a value with a Write Request (acknowledged).
    pub fn write(&mut self, handle: u16, value: &[u8]) -> Result<(), GattError> {
        match self.request(&att::write_req(handle, value), att::OP_WRITE_RSP)? {
            AttPdu::WriteResponse => Ok(()),
            other => Err(Self::att_err(other, "write")),
        }
    }

    /// Write a value with a Write Command (unacknowledged). Success means the
    /// PDU was handed to the transport, not that the server applied it. The
    /// value must fit in one PDU (the MTU minus the 3-byte header): the server
    /// silently drops an oversized Write Command, so it is rejected here where
    /// the caller can see the failure.
    pub fn write_without_response(&mut self, handle: u16, value: &[u8]) -> Result<(), GattError> {
        let max = self.mtu as usize - 3;
        if value.len() > max {
            return Err(GattError::Protocol(format!(
                "Write Command value is {} bytes but the MTU allows {max}",
                value.len()
            )));
        }
        self.io.send(&att::write_cmd(handle, value))?;
        Ok(())
    }

    /// Subscribe (or, with both `false`, unsubscribe) by writing the CCCD.
    pub fn subscribe(
        &mut self,
        cccd_handle: u16,
        notify: bool,
        indicate: bool,
    ) -> Result<(), GattError> {
        self.write(cccd_handle, &gatt::cccd_value(notify, indicate))
    }

    /// Drain notifications/indications collected while awaiting request responses.
    pub fn take_notifications(&mut self) -> Vec<(u16, Vec<u8>)> {
        std::mem::take(&mut self.pending)
    }

    /// Block for the next server-initiated event (for a notify stream). Returns
    /// any queued notification first, then reads one PDU: `Some((handle, value))`
    /// for a notification/indication (confirming indications), `None` for a
    /// receive timeout or a non-event PDU (so the caller can loop and re-check a
    /// shutdown flag).
    pub fn next_event(&mut self) -> Result<Option<(u16, Vec<u8>)>, GattError> {
        if !self.pending.is_empty() {
            return Ok(Some(self.pending.remove(0)));
        }
        let raw = match self.io.recv() {
            Ok(raw) => raw,
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                return Ok(None);
            }
            Err(e) => return Err(GattError::Io(e)),
        };
        match att::parse(&raw) {
            Some(AttPdu::HandleValueNotification { handle, value }) => Ok(Some((handle, value))),
            Some(AttPdu::HandleValueIndication { handle, value }) => {
                self.io.send(&att::handle_value_confirmation())?;
                Ok(Some((handle, value)))
            }
            _ => Ok(None),
        }
    }

    /// Walk the entire GATT tree: every primary service, its characteristics,
    /// and each characteristic's descriptors — the full characterization an
    /// `--interact` session performs. A characteristic's descriptor range runs
    /// from its value handle + 1 up to the handle before the next
    /// characteristic's declaration (or the service's end handle for the last
    /// characteristic); an empty range issues no Find Information request.
    pub fn discover_all(&mut self) -> Result<Vec<DiscoveredService>, GattError> {
        let services = self.discover_services()?;
        let mut out = Vec::with_capacity(services.len());
        for service in services {
            let chars = self.discover_characteristics(&service)?;
            let mut discovered = Vec::with_capacity(chars.len());
            for (i, ch) in chars.iter().enumerate() {
                let desc_start = ch.value_handle.saturating_add(1);
                let desc_end = chars
                    .get(i + 1)
                    .map(|next| next.decl_handle.saturating_sub(1))
                    .unwrap_or(service.end_handle);
                let descriptors = if desc_start <= desc_end {
                    self.discover_descriptors(desc_start, desc_end)?
                } else {
                    Vec::new()
                };
                discovered.push(DiscoveredCharacteristic {
                    characteristic: ch.clone(),
                    descriptors,
                });
            }
            out.push(DiscoveredService {
                service,
                characteristics: discovered,
            });
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    /// An in-memory ATT transport: records sent PDUs, replays a queue of
    /// responses. An exhausted queue surfaces as a timeout (so `next_event`
    /// treats it as "no more events").
    struct MockIo {
        sent: Vec<Vec<u8>>,
        responses: VecDeque<Vec<u8>>,
    }

    impl MockIo {
        fn new(responses: Vec<Vec<u8>>) -> Self {
            Self {
                sent: Vec::new(),
                responses: responses.into(),
            }
        }
    }

    impl AttIo for MockIo {
        fn send(&mut self, pdu: &[u8]) -> io::Result<()> {
            self.sent.push(pdu.to_vec());
            Ok(())
        }
        fn recv(&mut self) -> io::Result<Vec<u8>> {
            self.responses
                .pop_front()
                .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "no more responses"))
        }
    }

    #[test]
    fn discovers_services_until_attribute_not_found() {
        // One group-type response with two services, then Attribute Not Found.
        let group = vec![
            0x11, 0x06, 0x01, 0x00, 0x05, 0x00, 0x00, 0x18, 0x06, 0x00, 0x09, 0x00, 0x01, 0x18,
        ];
        let not_found = vec![
            0x01,
            att::OP_READ_BY_GROUP_TYPE_REQ,
            0x0A,
            0x00,
            att::ERR_ATTRIBUTE_NOT_FOUND,
        ];
        let mut client = GattClient::new(MockIo::new(vec![group, not_found]));
        let services = client.discover_services().unwrap();
        assert_eq!(services.len(), 2);
        assert_eq!(services[0].start_handle, 0x0001);
        assert_eq!(services[1].uuid, "00001801-0000-1000-8000-00805f9b34fb");
        // The second request continued from end_handle(0x0009) + 1 = 0x000A.
        assert_eq!(client.io.sent.len(), 2);
        assert_eq!(&client.io.sent[1][1..3], &[0x0A, 0x00]);
    }

    #[test]
    fn discovers_characteristics_within_a_service() {
        // Read By Type response: one characteristic (decl 0x0002), then not found.
        let chars = vec![0x09, 0x07, 0x02, 0x00, 0x12, 0x03, 0x00, 0x00, 0x2a];
        let not_found = vec![
            0x01,
            att::OP_READ_BY_TYPE_REQ,
            0x03,
            0x00,
            att::ERR_ATTRIBUTE_NOT_FOUND,
        ];
        let mut client = GattClient::new(MockIo::new(vec![chars, not_found]));
        let svc = Service {
            start_handle: 0x0001,
            end_handle: 0x000F,
            uuid: "00001800-0000-1000-8000-00805f9b34fb".into(),
        };
        let found = client.discover_characteristics(&svc).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].value_handle, 0x0003);
        assert!(found[0].can_notify());
    }

    #[test]
    fn read_returns_value_and_surfaces_att_error() {
        let read_rsp = vec![0x0B, 0xDE, 0xAD, 0xBE, 0xEF];
        let mut client = GattClient::new(MockIo::new(vec![read_rsp]));
        assert_eq!(client.read(0x0003).unwrap(), vec![0xDE, 0xAD, 0xBE, 0xEF]);

        // Read Not Permitted -> GattError::Att.
        let err = vec![
            0x01,
            att::OP_READ_REQ,
            0x03,
            0x00,
            att::ERR_READ_NOT_PERMITTED,
        ];
        let mut client = GattClient::new(MockIo::new(vec![err]));
        match client.read(0x0003) {
            Err(GattError::Att { error, .. }) => assert_eq!(error, att::ERR_READ_NOT_PERMITTED),
            other => panic!("expected Att error, got {other:?}"),
        }
    }

    #[test]
    fn read_long_chains_blobs_until_short_chunk() {
        // Force MTU 5 so chunk_max is 4: the 4-byte first read looks "full" and a
        // Read Blob is issued; the 2-byte blob is short, ending the chain at 6.
        let mut client =
            GattClient::new(MockIo::new(vec![vec![0x0B, 1, 2, 3, 4], vec![0x0D, 5, 6]]));
        client.mtu = 5;
        assert_eq!(client.read_long(0x0003).unwrap(), vec![1, 2, 3, 4, 5, 6]);
    }

    #[test]
    fn read_long_reads_every_full_blob() {
        // MTU 5 (chunk_max 4): a full first read, a full blob, then a short blob.
        // The chain must gather all three chunks — a regression guard against
        // stopping after a single blob and truncating the value.
        let mut client = GattClient::new(MockIo::new(vec![
            vec![0x0B, 1, 2, 3, 4],
            vec![0x0D, 5, 6, 7, 8],
            vec![0x0D, 9, 10],
        ]));
        client.mtu = 5;
        assert_eq!(
            client.read_long(0x0003).unwrap(),
            vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
        );
    }

    #[test]
    fn read_long_stops_at_max_att_value_len() {
        // A hostile server that answers every Read Blob with a full chunk would
        // grow the accumulator forever; the MAX_ATT_VALUE_LEN cap must halt it.
        // With chunk_max 299, one full read + one full blob reaches 598 >= 512, so
        // read_long returns without issuing a third request (had it not capped, it
        // would recv on the empty queue and error). Only two PDUs are sent.
        let mut read_rsp = vec![0x0Bu8];
        read_rsp.extend(std::iter::repeat_n(0xABu8, 299));
        let mut blob_rsp = vec![0x0Du8];
        blob_rsp.extend(std::iter::repeat_n(0xCDu8, 299));
        let mut client = GattClient::new(MockIo::new(vec![read_rsp, blob_rsp]));
        client.mtu = 300;
        let value = client.read_long(0x0003).unwrap();
        assert_eq!(value.len(), 598);
        assert!(value.len() <= MAX_ATT_VALUE_LEN + 299);
        assert_eq!(client.io.sent.len(), 2);
    }

    #[test]
    fn discover_services_terminates_when_peer_stops_advancing() {
        // First batch advances start (end handle 0x0002 -> next start 0x0003); the
        // second batch's max end handle (0x0001) is below that start, so no forward
        // progress is possible and the walk must break. Without the guard the loop
        // would re-request from a pinned/rewound start and time out on the empty
        // queue (an error), so a clean Ok proves termination.
        let a = vec![0x11, 0x06, 0x01, 0x00, 0x02, 0x00, 0x00, 0x18];
        let b = vec![0x11, 0x06, 0x01, 0x00, 0x01, 0x00, 0x00, 0x18];
        let mut client = GattClient::new(MockIo::new(vec![a, b]));
        let services = client.discover_services().unwrap();
        assert_eq!(services.len(), 2);
        assert_eq!(client.io.sent.len(), 2);
    }

    #[test]
    fn discover_characteristics_terminates_when_peer_stops_advancing() {
        // Both batches report the same declaration handle (0x0002); after the
        // first advances start to 0x0003 the second makes no progress, so the
        // guard must break instead of re-requesting from a pinned start.
        let entry = vec![0x09, 0x07, 0x02, 0x00, 0x12, 0x03, 0x00, 0x00, 0x2a];
        let mut client = GattClient::new(MockIo::new(vec![entry.clone(), entry]));
        let svc = Service {
            start_handle: 0x0001,
            end_handle: 0x000F,
            uuid: "00001800-0000-1000-8000-00805f9b34fb".into(),
        };
        let chars = client.discover_characteristics(&svc).unwrap();
        assert_eq!(chars.len(), 2);
        assert_eq!(client.io.sent.len(), 2);
    }

    #[test]
    fn discover_descriptors_terminates_when_peer_stops_advancing() {
        // Both Find Information batches report the same handle (0x0004); the guard
        // must break once the peer stops advancing rather than loop.
        let entry = vec![0x05, 0x01, 0x04, 0x00, 0x02, 0x29];
        let mut client = GattClient::new(MockIo::new(vec![entry.clone(), entry]));
        let descs = client.discover_descriptors(0x0004, 0x000F).unwrap();
        assert_eq!(descs.len(), 2);
        assert_eq!(client.io.sent.len(), 2);
    }

    #[test]
    fn exchange_mtu_takes_the_min_and_clamps_to_default() {
        // Server offers 5 -> clamped up to the 23-byte default floor.
        let mut client = GattClient::new(MockIo::new(vec![vec![0x03, 0x05, 0x00]]));
        assert_eq!(client.exchange_mtu(0x0064).unwrap(), DEFAULT_ATT_MTU);
        // Server offers 100, we asked for 64 -> min is 64.
        let mut client = GattClient::new(MockIo::new(vec![vec![0x03, 0x64, 0x00]]));
        assert_eq!(client.exchange_mtu(0x0040).unwrap(), 64);
    }

    #[test]
    fn write_without_response_sends_a_write_command() {
        // No response is expected, so the empty response queue is never read.
        let mut client = GattClient::new(MockIo::new(vec![]));
        client
            .write_without_response(0x0004, &[0x01, 0x00])
            .unwrap();
        assert_eq!(client.io.sent, vec![vec![0x52, 0x04, 0x00, 0x01, 0x00]]);
    }

    #[test]
    fn write_without_response_rejects_a_value_over_the_mtu() {
        // The default MTU of 23 caps the value at 20 bytes. 21 bytes must fail
        // client-side with nothing sent; exactly 20 must go through.
        let mut client = GattClient::new(MockIo::new(vec![]));
        let err = client
            .write_without_response(0x0004, &[0u8; 21])
            .unwrap_err();
        assert!(matches!(err, GattError::Protocol(_)));
        assert!(client.io.sent.is_empty());
        client.write_without_response(0x0004, &[0u8; 20]).unwrap();
        assert_eq!(client.io.sent.len(), 1);
    }

    #[test]
    fn subscribe_writes_the_cccd_notify_bit() {
        let mut client = GattClient::new(MockIo::new(vec![vec![0x13]])); // Write Response
        client.subscribe(0x0004, true, false).unwrap();
        // Write Request to handle 0x0004 with value 0x0001.
        assert_eq!(client.io.sent[0], vec![0x12, 0x04, 0x00, 0x01, 0x00]);
    }

    #[test]
    fn notification_during_request_is_queued_then_drained() {
        // A notification arrives before the Read Response; the read still
        // succeeds and the notification is available afterwards.
        let ntf = vec![0x1B, 0x03, 0x00, 0xAA];
        let read_rsp = vec![0x0B, 0xBB];
        let mut client = GattClient::new(MockIo::new(vec![ntf, read_rsp]));
        assert_eq!(client.read(0x0005).unwrap(), vec![0xBB]);
        assert_eq!(client.take_notifications(), vec![(0x0003, vec![0xAA])]);
    }

    #[test]
    fn indication_is_confirmed() {
        // An indication arrives before a Write Response; the client must send a
        // Handle Value Confirmation (0x1E).
        let ind = vec![0x1D, 0x03, 0x00, 0xCC];
        let write_rsp = vec![0x13];
        let mut client = GattClient::new(MockIo::new(vec![ind, write_rsp]));
        client.write(0x0004, &[0x01, 0x00]).unwrap();
        // sent[0] = write req, sent[1] = confirmation.
        assert!(client.io.sent.contains(&vec![att::OP_HANDLE_VALUE_CFM]));
        assert_eq!(client.take_notifications(), vec![(0x0003, vec![0xCC])]);
    }

    #[test]
    fn next_event_returns_none_on_timeout() {
        // Empty queue -> recv times out -> next_event yields None (not an error).
        let mut client = GattClient::new(MockIo::new(vec![]));
        assert_eq!(client.next_event().unwrap(), None);
    }

    #[test]
    fn discover_all_walks_service_characteristic_descriptor_tree() {
        // One service 0x0001..0x0009 (uuid 0x1800), one characteristic (decl
        // 0x0002, value 0x0003, uuid 0x2a00), one descriptor (CCCD @ 0x0004).
        // Each discovery sweep ends with an Attribute Not Found error response.
        let na = att::ERR_ATTRIBUTE_NOT_FOUND;
        let responses = vec![
            // discover_services: one service, then not found.
            vec![0x11, 0x06, 0x01, 0x00, 0x09, 0x00, 0x00, 0x18],
            vec![0x01, att::OP_READ_BY_GROUP_TYPE_REQ, 0x0A, 0x00, na],
            // discover_characteristics(0x0001..0x0009): one char, then not found.
            vec![0x09, 0x07, 0x02, 0x00, 0x12, 0x03, 0x00, 0x00, 0x2a],
            vec![0x01, att::OP_READ_BY_TYPE_REQ, 0x03, 0x00, na],
            // discover_descriptors(0x0004..0x0009): CCCD, then not found.
            vec![0x05, 0x01, 0x04, 0x00, 0x02, 0x29],
            vec![0x01, att::OP_FIND_INFORMATION_REQ, 0x05, 0x00, na],
        ];
        let mut client = GattClient::new(MockIo::new(responses));
        let tree = client.discover_all().unwrap();

        assert_eq!(tree.len(), 1);
        let svc = &tree[0];
        assert_eq!(svc.service.uuid, "00001800-0000-1000-8000-00805f9b34fb");
        assert_eq!(svc.characteristics.len(), 1);
        let ch = &svc.characteristics[0];
        assert_eq!(ch.characteristic.value_handle, 0x0003);
        assert_eq!(
            ch.characteristic.uuid,
            "00002a00-0000-1000-8000-00805f9b34fb"
        );
        assert!(ch.characteristic.can_notify());
        assert_eq!(ch.descriptors.len(), 1);
        assert_eq!(ch.descriptors[0].handle, 0x0004);
        assert_eq!(ch.descriptors[0].uuid, gatt::CCCD_UUID);
    }

    #[test]
    fn discover_all_skips_find_information_when_no_descriptor_range() {
        // A characteristic whose value handle is the service's end handle has no
        // room for descriptors, so discover_all issues no Find Information — the
        // response queue therefore needs only the service + characteristic sweeps.
        let na = att::ERR_ATTRIBUTE_NOT_FOUND;
        let responses = vec![
            vec![0x11, 0x06, 0x01, 0x00, 0x03, 0x00, 0x00, 0x18], // service 0x0001..0x0003
            vec![0x01, att::OP_READ_BY_GROUP_TYPE_REQ, 0x04, 0x00, na],
            // char decl 0x0002, value handle 0x0003 == service end -> no descriptors.
            vec![0x09, 0x07, 0x02, 0x00, 0x02, 0x03, 0x00, 0x00, 0x2a],
            vec![0x01, att::OP_READ_BY_TYPE_REQ, 0x03, 0x00, na],
        ];
        let mut client = GattClient::new(MockIo::new(responses));
        let tree = client.discover_all().unwrap();
        assert_eq!(tree[0].characteristics[0].descriptors, vec![]);
        // Exactly four requests were sent — no Find Information among them.
        assert_eq!(client.io.sent.len(), 4);
        assert!(client
            .io
            .sent
            .iter()
            .all(|req| req[0] != att::OP_FIND_INFORMATION_REQ));
    }
}
