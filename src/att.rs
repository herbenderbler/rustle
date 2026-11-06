//! Pure ATT (Attribute Protocol) PDU codec.
//!
//! Encoders for the requests/commands a GATT **client** sends, and a decoder
//! for the responses/notifications it receives, over the ATT fixed channel
//! (L2CAP CID 0x0004). Platform-independent and dependency-free; the L2CAP
//! socket that carries these bytes is [`crate::l2cap`], and the GATT record
//! layer that interprets the response payloads is in [`crate::gatt`].
//!
//! Decoding never panics on attacker-shaped bytes: a truncated or malformed PDU
//! yields `None` (or, for list responses, the entries decoded before the bad
//! one).

use crate::hci::{format_uuid128, format_uuid16};

// ---------------------------------------------------------------------------
// ATT opcodes (Bluetooth Core, Vol 3, Part F, §3.4).
// ---------------------------------------------------------------------------

/// Error Response.
pub const OP_ERROR_RSP: u8 = 0x01;
/// Exchange MTU Request / Response.
pub const OP_EXCHANGE_MTU_REQ: u8 = 0x02;
pub const OP_EXCHANGE_MTU_RSP: u8 = 0x03;
/// Find Information Request / Response (descriptor discovery).
pub const OP_FIND_INFORMATION_REQ: u8 = 0x04;
pub const OP_FIND_INFORMATION_RSP: u8 = 0x05;
/// Read By Type Request / Response (characteristic discovery).
pub const OP_READ_BY_TYPE_REQ: u8 = 0x08;
pub const OP_READ_BY_TYPE_RSP: u8 = 0x09;
/// Read Request / Response.
pub const OP_READ_REQ: u8 = 0x0A;
pub const OP_READ_RSP: u8 = 0x0B;
/// Read Blob Request / Response.
pub const OP_READ_BLOB_REQ: u8 = 0x0C;
pub const OP_READ_BLOB_RSP: u8 = 0x0D;
/// Read By Group Type Request / Response (primary-service discovery).
pub const OP_READ_BY_GROUP_TYPE_REQ: u8 = 0x10;
pub const OP_READ_BY_GROUP_TYPE_RSP: u8 = 0x11;
/// Write Request / Response.
pub const OP_WRITE_REQ: u8 = 0x12;
pub const OP_WRITE_RSP: u8 = 0x13;
/// Handle Value Notification / Indication, and the client's Confirmation.
pub const OP_HANDLE_VALUE_NTF: u8 = 0x1B;
pub const OP_HANDLE_VALUE_IND: u8 = 0x1D;
pub const OP_HANDLE_VALUE_CFM: u8 = 0x1E;
/// Write Command (unacknowledged; the command bit 0x40 set on Write Request).
pub const OP_WRITE_CMD: u8 = 0x52;

// ---------------------------------------------------------------------------
// ATT error codes carried in an Error Response (Vol 3, Part F, §3.4.1.1). Only
// the codes the GATT client acts on are named; others are surfaced numerically.
// ---------------------------------------------------------------------------

pub const ERR_INVALID_HANDLE: u8 = 0x01;
pub const ERR_READ_NOT_PERMITTED: u8 = 0x02;
pub const ERR_WRITE_NOT_PERMITTED: u8 = 0x03;
pub const ERR_INSUFFICIENT_AUTHENTICATION: u8 = 0x05;
pub const ERR_REQUEST_NOT_SUPPORTED: u8 = 0x06;
/// Read Blob past the end of a value — the client's signal that a long read is done.
pub const ERR_INVALID_OFFSET: u8 = 0x07;
pub const ERR_INSUFFICIENT_AUTHORIZATION: u8 = 0x08;
/// No attributes in the requested range — the client's signal that a discovery
/// sweep is complete.
pub const ERR_ATTRIBUTE_NOT_FOUND: u8 = 0x0A;
pub const ERR_INSUFFICIENT_ENCRYPTION: u8 = 0x0F;

// ---------------------------------------------------------------------------
// Request / command encoders (client -> server).
// ---------------------------------------------------------------------------

/// Encode a UUID (16- or 128-bit string) into its little-endian ATT wire form.
/// Returns `None` for a string that is neither a Bluetooth 16-bit UUID (in the
/// base range) nor a full 128-bit UUID.
fn uuid_to_le(uuid: &str) -> Option<Vec<u8>> {
    let hex: String = uuid.chars().filter(|c| *c != '-').collect();
    // Checking the digits first keeps `from_str_radix` from accepting a sign,
    // and makes the byte length a digit count.
    if hex.len() != 32 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let value = u128::from_str_radix(&hex, 16).ok()?;
    // The Bluetooth Base UUID, 00000000-0000-1000-8000-00805f9b34fb. A UUID
    // that matches it outside the 16-bit field (the `xxxx` of
    // 0000xxxx-0000-1000-8000-00805f9b34fb) has a 16-bit shorthand.
    const BASE: u128 = 0x0000_0000_0000_1000_8000_0080_5f9b_34fb;
    const SHORT_FIELD: u128 = 0xffff << 96;
    if value & !SHORT_FIELD == BASE {
        Some(((value >> 96) as u16).to_le_bytes().to_vec())
    } else {
        // Full 128-bit, little-endian (reverse of the display order).
        Some(value.to_le_bytes().to_vec())
    }
}

/// Exchange MTU Request: negotiate the client's receive MTU.
pub fn exchange_mtu_req(client_rx_mtu: u16) -> Vec<u8> {
    let m = client_rx_mtu.to_le_bytes();
    vec![OP_EXCHANGE_MTU_REQ, m[0], m[1]]
}

/// Find Information Request: discover attribute handles + types in a range
/// (used for descriptor discovery).
pub fn find_information_req(start: u16, end: u16) -> Vec<u8> {
    let s = start.to_le_bytes();
    let e = end.to_le_bytes();
    vec![OP_FIND_INFORMATION_REQ, s[0], s[1], e[0], e[1]]
}

/// Read By Type Request: find attributes of `type_uuid` in a range (characteristic
/// discovery uses the Characteristic Declaration type 0x2803). `None` if the UUID
/// can't be encoded.
pub fn read_by_type_req(start: u16, end: u16, type_uuid: &str) -> Option<Vec<u8>> {
    read_range_req(OP_READ_BY_TYPE_REQ, start, end, type_uuid)
}

/// Read By Group Type Request: find grouping attributes of `group_uuid` in a
/// range (primary-service discovery uses the Primary Service type 0x2800).
pub fn read_by_group_type_req(start: u16, end: u16, group_uuid: &str) -> Option<Vec<u8>> {
    read_range_req(OP_READ_BY_GROUP_TYPE_REQ, start, end, group_uuid)
}

fn read_range_req(opcode: u8, start: u16, end: u16, uuid: &str) -> Option<Vec<u8>> {
    let s = start.to_le_bytes();
    let e = end.to_le_bytes();
    let u = uuid_to_le(uuid)?;
    let mut pkt = Vec::with_capacity(5 + u.len());
    pkt.extend_from_slice(&[opcode, s[0], s[1], e[0], e[1]]);
    pkt.extend_from_slice(&u);
    Some(pkt)
}

/// Read Request: read a characteristic/descriptor value by handle.
pub fn read_req(handle: u16) -> Vec<u8> {
    let h = handle.to_le_bytes();
    vec![OP_READ_REQ, h[0], h[1]]
}

/// Read Blob Request: read the continuation of a long value from `offset`.
pub fn read_blob_req(handle: u16, offset: u16) -> Vec<u8> {
    let h = handle.to_le_bytes();
    let o = offset.to_le_bytes();
    vec![OP_READ_BLOB_REQ, h[0], h[1], o[0], o[1]]
}

/// Write Request (acknowledged): write `value` to `handle`.
pub fn write_req(handle: u16, value: &[u8]) -> Vec<u8> {
    let h = handle.to_le_bytes();
    let mut pkt = Vec::with_capacity(3 + value.len());
    pkt.extend_from_slice(&[OP_WRITE_REQ, h[0], h[1]]);
    pkt.extend_from_slice(value);
    pkt
}

/// Write Command (unacknowledged): write `value` to `handle`. The server sends
/// neither a response nor an error, so the PDU layout is the only feedback the
/// wire gives.
pub fn write_cmd(handle: u16, value: &[u8]) -> Vec<u8> {
    let h = handle.to_le_bytes();
    let mut pkt = Vec::with_capacity(3 + value.len());
    pkt.extend_from_slice(&[OP_WRITE_CMD, h[0], h[1]]);
    pkt.extend_from_slice(value);
    pkt
}

/// Handle Value Confirmation: the client's ack of a server Indication.
pub fn handle_value_confirmation() -> Vec<u8> {
    vec![OP_HANDLE_VALUE_CFM]
}

// ---------------------------------------------------------------------------
// Response / notification decoder (server -> client).
// ---------------------------------------------------------------------------

/// A decoded inbound ATT PDU. Response payloads whose interpretation is
/// GATT-specific (service / characteristic records) are left as raw `(handle,
/// value)` entries for [`crate::gatt`] to decode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttPdu {
    /// Error Response: the `req_opcode` that failed, the attribute `handle` (0
    /// when not applicable), and the ATT error code.
    ErrorResponse {
        req_opcode: u8,
        handle: u16,
        error: u8,
    },
    /// Exchange MTU Response: the server's receive MTU.
    ExchangeMtuResponse { mtu: u16 },
    /// Find Information Response: `(handle, uuid)` pairs (descriptor discovery).
    FindInformationResponse { entries: Vec<(u16, String)> },
    /// Read By Type Response: `(handle, value)` entries (characteristic discovery).
    ReadByTypeResponse { entries: Vec<(u16, Vec<u8>)> },
    /// Read By Group Type Response: `(start_handle, end_handle, value)` entries
    /// (primary-service discovery).
    ReadByGroupTypeResponse { entries: Vec<(u16, u16, Vec<u8>)> },
    /// Read Response: the (possibly truncated to MTU-1) attribute value.
    ReadResponse { value: Vec<u8> },
    /// Read Blob Response: a continuation chunk of a long value.
    ReadBlobResponse { value: Vec<u8> },
    /// Write Response: the server acknowledged a Write Request.
    WriteResponse,
    /// Handle Value Notification (no confirmation expected).
    HandleValueNotification { handle: u16, value: Vec<u8> },
    /// Handle Value Indication (the client must send a Confirmation).
    HandleValueIndication { handle: u16, value: Vec<u8> },
}

/// Parse one inbound ATT PDU. Returns `None` for an empty buffer, a truncated
/// fixed-layout PDU, or an opcode this client doesn't handle.
pub fn parse(buf: &[u8]) -> Option<AttPdu> {
    let (&opcode, rest) = buf.split_first()?;
    match opcode {
        OP_ERROR_RSP => {
            // req_opcode(1) handle(2) error(1)
            let &[req_opcode, h0, h1, error] = rest.first_chunk::<4>()?;
            Some(AttPdu::ErrorResponse {
                req_opcode,
                handle: u16::from_le_bytes([h0, h1]),
                error,
            })
        }
        OP_EXCHANGE_MTU_RSP => {
            let &mtu = rest.first_chunk::<2>()?;
            Some(AttPdu::ExchangeMtuResponse {
                mtu: u16::from_le_bytes(mtu),
            })
        }
        OP_FIND_INFORMATION_RSP => parse_find_information(rest),
        OP_READ_BY_TYPE_RSP => parse_read_by_type(rest),
        OP_READ_BY_GROUP_TYPE_RSP => parse_read_by_group_type(rest),
        OP_READ_RSP => Some(AttPdu::ReadResponse {
            value: rest.to_vec(),
        }),
        OP_READ_BLOB_RSP => Some(AttPdu::ReadBlobResponse {
            value: rest.to_vec(),
        }),
        OP_WRITE_RSP => Some(AttPdu::WriteResponse),
        OP_HANDLE_VALUE_NTF => {
            let (handle, value) = handle_value(rest)?;
            Some(AttPdu::HandleValueNotification { handle, value })
        }
        OP_HANDLE_VALUE_IND => {
            let (handle, value) = handle_value(rest)?;
            Some(AttPdu::HandleValueIndication { handle, value })
        }
        _ => None,
    }
}

/// The `handle(2) value(..)` body of a Handle Value Notification or
/// Indication.
fn handle_value(rest: &[u8]) -> Option<(u16, Vec<u8>)> {
    let (&handle, value) = rest.split_first_chunk::<2>()?;
    Some((u16::from_le_bytes(handle), value.to_vec()))
}

/// Decode a list of fixed-width entries, `width` bytes each, every one an
/// `N`-byte head and the bytes after it. A trailing partial entry is
/// dropped. `None` when `width` is too short to hold the head, or when
/// `entry` rejects one.
fn fixed_entries<const N: usize, T>(
    list: &[u8],
    width: usize,
    entry: impl Fn(&[u8; N], &[u8]) -> Option<T>,
) -> Option<Vec<T>> {
    // A head of at least one byte keeps `chunks_exact` off a zero width.
    const { assert!(N > 0, "fixed_entries needs a non-empty head") };
    if width < N {
        return None;
    }
    list.chunks_exact(width)
        .map(|chunk| {
            let (head, tail) = chunk.split_first_chunk::<N>()?;
            entry(head, tail)
        })
        .collect()
}

/// Format bytes (`0x01` = 16-bit UUIDs, `0x02` = 128-bit), then fixed-width
/// `[handle(2), uuid]` pairs.
fn parse_find_information(rest: &[u8]) -> Option<AttPdu> {
    let (&format, list) = rest.split_first()?;
    let uuid_len = match format {
        0x01 => 2,
        0x02 => 16,
        _ => return None,
    };
    let entries = fixed_entries::<2, _>(list, 2 + uuid_len, |&handle, uuid| {
        Some((u16::from_le_bytes(handle), uuid_from_le(uuid)?))
    })?;
    Some(AttPdu::FindInformationResponse { entries })
}

/// `length(1)` then fixed-width `[handle(2), value(length-2)]` entries.
fn parse_read_by_type(rest: &[u8]) -> Option<AttPdu> {
    let (&length, list) = rest.split_first()?;
    let entries = fixed_entries::<2, _>(list, length.into(), |&handle, value| {
        Some((u16::from_le_bytes(handle), value.to_vec()))
    })?;
    Some(AttPdu::ReadByTypeResponse { entries })
}

/// `length(1)` then fixed-width `[start(2), end(2), value(length-4)]` entries.
fn parse_read_by_group_type(rest: &[u8]) -> Option<AttPdu> {
    let (&length, list) = rest.split_first()?;
    let entries = fixed_entries::<4, _>(list, length.into(), |&[s0, s1, e0, e1], value| {
        let (start, end) = (u16::from_le_bytes([s0, s1]), u16::from_le_bytes([e0, e1]));
        Some((start, end, value.to_vec()))
    })?;
    Some(AttPdu::ReadByGroupTypeResponse { entries })
}

/// Decode a little-endian ATT UUID field (2 or 16 bytes) to a canonical
/// lowercase 128-bit UUID string. `None` for any other length.
pub fn uuid_from_le(le: &[u8]) -> Option<String> {
    match *le {
        [lo, hi] => Some(format_uuid16(u16::from_le_bytes([lo, hi]))),
        _ => <&[u8; 16]>::try_from(le).ok().map(format_uuid128),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A representative 16-bit UUID in canonical string form.
    const CCCD: &str = "00002902-0000-1000-8000-00805f9b34fb";
    // A random 128-bit vendor UUID.
    const VENDOR: &str = "12345678-1234-5678-9abc-def012345678";

    #[test]
    fn uuid_roundtrips_16_and_128_bit() {
        // 16-bit shorthand -> 2 LE bytes -> back.
        let le = uuid_to_le(CCCD).unwrap();
        assert_eq!(le, vec![0x02, 0x29]);
        assert_eq!(uuid_from_le(&le).as_deref(), Some(CCCD));

        // 128-bit -> 16 LE bytes (reversed) -> back.
        let le = uuid_to_le(VENDOR).unwrap();
        assert_eq!(le.len(), 16);
        assert_eq!(le[0], 0x78); // least-significant display byte first
        assert_eq!(uuid_from_le(&le).as_deref(), Some(VENDOR));
    }

    #[test]
    fn uuid_encoding_rejects_non_hex_strings() {
        // 32 bytes but not 32 characters: byte 2 falls inside the first 'é'.
        // Slicing the string two bytes at a time used to panic here.
        let multibyte = format!("a{}b", "é".repeat(15));
        assert_eq!(multibyte.len(), 32);
        assert_eq!(uuid_to_le(&multibyte), None);
        assert_eq!(read_by_type_req(0x0001, 0xFFFF, &multibyte), None);
        // A sign is not a hex digit, though `from_str_radix` accepts one.
        assert_eq!(uuid_to_le("+0002902-0000-1000-8000-00805f9b34fb"), None);
        assert_eq!(uuid_to_le("0000290g-0000-1000-8000-00805f9b34fb"), None);
        assert_eq!(uuid_to_le("2902"), None);
        // Case does not matter.
        assert_eq!(
            uuid_to_le("00002902-0000-1000-8000-00805F9B34FB"),
            Some(vec![0x02, 0x29])
        );
    }

    #[test]
    fn request_encoders_match_wire_layout() {
        assert_eq!(exchange_mtu_req(0x0203), vec![0x02, 0x03, 0x02]);
        assert_eq!(
            find_information_req(0x0001, 0xFFFF),
            vec![0x04, 0x01, 0x00, 0xFF, 0xFF]
        );
        assert_eq!(read_req(0x0025), vec![0x0A, 0x25, 0x00]);
        assert_eq!(
            read_blob_req(0x0025, 0x0016),
            vec![0x0C, 0x25, 0x00, 0x16, 0x00]
        );
        assert_eq!(write_req(0x0025, &[0xAB]), vec![0x12, 0x25, 0x00, 0xAB]);
        assert_eq!(write_cmd(0x0025, &[0xAB]), vec![0x52, 0x25, 0x00, 0xAB]);
        assert_eq!(handle_value_confirmation(), vec![0x1E]);
    }

    #[test]
    fn read_by_group_type_req_uses_16bit_service_uuid() {
        // Primary Service declaration type 0x2800.
        let primary = "00002800-0000-1000-8000-00805f9b34fb";
        assert_eq!(
            read_by_group_type_req(0x0001, 0xFFFF, primary).unwrap(),
            vec![0x10, 0x01, 0x00, 0xFF, 0xFF, 0x00, 0x28]
        );
    }

    #[test]
    fn parses_error_response() {
        // Read Request (0x0A) failed on handle 0x0025 with "Read Not Permitted" (0x02).
        let pdu = parse(&[0x01, 0x0A, 0x25, 0x00, 0x02]).unwrap();
        assert_eq!(
            pdu,
            AttPdu::ErrorResponse {
                req_opcode: 0x0A,
                handle: 0x0025,
                error: 0x02,
            }
        );
    }

    #[test]
    fn parses_exchange_mtu_response() {
        assert_eq!(
            parse(&[0x03, 0xF7, 0x00]).unwrap(),
            AttPdu::ExchangeMtuResponse { mtu: 247 }
        );
    }

    #[test]
    fn parses_read_by_group_type_response_services() {
        // length=6 -> 16-bit service UUIDs: two services.
        // svc1: handles 0x0001..0x0005, uuid 0x1800 (GAP)
        // svc2: handles 0x0006..0x0009, uuid 0x1801 (GATT)
        let buf = [
            0x11, 0x06, 0x01, 0x00, 0x05, 0x00, 0x00, 0x18, 0x06, 0x00, 0x09, 0x00, 0x01, 0x18,
        ];
        let pdu = parse(&buf).unwrap();
        assert_eq!(
            pdu,
            AttPdu::ReadByGroupTypeResponse {
                entries: vec![
                    (0x0001, 0x0005, vec![0x00, 0x18]),
                    (0x0006, 0x0009, vec![0x01, 0x18]),
                ],
            }
        );
    }

    #[test]
    fn parses_read_by_type_response_characteristics() {
        // length=7 -> [handle(2), value(5)]; value = props(1) + value_handle(2) + uuid16(2).
        // char at decl 0x0002: props 0x12 (read+notify), value handle 0x0003, uuid 0x2a00.
        let buf = [0x09, 0x07, 0x02, 0x00, 0x12, 0x03, 0x00, 0x00, 0x2a];
        let pdu = parse(&buf).unwrap();
        assert_eq!(
            pdu,
            AttPdu::ReadByTypeResponse {
                entries: vec![(0x0002, vec![0x12, 0x03, 0x00, 0x00, 0x2a])],
            }
        );
    }

    #[test]
    fn parses_find_information_response_descriptors() {
        // format 0x01 (16-bit): one descriptor, handle 0x0004, uuid 0x2902 (CCCD).
        let buf = [0x05, 0x01, 0x04, 0x00, 0x02, 0x29];
        let pdu = parse(&buf).unwrap();
        assert_eq!(
            pdu,
            AttPdu::FindInformationResponse {
                entries: vec![(0x0004, CCCD.to_string())],
            }
        );
    }

    #[test]
    fn parses_notifications_and_indications() {
        assert_eq!(
            parse(&[0x1B, 0x03, 0x00, 0xDE, 0xAD]).unwrap(),
            AttPdu::HandleValueNotification {
                handle: 0x0003,
                value: vec![0xDE, 0xAD],
            }
        );
        assert_eq!(
            parse(&[0x1D, 0x03, 0x00, 0xBE, 0xEF]).unwrap(),
            AttPdu::HandleValueIndication {
                handle: 0x0003,
                value: vec![0xBE, 0xEF],
            }
        );
    }

    #[test]
    fn parses_read_and_write_responses() {
        assert_eq!(
            parse(&[0x0B, 0x01, 0x02, 0x03]).unwrap(),
            AttPdu::ReadResponse {
                value: vec![0x01, 0x02, 0x03],
            }
        );
        assert_eq!(parse(&[0x13]).unwrap(), AttPdu::WriteResponse);
    }

    #[test]
    fn truncated_and_unknown_pdus_are_none() {
        assert!(parse(&[]).is_none()); // empty
        assert!(parse(&[0x01, 0x0A, 0x25]).is_none()); // error rsp too short
        assert!(parse(&[0x03, 0xF7]).is_none()); // mtu rsp too short
        assert!(parse(&[0x1B, 0x03]).is_none()); // notification missing handle byte
        assert!(parse(&[0xFF, 0x00]).is_none()); // unhandled opcode
                                                 // A group-type response claiming length 6 but with a truncated 2nd entry
                                                 // keeps the first and drops the partial one.
        let buf = [0x11, 0x06, 0x01, 0x00, 0x05, 0x00, 0x00, 0x18, 0x06, 0x00];
        assert_eq!(
            parse(&buf).unwrap(),
            AttPdu::ReadByGroupTypeResponse {
                entries: vec![(0x0001, 0x0005, vec![0x00, 0x18])],
            }
        );
    }
}
