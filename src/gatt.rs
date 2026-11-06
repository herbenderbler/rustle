//! Pure GATT record layer.
//!
//! Interprets the raw response payloads from [`crate::att`] into the GATT
//! objects a client discovers — primary services, characteristics, and
//! descriptors — and builds the Client Characteristic Configuration Descriptor
//! (CCCD) value used to subscribe. Platform-independent and I/O-free: the
//! request/response *exchange* that drives discovery is [`crate::client`];
//! this module only encodes/decodes the records.

use crate::att;

/// Primary Service declaration attribute type (`0x2800`) — the group type for
/// primary-service discovery (Read By Group Type).
pub const PRIMARY_SERVICE_UUID: &str = "00002800-0000-1000-8000-00805f9b34fb";
/// Characteristic declaration attribute type (`0x2803`) — the type for
/// characteristic discovery (Read By Type).
pub const CHARACTERISTIC_UUID: &str = "00002803-0000-1000-8000-00805f9b34fb";
/// Client Characteristic Configuration Descriptor (`0x2902`) — written to
/// subscribe to notifications/indications.
pub const CCCD_UUID: &str = "00002902-0000-1000-8000-00805f9b34fb";

/// Characteristic Properties bits (Bluetooth Core, Vol 3, Part G, §3.3.1.1).
pub mod char_prop {
    pub const BROADCAST: u8 = 0x01;
    pub const READ: u8 = 0x02;
    pub const WRITE_WITHOUT_RESPONSE: u8 = 0x04;
    pub const WRITE: u8 = 0x08;
    pub const NOTIFY: u8 = 0x10;
    pub const INDICATE: u8 = 0x20;
    pub const AUTHENTICATED_SIGNED_WRITES: u8 = 0x40;
    pub const EXTENDED_PROPERTIES: u8 = 0x80;
}

/// A discovered primary service and the handle range it spans.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Service {
    pub start_handle: u16,
    pub end_handle: u16,
    pub uuid: String,
}

/// A discovered characteristic: the declaration handle, its properties, the
/// value handle to read/write, and the characteristic UUID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Characteristic {
    pub decl_handle: u16,
    pub properties: u8,
    pub value_handle: u16,
    pub uuid: String,
}

impl Characteristic {
    pub fn can_read(&self) -> bool {
        self.properties & char_prop::READ != 0
    }
    pub fn can_write(&self) -> bool {
        self.properties & char_prop::WRITE != 0
    }
    pub fn can_notify(&self) -> bool {
        self.properties & char_prop::NOTIFY != 0
    }
    pub fn can_indicate(&self) -> bool {
        self.properties & char_prop::INDICATE != 0
    }
}

/// A discovered descriptor (handle + type UUID).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Descriptor {
    pub handle: u16,
    pub uuid: String,
}

/// Decode primary-service records from a Read By Group Type Response's entries
/// (`(start, end, value)`), where `value` is the service UUID in little-endian
/// form. Entries whose UUID field is a non-standard length are skipped.
pub fn parse_services(entries: &[(u16, u16, Vec<u8>)]) -> Vec<Service> {
    entries
        .iter()
        .filter_map(|(start, end, value)| {
            Some(Service {
                start_handle: *start,
                end_handle: *end,
                uuid: att::uuid_from_le(value)?,
            })
        })
        .collect()
}

/// Decode characteristic records from a Read By Type Response's entries
/// (`(decl_handle, value)`), where `value` = properties(1) + value_handle(2) +
/// characteristic UUID (little-endian, 2 or 16 bytes). Malformed entries skip.
pub fn parse_characteristics(entries: &[(u16, Vec<u8>)]) -> Vec<Characteristic> {
    entries
        .iter()
        .filter_map(|(decl_handle, value)| {
            // props(1) + value_handle(2), then a 16- or 128-bit UUID
            let (&[properties, h0, h1], uuid) = value.split_first_chunk::<3>()?;
            Some(Characteristic {
                decl_handle: *decl_handle,
                properties,
                value_handle: u16::from_le_bytes([h0, h1]),
                uuid: att::uuid_from_le(uuid)?,
            })
        })
        .collect()
}

/// Decode descriptor records from a Find Information Response's `(handle, uuid)`
/// entries.
pub fn parse_descriptors(entries: &[(u16, String)]) -> Vec<Descriptor> {
    entries
        .iter()
        .map(|(handle, uuid)| Descriptor {
            handle: *handle,
            uuid: uuid.clone(),
        })
        .collect()
}

/// The CCCD value that subscribes to notifications and/or indications — written
/// to a characteristic's Client Characteristic Configuration Descriptor
/// (`0x2902`). `[0x00, 0x00]` unsubscribes.
pub fn cccd_value(notify: bool, indicate: bool) -> [u8; 2] {
    let mut bits = 0u16;
    if notify {
        bits |= 0x0001;
    }
    if indicate {
        bits |= 0x0002;
    }
    bits.to_le_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::att::{parse, AttPdu};

    #[test]
    fn decodes_services_from_group_response() {
        // Reuse the ATT decoder, then interpret the entries as services.
        let buf = [
            0x11, 0x06, 0x01, 0x00, 0x05, 0x00, 0x00, 0x18, 0x06, 0x00, 0x09, 0x00, 0x01, 0x18,
        ];
        let AttPdu::ReadByGroupTypeResponse { entries } = parse(&buf).unwrap() else {
            panic!("expected group-type response");
        };
        let services = parse_services(&entries);
        assert_eq!(
            services,
            vec![
                Service {
                    start_handle: 0x0001,
                    end_handle: 0x0005,
                    uuid: "00001800-0000-1000-8000-00805f9b34fb".to_string(),
                },
                Service {
                    start_handle: 0x0006,
                    end_handle: 0x0009,
                    uuid: "00001801-0000-1000-8000-00805f9b34fb".to_string(),
                },
            ]
        );
    }

    #[test]
    fn decodes_characteristic_with_properties() {
        // decl 0x0002, props 0x12 (read+notify), value handle 0x0003, uuid 0x2a00.
        let entries = vec![(0x0002u16, vec![0x12u8, 0x03, 0x00, 0x00, 0x2a])];
        let chars = parse_characteristics(&entries);
        assert_eq!(chars.len(), 1);
        let c = &chars[0];
        assert_eq!(c.decl_handle, 0x0002);
        assert_eq!(c.value_handle, 0x0003);
        assert_eq!(c.uuid, "00002a00-0000-1000-8000-00805f9b34fb");
        assert!(c.can_read());
        assert!(c.can_notify());
        assert!(!c.can_write());
        assert!(!c.can_indicate());
    }

    #[test]
    fn decodes_128bit_characteristic_uuid() {
        // props 0x08 (write), value handle 0x0010, 128-bit vendor uuid (LE).
        let mut value = vec![0x08u8, 0x10, 0x00];
        // 12345678-1234-5678-9abc-def012345678 in little-endian bytes.
        let mut le = [
            0x12u8, 0x34, 0x56, 0x78, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34,
            0x56, 0x78,
        ];
        le.reverse();
        value.extend_from_slice(&le);
        let chars = parse_characteristics(&[(0x000Fu16, value)]);
        assert_eq!(chars[0].uuid, "12345678-1234-5678-9abc-def012345678");
        assert!(chars[0].can_write());
    }

    #[test]
    fn short_characteristic_value_is_skipped() {
        // Only props + one handle byte — too short to hold value_handle + uuid.
        let chars = parse_characteristics(&[(0x0002u16, vec![0x12, 0x03])]);
        assert!(chars.is_empty());
    }

    #[test]
    fn decodes_descriptors_from_find_info() {
        let buf = [0x05, 0x01, 0x04, 0x00, 0x02, 0x29];
        let AttPdu::FindInformationResponse { entries } = parse(&buf).unwrap() else {
            panic!("expected find-information response");
        };
        let descs = parse_descriptors(&entries);
        assert_eq!(
            descs,
            vec![Descriptor {
                handle: 0x0004,
                uuid: CCCD_UUID.to_string(),
            }]
        );
    }

    #[test]
    fn cccd_value_encodes_notify_indicate_bits() {
        assert_eq!(cccd_value(true, false), [0x01, 0x00]);
        assert_eq!(cccd_value(false, true), [0x02, 0x00]);
        assert_eq!(cccd_value(true, true), [0x03, 0x00]);
        assert_eq!(cccd_value(false, false), [0x00, 0x00]); // unsubscribe
    }
}
