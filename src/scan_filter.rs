//! Client-side filtering of decoded advertisements.
//!
//! A raw-HCI scan is programmed with "accept all" filtering (see
//! [`crate::scan::ScanParams`]), so every advertisement the controller hears
//! reaches the caller. This module narrows that stream in software: a
//! [`ScanFilter`] holds the criteria and [`ScanFilter::matches`] tests one
//! decoded advertisement against them. Filtering after the decode keeps the
//! behaviour exact and predictable; nothing is delegated to the controller.
//!
//! Pure and platform-independent, like the parsers it consumes.

use crate::hci::{format_uuid128, format_uuid16, format_uuid32, AdvReport, ParsedAd};

/// Criteria for keeping an advertisement.
///
/// An empty criterion is not applied, so the default filter matches
/// everything. Every populated criterion must be satisfied, and a criterion
/// holding several entries is satisfied by any one of them.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ScanFilter {
    /// Keep advertisements carrying at least one of these service UUIDs, in
    /// the canonical lowercase 128-bit form the crate's parsers emit. The
    /// UUID may appear in the advertised UUID list or as a service data
    /// entry. Use [`normalize_uuid`] to turn a 16- or 32-bit shorthand into
    /// that form.
    pub service_uuids: Vec<String>,
    /// Keep advertisements whose local name starts with this prefix.
    pub name_prefix: Option<String>,
    /// Keep advertisements carrying manufacturer data from at least one of
    /// these company identifiers.
    pub manufacturer_ids: Vec<u16>,
}

impl ScanFilter {
    /// True when no criterion is set, i.e. every advertisement matches.
    pub fn is_empty(&self) -> bool {
        self.service_uuids.is_empty()
            && self.name_prefix.is_none()
            && self.manufacturer_ids.is_empty()
    }

    /// Test one decoded AD payload against every populated criterion.
    pub fn matches(&self, ad: &ParsedAd) -> bool {
        if !self.service_uuids.is_empty()
            && !self
                .service_uuids
                .iter()
                .any(|u| ad.service_uuids.contains(u) || ad.service_data.contains_key(u))
        {
            return false;
        }
        if let Some(prefix) = &self.name_prefix {
            match &ad.local_name {
                Some(name) if name.starts_with(prefix.as_str()) => {}
                _ => return false,
            }
        }
        if !self.manufacturer_ids.is_empty()
            && !self
                .manufacturer_ids
                .iter()
                .any(|id| ad.manufacturer_data.contains_key(id))
        {
            return false;
        }
        true
    }

    /// [`matches`](Self::matches) applied to a report's decoded AD. On an
    /// active scan, test the merged advertisement from
    /// [`crate::scan_merge::ScanMerger`] instead, so a device whose matching
    /// field arrives in its `SCAN_RSP` is not dropped with only half its data
    /// seen.
    pub fn matches_report(&self, report: &AdvReport) -> bool {
        self.matches(&report.ad)
    }
}

/// Normalize a UUID string to the canonical lowercase 128-bit form the
/// crate's parsers emit. Hyphens are ignored: 4 or 8 hex digits are expanded
/// through the Bluetooth Base UUID, 32 hex digits are lowercased and
/// hyphenated. Anything else is `None`.
pub fn normalize_uuid(uuid: &str) -> Option<String> {
    let hex: String = uuid.trim().chars().filter(|c| *c != '-').collect();
    if !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    match hex.len() {
        4 => Some(format_uuid16(u16::from_str_radix(&hex, 16).ok()?)),
        8 => Some(format_uuid32(u32::from_str_radix(&hex, 16).ok()?)),
        32 => Some(format_uuid128(
            &u128::from_str_radix(&hex, 16).ok()?.to_le_bytes(),
        )),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hci::{AddrType, AdvPdu};

    const HRS: &str = "0000180d-0000-1000-8000-00805f9b34fb";
    const BATT: &str = "0000180f-0000-1000-8000-00805f9b34fb";

    fn ad(name: Option<&str>, uuids: &[&str], companies: &[u16]) -> ParsedAd {
        ParsedAd {
            local_name: name.map(str::to_string),
            service_uuids: uuids.iter().map(|s| s.to_string()).collect(),
            manufacturer_data: companies.iter().map(|&c| (c, Vec::new())).collect(),
            ..ParsedAd::default()
        }
    }

    #[test]
    fn empty_filter_matches_everything() {
        let f = ScanFilter::default();
        assert!(f.is_empty());
        assert!(f.matches(&ParsedAd::default()));
        assert!(f.matches(&ad(Some("x"), &[HRS], &[0x004C])));
    }

    #[test]
    fn service_uuid_criterion_is_any_of() {
        let f = ScanFilter {
            service_uuids: vec![HRS.to_string(), BATT.to_string()],
            ..ScanFilter::default()
        };
        assert!(!f.is_empty());
        assert!(f.matches(&ad(None, &[BATT], &[])));
        assert!(f.matches(&ad(None, &[HRS, "other"], &[])));
        assert!(!f.matches(&ad(None, &["other"], &[])));
        assert!(!f.matches(&ad(None, &[], &[])));
    }

    #[test]
    fn service_uuid_criterion_matches_service_data_keys() {
        let f = ScanFilter {
            service_uuids: vec![HRS.to_string()],
            ..ScanFilter::default()
        };
        // A device may advertise a service only through its service data,
        // with no UUID list at all.
        let data_only = ParsedAd {
            service_data: [(HRS.to_string(), vec![0x42])].into_iter().collect(),
            ..ParsedAd::default()
        };
        assert!(data_only.service_uuids.is_empty());
        assert!(f.matches(&data_only));
        let other_data = ParsedAd {
            service_data: [(BATT.to_string(), vec![0x42])].into_iter().collect(),
            ..ParsedAd::default()
        };
        assert!(!f.matches(&other_data));
    }

    #[test]
    fn name_prefix_requires_a_name_that_starts_with_it() {
        let f = ScanFilter {
            name_prefix: Some("Beacon".to_string()),
            ..ScanFilter::default()
        };
        assert!(f.matches(&ad(Some("Beacon-7"), &[], &[])));
        assert!(f.matches(&ad(Some("Beacon"), &[], &[])));
        assert!(!f.matches(&ad(Some("beacon-7"), &[], &[]))); // case-sensitive
        assert!(!f.matches(&ad(None, &[], &[]))); // nameless never matches
    }

    #[test]
    fn manufacturer_id_criterion_is_any_of() {
        let f = ScanFilter {
            manufacturer_ids: vec![0x004C, 0x09C8],
            ..ScanFilter::default()
        };
        assert!(f.matches(&ad(None, &[], &[0x09C8])));
        assert!(!f.matches(&ad(None, &[], &[0x00E0])));
        assert!(!f.matches(&ad(None, &[], &[])));
    }

    #[test]
    fn populated_criteria_must_all_hold() {
        let f = ScanFilter {
            service_uuids: vec![HRS.to_string()],
            name_prefix: Some("Beacon".to_string()),
            manufacturer_ids: vec![0x004C],
        };
        assert!(f.matches(&ad(Some("Beacon-7"), &[HRS], &[0x004C])));
        // Any single miss fails the whole filter.
        assert!(!f.matches(&ad(Some("Other"), &[HRS], &[0x004C])));
        assert!(!f.matches(&ad(Some("Beacon-7"), &[BATT], &[0x004C])));
        assert!(!f.matches(&ad(Some("Beacon-7"), &[HRS], &[0x09C8])));
    }

    #[test]
    fn matches_report_tests_the_decoded_ad() {
        let f = ScanFilter {
            name_prefix: Some("Beacon".to_string()),
            ..ScanFilter::default()
        };
        let report = AdvReport {
            address: "AA:BB:CC:DD:EE:FF".to_string(),
            addr_type: AddrType::Public,
            rssi: Some(-50),
            pdu: AdvPdu::Standalone,
            ad: ad(Some("Beacon-7"), &[], &[]),
        };
        assert!(f.matches_report(&report));
    }

    #[test]
    fn normalize_uuid_expands_short_forms() {
        assert_eq!(normalize_uuid("180d").as_deref(), Some(HRS));
        assert_eq!(normalize_uuid("180D").as_deref(), Some(HRS));
        assert_eq!(
            normalize_uuid("12345678").as_deref(),
            Some("12345678-0000-1000-8000-00805f9b34fb")
        );
    }

    #[test]
    fn normalize_uuid_canonicalizes_128_bit_forms() {
        assert_eq!(
            normalize_uuid("0000180D-0000-1000-8000-00805F9B34FB").as_deref(),
            Some(HRS)
        );
        assert_eq!(
            normalize_uuid("0000180d00001000800000805f9b34fb").as_deref(),
            Some(HRS)
        );
        // Already canonical stays canonical.
        assert_eq!(normalize_uuid(HRS).as_deref(), Some(HRS));
    }

    #[test]
    fn normalize_uuid_rejects_other_shapes() {
        assert_eq!(normalize_uuid(""), None);
        assert_eq!(normalize_uuid("180"), None); // wrong length
        assert_eq!(normalize_uuid("180g"), None); // not hex
        assert_eq!(normalize_uuid("0000180d-0000"), None); // partial
    }
}
