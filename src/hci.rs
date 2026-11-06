//! Pure BLE HCI framing and advertisement parsing.
//!
//! HCI event framing, LE Advertising Report decoding (legacy and extended),
//! AD-structure decoding, and HCI command framing. This layer is
//! platform-independent, dependency-free, and unit-tested on every OS; the
//! Linux-only socket layer that drives a real controller ([`crate::scan`])
//! consumes it rather than owning it.
//!
//! Malformed or truncated input never panics: parsing stops at the first bad
//! structure and returns whatever was decoded before it.

use std::collections::{hash_map::Entry, HashMap};

// ---------------------------------------------------------------------------
// AD (Advertising Data) structure type codes — Bluetooth Core, "Assigned
// Numbers", Generic Access Profile.
// ---------------------------------------------------------------------------

const AD_INCOMPLETE_16BIT_UUIDS: u8 = 0x02;
const AD_COMPLETE_16BIT_UUIDS: u8 = 0x03;
const AD_INCOMPLETE_32BIT_UUIDS: u8 = 0x04;
const AD_COMPLETE_32BIT_UUIDS: u8 = 0x05;
const AD_INCOMPLETE_128BIT_UUIDS: u8 = 0x06;
const AD_COMPLETE_128BIT_UUIDS: u8 = 0x07;
const AD_SHORTENED_LOCAL_NAME: u8 = 0x08;
const AD_COMPLETE_LOCAL_NAME: u8 = 0x09;
const AD_TX_POWER_LEVEL: u8 = 0x0A;
const AD_SERVICE_DATA_16BIT: u8 = 0x16;
const AD_APPEARANCE: u8 = 0x19;
const AD_SERVICE_DATA_32BIT: u8 = 0x20;
const AD_SERVICE_DATA_128BIT: u8 = 0x21;
const AD_MANUFACTURER_DATA: u8 = 0xFF;

/// Decoded fields from one advertisement's AD payload.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct ParsedAd {
    /// Complete (0x09) or shortened (0x08) local name.
    pub local_name: Option<String>,
    /// Service UUIDs, normalized to lowercase 128-bit string form.
    pub service_uuids: Vec<String>,
    /// Manufacturer-specific data keyed by company identifier (AD type 0xFF).
    pub manufacturer_data: HashMap<u16, Vec<u8>>,
    /// Service data (AD types 0x16 / 0x20 / 0x21), keyed by the service UUID
    /// normalized to lowercase 128-bit string form.
    pub service_data: HashMap<String, Vec<u8>>,
    /// Appearance (AD type 0x19), the GAP appearance category value.
    pub appearance: Option<u16>,
    /// TX power level in dBm (AD type 0x0A), if present.
    pub tx_power: Option<i8>,
}

impl ParsedAd {
    /// Fold a `SCAN_RSP`'s decoded AD into this primary advertisement's, taking
    /// the union of the two halves. A raw-HCI scanner delivers ADV_IND and its
    /// SCAN_RSP as separate report events; general-purpose stacks such as
    /// BlueZ over D-Bus surface them already combined, so merging here restores
    /// that parity (a device that splits its identifying fields across the two
    /// is seen as a whole, not each half alone).
    ///
    /// Fields already present in the primary win, with one exception: a longer
    /// local name from the response replaces a shorter or absent one, since a
    /// primary commonly carries only the *shortened* name and puts the complete
    /// name in the SCAN_RSP.
    pub fn merge_scan_response(&mut self, rsp: ParsedAd) {
        *self = std::mem::take(self).merged(rsp);
    }

    /// The union of this advertisement and `other`, with `self` taking precedence.
    /// A longer local name from `other` replaces a shorter or absent one, and ties
    /// keep `self`'s. Service UUIDs are the union in order of first appearance.
    /// Manufacturer data and service data keep the longer payload per key, ties
    /// keeping `self`'s, since a response often carries the richer copy of an
    /// entry the primary only announces. Appearance and TX power come from `self`
    /// unless absent. The merge never drops a key present on either side.
    pub fn merged(self, other: ParsedAd) -> ParsedAd {
        let mut service_uuids = self.service_uuids;
        for uuid in other.service_uuids {
            if !service_uuids.contains(&uuid) {
                service_uuids.push(uuid);
            }
        }
        ParsedAd {
            local_name: longer(self.local_name, other.local_name, String::len),
            service_uuids,
            manufacturer_data: union_longer(self.manufacturer_data, other.manufacturer_data),
            service_data: union_longer(self.service_data, other.service_data),
            appearance: self.appearance.or(other.appearance),
            tx_power: self.tx_power.or(other.tx_power),
        }
    }
}

/// Keep `new` only when it is strictly longer than `cur`; a tie keeps `cur`,
/// and an absent side yields the other.
fn longer<T>(cur: Option<T>, new: Option<T>, len: impl Fn(&T) -> usize) -> Option<T> {
    match (cur, new) {
        (Some(c), Some(n)) if len(&n) > len(&c) => Some(n),
        (Some(c), _) => Some(c),
        (None, n) => n,
    }
}

/// The union of two maps, keeping the longer payload for a key present in
/// both; a tie keeps `into`'s.
fn union_longer<K: Eq + std::hash::Hash>(
    mut into: HashMap<K, Vec<u8>>,
    from: HashMap<K, Vec<u8>>,
) -> HashMap<K, Vec<u8>> {
    for (key, data) in from {
        match into.entry(key) {
            Entry::Occupied(mut slot) => {
                if data.len() > slot.get().len() {
                    slot.insert(data);
                }
            }
            Entry::Vacant(slot) => {
                slot.insert(data);
            }
        }
    }
    into
}

/// Advertising address type reported by the controller in a report header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddrType {
    /// Public device address (or resolved public identity).
    Public,
    /// Random device address (static, or resolvable/non-resolvable private).
    Random,
}

impl AddrType {
    /// Map an HCI advertising `addr_type` byte to public/random. The spec values
    /// are `0x00` public, `0x01` random, `0x02` public identity (RPA resolved),
    /// `0x03` random identity; anything else falls back to public (`0x00`).
    pub fn from_hci(b: u8) -> Self {
        match b {
            0x01 | 0x03 => AddrType::Random,
            _ => AddrType::Public,
        }
    }

    /// Lowercase string form, `"public"` or `"random"`.
    pub fn as_str(self) -> &'static str {
        match self {
            AddrType::Public => "public",
            AddrType::Random => "random",
        }
    }
}

/// Which advertising PDU an [`AdvReport`] carries — enough to pair a scannable
/// primary (`ADV_IND` / `ADV_SCAN_IND`) with the `SCAN_RSP` the controller
/// solicits for it on an active scan, so the two halves can be merged into one
/// logical advertisement (see [`crate::scan_merge`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdvPdu {
    /// A scannable primary advertisement; a `SCAN_RSP` may follow on an active
    /// scan and should be merged in.
    ScannablePrimary,
    /// A scan response — the second half to merge into a `ScannablePrimary`.
    ScanResponse,
    /// Any other advertisement (non-scannable, directed, or non-connectable); no
    /// `SCAN_RSP` follows, so it stands alone.
    Standalone,
}

impl AdvPdu {
    /// Classify a *legacy* LE Advertising Report `event_type` byte (BT Core,
    /// Vol 4, Part E, §7.7.65.2): `0x00` ADV_IND and `0x02` ADV_SCAN_IND are
    /// scannable, `0x04` is SCAN_RSP, and `0x01` / `0x03` (directed /
    /// non-connectable) stand alone.
    pub fn from_legacy_event_type(evt: u8) -> Self {
        match evt {
            0x00 | 0x02 => AdvPdu::ScannablePrimary,
            0x04 => AdvPdu::ScanResponse,
            _ => AdvPdu::Standalone,
        }
    }

    /// Classify an *extended* advertising report `event_type` bitfield (BT Core,
    /// Vol 4, Part E, §7.7.65.13): bit 3 marks a scan response, bit 1 a scannable
    /// advertisement. The scan-response bit takes precedence.
    pub fn from_ext_event_type(evt: u16) -> Self {
        const SCAN_RESPONSE: u16 = 1 << 3;
        const SCANNABLE: u16 = 1 << 1;
        if evt & SCAN_RESPONSE != 0 {
            AdvPdu::ScanResponse
        } else if evt & SCANNABLE != 0 {
            AdvPdu::ScannablePrimary
        } else {
            AdvPdu::Standalone
        }
    }
}

/// One decoded LE Advertising Report.
#[derive(Debug, PartialEq)]
pub struct AdvReport {
    /// Device address in the conventional MSB-first uppercase display form
    /// (`AA:BB:CC:DD:EE:FF`).
    pub address: String,
    /// Public or random, from the report's `addr_type` byte. Reported on both the
    /// active and passive scan paths, so a consumer can tell a random address
    /// (no OUI) from a public one.
    pub addr_type: AddrType,
    /// RSSI in dBm (the trailing signed byte of the report), or `None` when the
    /// controller reports `0x7F` ("RSSI is not available", BT Core spec), which
    /// must not be read as +127 dBm.
    pub rssi: Option<i32>,
    /// Which advertising PDU this is, so a scannable primary and its SCAN_RSP can
    /// be coalesced (see [`AdvPdu`] and [`crate::scan_merge`]).
    pub pdu: AdvPdu,
    /// Decoded advertising data.
    pub ad: ParsedAd,
}

/// Decode an HCI RSSI byte: `0x7F` is the spec sentinel for "not available".
fn rssi_from_byte(b: u8) -> Option<i32> {
    (b != 0x7f).then_some(b as i8 as i32)
}

/// Format a 6-byte HCI address (little-endian on the wire) as an uppercase,
/// colon-separated MAC string.
pub fn format_addr_le(addr: &[u8]) -> String {
    // HCI delivers the address least-significant byte first; display is MSB first.
    // Written into one pre-sized buffer — this is the hottest advertising path, and
    // the old `map(format!).collect::<Vec>().join(":")` did ~7 heap allocations per
    // address. Manual hex avoids the formatting machinery entirely.
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(addr.len() * 3);
    for (i, &b) in addr.iter().rev().enumerate() {
        if i > 0 {
            out.push(':');
        }
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Expand a 16-bit UUID to the full 128-bit Bluetooth Base UUID string.
pub fn format_uuid16(v: u16) -> String {
    format!("0000{v:04x}-0000-1000-8000-00805f9b34fb")
}

/// Expand a 32-bit UUID to the full 128-bit Bluetooth Base UUID string.
pub fn format_uuid32(v: u32) -> String {
    format!("{v:08x}-0000-1000-8000-00805f9b34fb")
}

/// Format 16 little-endian UUID bytes as a canonical lowercase UUID string.
pub fn format_uuid128(le: &[u8; 16]) -> String {
    let v = u128::from_le_bytes(*le);
    format!(
        "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
        v >> 96,
        (v >> 80) & 0xffff,
        (v >> 64) & 0xffff,
        (v >> 48) & 0xffff,
        v & 0xffff_ffff_ffff,
    )
}

/// The AD structures in an advertisement payload, as `(ad_type, value)` pairs
/// in wire order. This is framing only; [`parse_ad_structures`] interprets the
/// types the crate decodes, and this iterator exposes the rest. Iteration stops
/// at a zero length byte, which terminates the list, or at a structure that
/// claims more bytes than remain, and never panics.
pub fn ad_structures(data: &[u8]) -> impl Iterator<Item = (u8, &[u8])> {
    let mut rest = data;
    std::iter::from_fn(move || {
        // Each structure is `[len][type][len - 1 bytes of value]`, so `len`
        // counts the type byte as well as the value bytes.
        let (&len, after_len) = rest.split_first()?;
        if len == 0 {
            return None;
        }
        let (body, tail) = after_len.split_at_checked(len as usize)?;
        // `len` is at least one here, so the body always holds the type byte.
        let (&ad_type, value) = body.split_first()?;
        rest = tail;
        Some((ad_type, value))
    })
}

/// Decode an advertisement's AD payload into [`ParsedAd`].
///
/// AD structures are length-prefixed: `[len][type][len-1 bytes of data]…`.
/// Framing is done by [`ad_structures`], so a malformed or truncated structure
/// terminates parsing without panicking; any fields decoded before it are kept.
pub fn parse_ad_structures(data: &[u8]) -> ParsedAd {
    ad_structures(data).fold(ParsedAd::default(), |ad, (ad_type, value)| {
        ad.with_structure(ad_type, value)
    })
}

impl ParsedAd {
    /// Fold one framed AD structure into the decoded fields. AD types the crate
    /// does not decode, and values too short for their type, leave the fields
    /// unchanged.
    fn with_structure(mut self, ad_type: u8, value: &[u8]) -> ParsedAd {
        match ad_type {
            AD_COMPLETE_LOCAL_NAME | AD_SHORTENED_LOCAL_NAME => {
                self.local_name = Some(String::from_utf8_lossy(value).to_string());
            }
            AD_INCOMPLETE_16BIT_UUIDS | AD_COMPLETE_16BIT_UUIDS => {
                let uuids = value.as_chunks::<2>().0.iter();
                self.service_uuids
                    .extend(uuids.map(|&u| format_uuid16(u16::from_le_bytes(u))));
            }
            AD_INCOMPLETE_32BIT_UUIDS | AD_COMPLETE_32BIT_UUIDS => {
                let uuids = value.as_chunks::<4>().0.iter();
                self.service_uuids
                    .extend(uuids.map(|&u| format_uuid32(u32::from_le_bytes(u))));
            }
            AD_INCOMPLETE_128BIT_UUIDS | AD_COMPLETE_128BIT_UUIDS => {
                let uuids = value.as_chunks::<16>().0.iter();
                self.service_uuids.extend(uuids.map(format_uuid128));
            }
            // Each keyed payload leads with its key; a value too short to hold
            // the key is dropped.
            AD_MANUFACTURER_DATA => {
                if let Some((&company, data)) = value.split_first_chunk::<2>() {
                    self.manufacturer_data
                        .insert(u16::from_le_bytes(company), data.to_vec());
                }
            }
            AD_SERVICE_DATA_16BIT => {
                if let Some((&uuid, data)) = value.split_first_chunk::<2>() {
                    self.service_data
                        .insert(format_uuid16(u16::from_le_bytes(uuid)), data.to_vec());
                }
            }
            AD_SERVICE_DATA_32BIT => {
                if let Some((&uuid, data)) = value.split_first_chunk::<4>() {
                    self.service_data
                        .insert(format_uuid32(u32::from_le_bytes(uuid)), data.to_vec());
                }
            }
            AD_SERVICE_DATA_128BIT => {
                if let Some((uuid, data)) = value.split_first_chunk::<16>() {
                    self.service_data
                        .insert(format_uuid128(uuid), data.to_vec());
                }
            }
            AD_APPEARANCE => {
                if let Some(&appearance) = value.first_chunk::<2>() {
                    self.appearance = Some(u16::from_le_bytes(appearance));
                }
            }
            AD_TX_POWER_LEVEL => {
                if let Some(&b) = value.first() {
                    self.tx_power = Some(b as i8);
                }
            }
            _ => {} // ignore other AD types
        }
        self
    }
}

/// The reports of an advertising report sub-event: a `num_reports` byte, then
/// that many variable-length reports, each split off the front of the
/// remaining bytes by `report`. Decoding stops after `num_reports` reports or
/// at the first one `report` cannot split, so truncated input yields the
/// reports decoded before it.
fn reports<'a>(
    params: &'a [u8],
    mut report: impl FnMut(&'a [u8]) -> Option<(AdvReport, &'a [u8])>,
) -> Vec<AdvReport> {
    let Some((&num_reports, mut rest)) = params.split_first() else {
        return Vec::new();
    };
    std::iter::from_fn(|| {
        let (decoded, tail) = report(rest)?;
        rest = tail;
        Some(decoded)
    })
    .take(num_reports.into())
    .collect()
}

/// Parse the parameters of an `LE Advertising Report` sub-event (everything
/// after the sub-event code byte) into zero or more [`AdvReport`]s.
///
/// Layout per the Bluetooth Core spec (Vol 4, Part E, §7.7.65.2):
/// `num_reports`, then for each report `event_type(1) addr_type(1) addr(6)
/// data_len(1) data(data_len) rssi(1)`.  Controllers in practice emit a single
/// report per event; multiple reports are parsed sequentially.  Truncated
/// input stops parsing and returns the reports decoded so far.
pub fn parse_le_advertising_report(params: &[u8]) -> Vec<AdvReport> {
    reports(params, |rest| {
        let (&[event_type, addr_type], rest) = rest.split_first_chunk::<2>()?;
        let (addr, rest) = rest.split_first_chunk::<6>()?;
        let (&data_len, rest) = rest.split_first()?;
        let (ad, rest) = rest.split_at_checked(data_len.into())?;
        let (&rssi, rest) = rest.split_first()?;
        let report = AdvReport {
            address: format_addr_le(addr),
            addr_type: AddrType::from_hci(addr_type),
            rssi: rssi_from_byte(rssi),
            pdu: AdvPdu::from_legacy_event_type(event_type),
            ad: parse_ad_structures(ad),
        };
        Some((report, rest))
    })
}

/// Parse the parameters of an `LE Extended Advertising Report` sub-event
/// (everything after the sub-event code byte) into zero or more [`AdvReport`]s.
///
/// Layout per the Bluetooth Core spec (Vol 4, Part E, §7.7.65.13): `num_reports`,
/// then for each report a 24-byte fixed header — `event_type(2) addr_type(1)
/// addr(6) primary_phy(1) secondary_phy(1) adv_sid(1) tx_power(1) rssi(1)
/// periodic_interval(2) direct_addr_type(1) direct_addr(6) data_len(1)` —
/// followed by `data_len` bytes of AD.  Unlike the legacy report, RSSI sits
/// *inside* the header (not trailing) and there is a dedicated TX-power byte
/// (`0x7F` = unavailable).  BT5 controllers report extended-advertising PDUs
/// only through this sub-event, and report legacy advertisements through it too
/// once an extended scan is enabled — so decoding it is required to see those
/// devices at all.  Truncated input stops parsing and returns what was decoded.
pub fn parse_le_extended_advertising_report(params: &[u8]) -> Vec<AdvReport> {
    reports(params, |rest| {
        let (&event_type, rest) = rest.split_first_chunk::<2>()?;
        let (&addr_type, rest) = rest.split_first()?;
        let (addr, rest) = rest.split_first_chunk::<6>()?;
        let (&[_primary_phy, _secondary_phy, _adv_sid, tx_power, rssi], rest) =
            rest.split_first_chunk::<5>()?;
        // periodic_interval(2) direct_addr_type(1) direct_addr(6)
        let (_, rest) = rest.split_first_chunk::<9>()?;
        let (&data_len, rest) = rest.split_first()?;
        let (ad, rest) = rest.split_at_checked(data_len.into())?;
        let mut ad = parse_ad_structures(ad);
        // Prefer the header TX-power field when the AD carried no TX-power
        // structure of its own (0x7F means the controller had no value).
        if ad.tx_power.is_none() && tx_power != 0x7f {
            ad.tx_power = Some(tx_power as i8);
        }
        let report = AdvReport {
            address: format_addr_le(addr),
            addr_type: AddrType::from_hci(addr_type),
            rssi: rssi_from_byte(rssi),
            pdu: AdvPdu::from_ext_event_type(u16::from_le_bytes(event_type)),
            ad,
        };
        Some((report, rest))
    })
}

/// HCI packet indicators, the first byte of a raw-socket datagram: a command
/// the host sends, and an event the controller sends back.
const HCI_COMMAND_PKT: u8 = 0x01;
const HCI_EVENT_PKT: u8 = 0x04;
/// Event code for an LE Meta event.
const HCI_EV_LE_META: u8 = 0x3E;
/// LE Meta sub-event code for an Advertising Report.
const HCI_SUBEV_LE_ADVERTISING_REPORT: u8 = 0x02;
/// LE Meta sub-event code for an Extended Advertising Report (BT5).
const HCI_SUBEV_LE_EXT_ADVERTISING_REPORT: u8 = 0x0D;
/// Event code for Command Complete.
pub(crate) const HCI_EV_CMD_COMPLETE: u8 = 0x0E;
/// Event code for Command Status.
pub(crate) const HCI_EV_CMD_STATUS: u8 = 0x0F;

/// Parse a raw HCI datagram read from the socket into advertising reports.
///
/// Expects the leading packet-type byte (`0x04` for events).  Returns an empty
/// vector for non-event packets, non-LE-meta events, and non-advertising-report
/// sub-events, as well as for any truncated input.
pub fn parse_hci_packet(buf: &[u8]) -> Vec<AdvReport> {
    // LE Meta parameters: [sub-event code][sub-event parameters…]
    match event_params(buf) {
        Some((HCI_EV_LE_META, [HCI_SUBEV_LE_ADVERTISING_REPORT, report @ ..])) => {
            parse_le_advertising_report(report)
        }
        Some((HCI_EV_LE_META, [HCI_SUBEV_LE_EXT_ADVERTISING_REPORT, report @ ..])) => {
            parse_le_extended_advertising_report(report)
        }
        _ => Vec::new(),
    }
}

/// True if `buf` is framed as an LE advertising-report event (legacy sub-event
/// `0x02` or extended `0x0D`), regardless of whether its body parses.  Paired
/// with [`parse_hci_packet`]'s output: an adv-report packet that yields zero
/// reports is a truncated/malformed report or an AD layout we don't decode,
/// which a caller may want to count.  Non-advertising events
/// (Command Complete, connection events, …) are *not* adv-report packets, so a
/// legitimately empty decode of those is never miscounted.
pub fn is_adv_report_packet(buf: &[u8]) -> bool {
    // [type=0x04][event_code=0x3E][param_len][sub-event code]…, whatever
    // param_len claims.
    matches!(
        buf,
        [
            HCI_EVENT_PKT,
            HCI_EV_LE_META,
            _,
            HCI_SUBEV_LE_ADVERTISING_REPORT | HCI_SUBEV_LE_EXT_ADVERTISING_REPORT,
            ..
        ]
    )
}

/// Split an HCI event packet into its event code and parameters. `None` for a
/// non-event packet, or one whose parameter length overruns the buffer.
fn event_params(buf: &[u8]) -> Option<(u8, &[u8])> {
    // [type=0x04][event_code][param_len][params…]
    let &[HCI_EVENT_PKT, event_code, param_len, ref params @ ..] = buf else {
        return None;
    };
    params
        .get(..param_len as usize)
        .map(|params| (event_code, params))
}

/// Split Command Complete parameters into the answered opcode and the return
/// parameters that follow it.
fn command_complete_params(p: &[u8]) -> Option<(u16, &[u8])> {
    // [num_hci_cmd_pkts][opcode_lo][opcode_hi][return parameters…]
    let &[_, lo, hi, ref ret @ ..] = p else {
        return None;
    };
    Some((u16::from_le_bytes([lo, hi]), ret))
}

/// If `buf` is a Command Complete event, return the opcode it answers and its
/// return parameters, which begin with the status for every command this crate
/// sends; otherwise `None`. A Command Status event is not a Command Complete:
/// [`parse_command_event`] accepts either when only the status matters.
pub fn parse_command_complete(buf: &[u8]) -> Option<(u16, &[u8])> {
    match event_params(buf)? {
        (HCI_EV_CMD_COMPLETE, p) => command_complete_params(p),
        _ => None,
    }
}

/// If `buf` is a Command Complete or Command Status event, return its
/// `(opcode, status)`; otherwise `None`.
///
/// Used to confirm the controller actually *accepted* an HCI command (status
/// `0x00`) rather than only that the bytes were written — so a controller that
/// rejects a scan command surfaces a real error instead of a silent "scan
/// active, no detections".
pub fn parse_command_event(buf: &[u8]) -> Option<(u16, u8)> {
    match event_params(buf)? {
        (HCI_EV_CMD_COMPLETE, p) => {
            let (opcode, ret) = command_complete_params(p)?;
            Some((opcode, *ret.first()?))
        }
        // Command Status: [status][num_hci_cmd_pkts][opcode_lo][opcode_hi]
        (HCI_EV_CMD_STATUS, &[status, _, lo, hi, ..]) => {
            Some((u16::from_le_bytes([lo, hi]), status))
        }
        _ => None,
    }
}

/// Whether `pkt` settles a wait for `opcode`'s Command Complete or Command
/// Status. `None` keeps waiting: the packet is an advertising report, another
/// command's event, or not an event at all. `Some(Ok(()))` means the controller
/// accepted the command (status `0x00`) and `Some(Err(status))` means it
/// rejected it. This is the pure half of a command exchange; the socket layers
/// loop on it with a bounded number of reads.
pub fn command_outcome(opcode: u16, pkt: &[u8]) -> Option<Result<(), u8>> {
    match parse_command_event(pkt)? {
        (op, 0x00) if op == opcode => Some(Ok(())),
        (op, status) if op == opcode => Some(Err(status)),
        _ => None,
    }
}

/// Frame one HCI command packet for a raw HCI socket:
/// `[0x01 HCI_COMMAND_PKT][opcode_lo][opcode_hi][param_len][params…]`.
///
/// The inverse of [`parse_command_event`]'s opcode echo: the `opcode` passed
/// here is the one the controller's Command Complete / Command Status reports.
///
/// # Panics
///
/// If `params` exceeds 255 bytes — the HCI parameter-length field is one byte,
/// so a longer command is a caller bug, not a runtime condition.
pub fn build_command(opcode: u16, params: &[u8]) -> Vec<u8> {
    assert!(
        params.len() <= u8::MAX as usize,
        "HCI command parameters exceed 255 bytes"
    );
    let mut pkt = Vec::with_capacity(4 + params.len());
    pkt.push(HCI_COMMAND_PKT);
    pkt.extend_from_slice(&opcode.to_le_bytes());
    pkt.push(params.len() as u8);
    pkt.extend_from_slice(params);
    pkt
}

// ===========================================================================
// Tests for the pure parsing layer (run on every platform)
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_command_frames_opcode_little_endian_with_length() {
        // LE Set Scan Enable (0x200C), params [enable=1, filter_dup=0].
        assert_eq!(
            build_command(0x200C, &[0x01, 0x00]),
            vec![0x01, 0x0C, 0x20, 0x02, 0x01, 0x00]
        );
        // No parameters: a bare 4-byte header with param_len = 0.
        assert_eq!(build_command(0x0C03, &[]), vec![0x01, 0x03, 0x0C, 0x00]);
    }

    #[test]
    fn build_command_round_trips_through_command_complete() {
        // The opcode framed into a command is the one a Command Complete event
        // echoes back, so a caller can match the response to its request.
        let opcode = 0x2041;
        let pkt = build_command(opcode, &[0; 8]);
        let echoed = u16::from_le_bytes([pkt[1], pkt[2]]);
        let event = [
            HCI_EVENT_PKT,
            HCI_EV_CMD_COMPLETE,
            4,
            1,
            pkt[1],
            pkt[2],
            0x00,
        ];
        assert_eq!(parse_command_event(&event), Some((echoed, 0x00)));
        assert_eq!(echoed, opcode);
    }

    #[test]
    #[should_panic(expected = "exceed 255 bytes")]
    fn build_command_rejects_oversized_parameters() {
        build_command(0x200B, &[0; 256]);
    }

    #[test]
    fn uuid16_expands_to_base_uuid() {
        // A 16-bit UUID sits in the third hex group of the Bluetooth Base UUID.
        assert_eq!(
            format_uuid16(0x3100),
            "00003100-0000-1000-8000-00805f9b34fb"
        );
    }

    #[test]
    fn uuid32_expands_to_base_uuid() {
        assert_eq!(
            format_uuid32(0x0000_3100),
            "00003100-0000-1000-8000-00805f9b34fb"
        );
    }

    #[test]
    fn uuid128_is_byte_reversed_and_grouped() {
        // Little-endian bytes of 00003100-0000-1000-8000-00805f9b34fb.
        let le = [
            0xfb, 0x34, 0x9b, 0x5f, 0x80, 0x00, 0x00, 0x80, 0x00, 0x10, 0x00, 0x00, 0x00, 0x31,
            0x00, 0x00,
        ];
        assert_eq!(format_uuid128(&le), "00003100-0000-1000-8000-00805f9b34fb");
    }

    #[test]
    fn addr_is_reversed_and_uppercased() {
        // On the wire, least-significant byte first.
        let addr = [0xcc, 0xbb, 0xaa, 0x4e, 0xc9, 0x70];
        assert_eq!(format_addr_le(&addr), "70:C9:4E:AA:BB:CC");
    }

    #[test]
    fn ad_parses_complete_local_name() {
        // [len=8][type=0x09]['B','e','a','c','o','n','7']
        let name = b"Beacon7";
        let mut data = vec![(name.len() + 1) as u8, AD_COMPLETE_LOCAL_NAME];
        data.extend_from_slice(name);
        let ad = parse_ad_structures(&data);
        assert_eq!(ad.local_name.as_deref(), Some("Beacon7"));
    }

    #[test]
    fn ad_parses_16bit_service_uuid_list() {
        // len=5, type=0x03 (complete 16-bit UUIDs), two UUIDs 0x3100, 0x1809
        let data = [0x05, AD_COMPLETE_16BIT_UUIDS, 0x00, 0x31, 0x09, 0x18];
        let ad = parse_ad_structures(&data);
        assert!(ad
            .service_uuids
            .contains(&"00003100-0000-1000-8000-00805f9b34fb".to_string()));
        assert!(ad
            .service_uuids
            .contains(&"00001809-0000-1000-8000-00805f9b34fb".to_string()));
    }

    #[test]
    fn ad_parses_manufacturer_data() {
        // len=4, type=0xFF, company=0x09C8 (XUNTONG, LE bytes c8 09), payload de ad
        let data = [0x05, AD_MANUFACTURER_DATA, 0xc8, 0x09, 0xde, 0xad];
        let ad = parse_ad_structures(&data);
        assert_eq!(ad.manufacturer_data.get(&0x09C8), Some(&vec![0xde, 0xad]));
    }

    #[test]
    fn ad_parses_service_data() {
        // 16-bit: uuid 0x180f (LE bytes 0f 18), payload 0x64.
        let data = [0x04, AD_SERVICE_DATA_16BIT, 0x0f, 0x18, 0x64];
        let ad = parse_ad_structures(&data);
        assert_eq!(
            ad.service_data.get("0000180f-0000-1000-8000-00805f9b34fb"),
            Some(&vec![0x64])
        );

        // 32-bit: uuid 0x12345678, payload aa bb.
        let data = [
            0x07,
            AD_SERVICE_DATA_32BIT,
            0x78,
            0x56,
            0x34,
            0x12,
            0xaa,
            0xbb,
        ];
        let ad = parse_ad_structures(&data);
        assert_eq!(
            ad.service_data.get("12345678-0000-1000-8000-00805f9b34fb"),
            Some(&vec![0xaa, 0xbb])
        );

        // 128-bit: the LE bytes of 00003100-0000-1000-8000-00805f9b34fb, payload 01.
        let mut data = vec![0x12, AD_SERVICE_DATA_128BIT];
        data.extend_from_slice(&[
            0xfb, 0x34, 0x9b, 0x5f, 0x80, 0x00, 0x00, 0x80, 0x00, 0x10, 0x00, 0x00, 0x00, 0x31,
            0x00, 0x00,
        ]);
        data.push(0x01);
        let ad = parse_ad_structures(&data);
        assert_eq!(
            ad.service_data.get("00003100-0000-1000-8000-00805f9b34fb"),
            Some(&vec![0x01])
        );
    }

    #[test]
    fn ad_parses_service_data_with_empty_payload() {
        // A bare UUID with no payload is still an entry: the device advertises
        // the service, just with nothing attached.
        let data = [0x03, AD_SERVICE_DATA_16BIT, 0x0f, 0x18];
        let ad = parse_ad_structures(&data);
        assert_eq!(
            ad.service_data.get("0000180f-0000-1000-8000-00805f9b34fb"),
            Some(&vec![])
        );
    }

    #[test]
    fn ad_parses_appearance() {
        // 0x0341 = Generic Watch.
        let data = [0x03, AD_APPEARANCE, 0x41, 0x03];
        let ad = parse_ad_structures(&data);
        assert_eq!(ad.appearance, Some(0x0341));
    }

    #[test]
    fn ad_ignores_truncated_service_data_and_appearance() {
        // 16-bit service data needs at least its 2 UUID bytes and appearance
        // needs both of its bytes; shorter values are skipped without panicking.
        let data = [0x02, AD_SERVICE_DATA_16BIT, 0x0f, 0x02, AD_APPEARANCE, 0x41];
        let ad = parse_ad_structures(&data);
        assert!(ad.service_data.is_empty());
        assert_eq!(ad.appearance, None);
    }

    #[test]
    fn ad_parses_tx_power() {
        let data = [0x02, AD_TX_POWER_LEVEL, 0xf8]; // -8 dBm
        let ad = parse_ad_structures(&data);
        assert_eq!(ad.tx_power, Some(-8));
    }

    #[test]
    fn ad_tolerates_truncation() {
        // Claims 8 bytes of name but only provides 3 — must not panic.
        let data = [0x09, AD_COMPLETE_LOCAL_NAME, b'F', b'S'];
        let ad = parse_ad_structures(&data);
        assert!(ad.local_name.is_none());
    }

    #[test]
    fn ad_stops_on_zero_length() {
        let data = [0x00, 0x09, b'X'];
        let ad = parse_ad_structures(&data);
        assert!(ad.local_name.is_none());
    }

    #[test]
    fn ad_structures_yields_type_and_value_pairs() {
        // [len=2][type=0x0A][0xf8] then [len=3][type=0x09]['F','S'].
        let data = [
            0x02,
            AD_TX_POWER_LEVEL,
            0xf8,
            0x03,
            AD_COMPLETE_LOCAL_NAME,
            b'F',
            b'S',
        ];
        let structures: Vec<(u8, &[u8])> = ad_structures(&data).collect();
        let expected: Vec<(u8, &[u8])> = vec![
            (AD_TX_POWER_LEVEL, &[0xf8]),
            (AD_COMPLETE_LOCAL_NAME, b"FS"),
        ];
        assert_eq!(structures, expected);
    }

    #[test]
    fn ad_structures_stops_at_zero_length() {
        // A zero length byte ends the list; the well-formed structure after it
        // is padding, not data.
        let data = [
            0x02,
            AD_TX_POWER_LEVEL,
            0xf8,
            0x00,
            0x02,
            AD_COMPLETE_LOCAL_NAME,
            b'X',
        ];
        let structures: Vec<(u8, &[u8])> = ad_structures(&data).collect();
        let expected: Vec<(u8, &[u8])> = vec![(AD_TX_POWER_LEVEL, &[0xf8])];
        assert_eq!(structures, expected);
    }

    #[test]
    fn ad_structures_stops_at_a_truncated_structure() {
        // The second structure claims 8 bytes of name but only 2 remain.
        let data = [
            0x02,
            AD_TX_POWER_LEVEL,
            0xf8,
            0x09,
            AD_COMPLETE_LOCAL_NAME,
            b'F',
            b'S',
        ];
        let structures: Vec<(u8, &[u8])> = ad_structures(&data).collect();
        let expected: Vec<(u8, &[u8])> = vec![(AD_TX_POWER_LEVEL, &[0xf8])];
        assert_eq!(structures, expected);
    }

    #[test]
    fn ad_structures_yields_an_empty_value_for_a_type_only_structure() {
        // `len` counts the type byte, so a length of 1 is a type with no value.
        let data = [0x01, AD_COMPLETE_LOCAL_NAME];
        let structures: Vec<(u8, &[u8])> = ad_structures(&data).collect();
        let expected: Vec<(u8, &[u8])> = vec![(AD_COMPLETE_LOCAL_NAME, &[])];
        assert_eq!(structures, expected);
    }

    #[test]
    fn ad_structures_on_empty_input_yields_nothing() {
        assert_eq!(ad_structures(&[]).count(), 0);
    }

    #[test]
    fn advertising_report_decodes_address_rssi_and_ad() {
        // num_reports=1, evt_type=0x00, addr_type=0x00, addr (LE), data_len, data, rssi
        let addr = [0xcc, 0xbb, 0xaa, 0x4e, 0xc9, 0x70];
        let ad = [0x05u8, AD_COMPLETE_16BIT_UUIDS, 0x00, 0x31, 0x09, 0x18];
        let mut params = vec![0x01, 0x00, 0x00];
        params.extend_from_slice(&addr);
        params.push(ad.len() as u8);
        params.extend_from_slice(&ad);
        params.push(0xd6); // rssi = -42

        let reports = parse_le_advertising_report(&params);
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].address, "70:C9:4E:AA:BB:CC");
        assert_eq!(reports[0].addr_type, AddrType::Public); // addr_type byte 0x00
        assert_eq!(reports[0].rssi, Some(-42));
        assert!(reports[0]
            .ad
            .service_uuids
            .contains(&"00003100-0000-1000-8000-00805f9b34fb".to_string()));
    }

    #[test]
    fn addr_type_maps_public_and_random() {
        assert_eq!(AddrType::from_hci(0x00), AddrType::Public);
        assert_eq!(AddrType::from_hci(0x02), AddrType::Public); // public identity
        assert_eq!(AddrType::from_hci(0x01), AddrType::Random);
        assert_eq!(AddrType::from_hci(0x03), AddrType::Random); // random identity
        assert_eq!(AddrType::from_hci(0xff), AddrType::Public); // unknown -> public
        assert_eq!(AddrType::Public.as_str(), "public");
        assert_eq!(AddrType::Random.as_str(), "random");
    }

    #[test]
    fn adv_pdu_classifies_legacy_event_types() {
        assert_eq!(
            AdvPdu::from_legacy_event_type(0x00),
            AdvPdu::ScannablePrimary
        ); // ADV_IND
        assert_eq!(
            AdvPdu::from_legacy_event_type(0x02),
            AdvPdu::ScannablePrimary
        ); // ADV_SCAN_IND
        assert_eq!(AdvPdu::from_legacy_event_type(0x04), AdvPdu::ScanResponse); // SCAN_RSP
        assert_eq!(AdvPdu::from_legacy_event_type(0x01), AdvPdu::Standalone); // ADV_DIRECT_IND
        assert_eq!(AdvPdu::from_legacy_event_type(0x03), AdvPdu::Standalone); // ADV_NONCONN_IND
    }

    #[test]
    fn adv_pdu_classifies_extended_event_types() {
        // bit 1 = scannable, bit 3 = scan response (response wins if both set).
        assert_eq!(AdvPdu::from_ext_event_type(0x0000), AdvPdu::Standalone);
        assert_eq!(
            AdvPdu::from_ext_event_type(0x0002),
            AdvPdu::ScannablePrimary
        );
        assert_eq!(AdvPdu::from_ext_event_type(0x0008), AdvPdu::ScanResponse);
        assert_eq!(AdvPdu::from_ext_event_type(0x000A), AdvPdu::ScanResponse);
        // A connectable+scannable legacy-wrapped advert (bits 0,1,4) is scannable.
        assert_eq!(
            AdvPdu::from_ext_event_type(0x0013),
            AdvPdu::ScannablePrimary
        );
    }

    #[test]
    fn merge_scan_response_unions_fields() {
        let mut primary = ParsedAd {
            local_name: Some("Bcn".to_string()), // shortened
            service_uuids: vec!["a".to_string()],
            manufacturer_data: HashMap::from([(0x09C8, vec![1, 2])]),
            service_data: HashMap::from([("sd-a".to_string(), vec![1, 2])]),
            appearance: None,
            tx_power: None,
        };
        let rsp = ParsedAd {
            local_name: Some("Beacon-7".to_string()), // complete -> replaces shorter
            service_uuids: vec!["a".to_string(), "b".to_string()], // "a" dedup, "b" added
            manufacturer_data: HashMap::from([
                (0x09C8, vec![9, 9]), // primary wins on conflict
                (0x00E0, vec![3]),    // new company added
            ]),
            service_data: HashMap::from([
                ("sd-a".to_string(), vec![9, 9]), // same length: primary wins
                ("sd-b".to_string(), vec![3]),    // new service added
            ]),
            appearance: Some(0x0341),
            tx_power: Some(-4),
        };
        primary.merge_scan_response(rsp);
        assert_eq!(primary.local_name.as_deref(), Some("Beacon-7"));
        assert_eq!(
            primary.service_uuids,
            vec!["a".to_string(), "b".to_string()]
        );
        assert_eq!(primary.manufacturer_data.get(&0x09C8), Some(&vec![1, 2]));
        assert_eq!(primary.manufacturer_data.get(&0x00E0), Some(&vec![3]));
        assert_eq!(primary.service_data.get("sd-a"), Some(&vec![1, 2]));
        assert_eq!(primary.service_data.get("sd-b"), Some(&vec![3]));
        assert_eq!(primary.appearance, Some(0x0341));
        assert_eq!(primary.tx_power, Some(-4));
    }

    #[test]
    fn merge_scan_response_keeps_longer_service_data_payload() {
        // A bare entry in the primary, the same service carrying its payload in
        // the response. The richer copy must survive the merge.
        let mut primary = ParsedAd {
            service_data: HashMap::from([("sd".to_string(), vec![])]),
            ..ParsedAd::default()
        };
        primary.merge_scan_response(ParsedAd {
            service_data: HashMap::from([("sd".to_string(), vec![0x64, 0x01])]),
            ..ParsedAd::default()
        });
        assert_eq!(primary.service_data.get("sd"), Some(&vec![0x64, 0x01]));
    }

    #[test]
    fn merge_scan_response_keeps_longer_manufacturer_payload() {
        // Bare vendor ID in the primary, the same ID carrying the serial in the
        // response. The richer (longer) payload must survive the merge, or the
        // serial is lost.
        let mut primary = ParsedAd {
            manufacturer_data: HashMap::from([(0x09C8, vec![0x01])]), // bare
            ..ParsedAd::default()
        };
        primary.merge_scan_response(ParsedAd {
            manufacturer_data: HashMap::from([(0x09C8, b"TN12345678".to_vec())]),
            ..ParsedAd::default()
        });
        assert_eq!(
            primary.manufacturer_data.get(&0x09C8),
            Some(&b"TN12345678".to_vec())
        );
    }

    #[test]
    fn merge_scan_response_keeps_longer_primary_name() {
        // A primary that already carries the complete name is not overwritten by a
        // shorter response name.
        let mut primary = ParsedAd {
            local_name: Some("Beacon-7".to_string()),
            ..ParsedAd::default()
        };
        primary.merge_scan_response(ParsedAd {
            local_name: Some("Bcn".to_string()),
            ..ParsedAd::default()
        });
        assert_eq!(primary.local_name.as_deref(), Some("Beacon-7"));
    }

    #[test]
    fn merged_is_idempotent() {
        // Merging a fully populated value with itself changes nothing: every
        // per-field rule is a tie that keeps `self`'s copy, or a union of equals.
        let a = ParsedAd {
            local_name: Some("Beacon-7".to_string()),
            service_uuids: vec!["a".to_string(), "b".to_string()],
            manufacturer_data: HashMap::from([(0x09C8, vec![1, 2, 3]), (0x00E0, vec![4])]),
            service_data: HashMap::from([
                ("sd-a".to_string(), vec![5, 6]),
                ("sd-b".to_string(), vec![]),
            ]),
            appearance: Some(0x0341),
            tx_power: Some(-4),
        };
        assert_eq!(a.clone().merged(a.clone()), a);
    }

    #[test]
    fn merged_keeps_self_on_equal_length() {
        // A tie on length goes to `self`: an equal-length name or payload from
        // `other` never displaces the copy already held.
        let a = ParsedAd {
            local_name: Some("Bcn".to_string()),
            manufacturer_data: HashMap::from([(0x09C8, vec![1, 2])]),
            service_data: HashMap::from([("sd".to_string(), vec![3, 4])]),
            ..ParsedAd::default()
        };
        let b = ParsedAd {
            local_name: Some("Xyz".to_string()),
            manufacturer_data: HashMap::from([(0x09C8, vec![9, 9])]),
            service_data: HashMap::from([("sd".to_string(), vec![8, 8])]),
            ..ParsedAd::default()
        };
        let merged = a.merged(b);
        assert_eq!(merged.local_name.as_deref(), Some("Bcn"));
        assert_eq!(merged.manufacturer_data.get(&0x09C8), Some(&vec![1, 2]));
        assert_eq!(merged.service_data.get("sd"), Some(&vec![3, 4]));
    }

    #[test]
    fn merged_keeps_every_key_from_both_sides() {
        // Disjoint keys all survive, and a service UUID seen on both sides is
        // listed once, in order of first appearance.
        let a = ParsedAd {
            service_uuids: vec!["a".to_string(), "b".to_string()],
            manufacturer_data: HashMap::from([(0x0001, vec![1]), (0x0002, vec![2])]),
            service_data: HashMap::from([
                ("sd-1".to_string(), vec![1]),
                ("sd-2".to_string(), vec![2]),
            ]),
            ..ParsedAd::default()
        };
        let b = ParsedAd {
            service_uuids: vec!["b".to_string(), "c".to_string()],
            manufacturer_data: HashMap::from([(0x0003, vec![3]), (0x0004, vec![4])]),
            service_data: HashMap::from([
                ("sd-3".to_string(), vec![3]),
                ("sd-4".to_string(), vec![4]),
            ]),
            ..ParsedAd::default()
        };
        let merged = a.merged(b);
        assert_eq!(
            merged.service_uuids,
            vec!["a".to_string(), "b".to_string(), "c".to_string()]
        );
        assert_eq!(
            merged.manufacturer_data,
            HashMap::from([
                (0x0001, vec![1]),
                (0x0002, vec![2]),
                (0x0003, vec![3]),
                (0x0004, vec![4]),
            ])
        );
        assert_eq!(
            merged.service_data,
            HashMap::from([
                ("sd-1".to_string(), vec![1]),
                ("sd-2".to_string(), vec![2]),
                ("sd-3".to_string(), vec![3]),
                ("sd-4".to_string(), vec![4]),
            ])
        );
    }

    #[test]
    fn merged_is_associative() {
        // Every per-field rule is either a union or "leftmost of the longest",
        // so the grouping of a three-way merge must not matter. The values
        // below hit ties and strict length differences in both directions.
        let a = ParsedAd {
            local_name: Some("Bcn".to_string()),
            service_uuids: vec!["a".to_string(), "b".to_string()],
            manufacturer_data: HashMap::from([(0x09C8, vec![1, 2]), (0x00E0, vec![1])]),
            service_data: HashMap::from([
                ("sd-a".to_string(), vec![1, 2, 3]),
                ("sd-b".to_string(), vec![]),
            ]),
            appearance: None,
            tx_power: Some(-4),
        };
        let b = ParsedAd {
            local_name: Some("Beacon-7".to_string()), // longer than a's
            service_uuids: vec!["b".to_string(), "c".to_string()],
            manufacturer_data: HashMap::from([
                (0x09C8, vec![9, 9]),    // ties with a's
                (0x1234, vec![5, 5, 5]), // new company
            ]),
            service_data: HashMap::from([
                ("sd-a".to_string(), vec![7]),    // shorter than a's
                ("sd-c".to_string(), vec![4, 4]), // new service
            ]),
            appearance: Some(0x0341),
            tx_power: None,
        };
        let c = ParsedAd {
            local_name: Some("Beacon-8".to_string()), // ties with b's
            service_uuids: vec!["c".to_string(), "a".to_string(), "d".to_string()],
            manufacturer_data: HashMap::from([
                (0x09C8, vec![3, 3, 3]), // longer than both
                (0x00E0, vec![2]),       // ties with a's
                (0x1234, vec![6, 6]),    // shorter than b's
            ]),
            service_data: HashMap::from([
                ("sd-b".to_string(), vec![1]),    // longer than a's
                ("sd-c".to_string(), vec![5, 5]), // ties with b's
                ("sd-d".to_string(), vec![9]),    // new service
            ]),
            appearance: Some(0x0000),
            tx_power: Some(8),
        };
        let left = a.clone().merged(b.clone()).merged(c.clone());
        let right = a.merged(b.merged(c));
        assert_eq!(left, right);
        // And the result is the leftmost of the longest on every contested key.
        assert_eq!(left.local_name.as_deref(), Some("Beacon-7"));
        assert_eq!(
            left.service_uuids,
            vec![
                "a".to_string(),
                "b".to_string(),
                "c".to_string(),
                "d".to_string()
            ]
        );
        assert_eq!(left.manufacturer_data.get(&0x09C8), Some(&vec![3, 3, 3]));
        assert_eq!(left.manufacturer_data.get(&0x00E0), Some(&vec![1]));
        assert_eq!(left.manufacturer_data.get(&0x1234), Some(&vec![5, 5, 5]));
        assert_eq!(left.service_data.get("sd-a"), Some(&vec![1, 2, 3]));
        assert_eq!(left.service_data.get("sd-b"), Some(&vec![1]));
        assert_eq!(left.service_data.get("sd-c"), Some(&vec![4, 4]));
        assert_eq!(left.service_data.get("sd-d"), Some(&vec![9]));
        assert_eq!(left.appearance, Some(0x0341));
        assert_eq!(left.tx_power, Some(-4));
    }

    #[test]
    fn merge_scan_response_delegates_to_merged() {
        // The mutating entry point and the value-level one agree on the same
        // inputs.
        let primary = ParsedAd {
            local_name: Some("Bcn".to_string()),
            service_uuids: vec!["a".to_string()],
            manufacturer_data: HashMap::from([(0x09C8, vec![1])]),
            service_data: HashMap::from([("sd-a".to_string(), vec![1, 2])]),
            appearance: None,
            tx_power: Some(-4),
        };
        let rsp = ParsedAd {
            local_name: Some("Beacon-7".to_string()),
            service_uuids: vec!["a".to_string(), "b".to_string()],
            manufacturer_data: HashMap::from([(0x09C8, b"TN12345678".to_vec()), (0x00E0, vec![3])]),
            service_data: HashMap::from([
                ("sd-a".to_string(), vec![9, 9]),
                ("sd-b".to_string(), vec![3]),
            ]),
            appearance: Some(0x0341),
            tx_power: None,
        };
        let mut mutated = primary.clone();
        mutated.merge_scan_response(rsp.clone());
        assert_eq!(mutated, primary.merged(rsp));
    }

    #[test]
    fn legacy_report_tags_scan_response_pdu() {
        // event_type 0x04 = SCAN_RSP.
        let addr = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        let mut params = vec![0x01u8, 0x04, 0x00]; // num_reports, event_type=SCAN_RSP, addr_type
        params.extend_from_slice(&addr);
        params.push(0x00); // data_len
        params.push(0xd6); // rssi
        let reports = parse_le_advertising_report(&params);
        assert_eq!(reports[0].pdu, AdvPdu::ScanResponse);
    }

    #[test]
    fn advertising_report_decodes_random_addr_type() {
        // addr_type byte = 0x01 (random), no AD, one RSSI byte.
        let addr = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        let mut params = vec![0x01u8, 0x00, 0x01]; // num_reports, event_type, addr_type=random
        params.extend_from_slice(&addr);
        params.push(0x00); // data_len
        params.push(0xd6); // rssi
        let reports = parse_le_advertising_report(&params);
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].addr_type, AddrType::Random);
    }

    #[test]
    fn advertising_report_tolerates_truncation() {
        // Claims a report but provides no body.
        let params = [0x01u8];
        assert!(parse_le_advertising_report(&params).is_empty());
    }

    #[test]
    fn hci_packet_unwraps_le_advertising_report() {
        // Build the report params, then wrap as [0x04][0x3E][plen][0x02][params].
        let addr = [0xcc, 0xbb, 0xaa, 0x4e, 0xc9, 0x70];
        let ad = [0x03u8, AD_COMPLETE_LOCAL_NAME, b'F', b'S']; // len wrong on purpose? no: len=3 -> type+2 bytes
        let mut report = vec![0x01u8, 0x00, 0x00];
        report.extend_from_slice(&addr);
        report.push(ad.len() as u8);
        report.extend_from_slice(&ad);
        report.push(0xd0); // rssi

        let subevent_params: Vec<u8> = std::iter::once(HCI_SUBEV_LE_ADVERTISING_REPORT)
            .chain(report.iter().copied())
            .collect();
        let mut pkt = vec![HCI_EVENT_PKT, HCI_EV_LE_META, subevent_params.len() as u8];
        pkt.extend_from_slice(&subevent_params);

        let reports = parse_hci_packet(&pkt);
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].address, "70:C9:4E:AA:BB:CC");
        assert_eq!(reports[0].ad.local_name.as_deref(), Some("FS"));
    }

    /// Build the parameters of a single-report Extended Advertising Report,
    /// starting at `num_reports` (i.e. what `parse_le_extended_advertising_report`
    /// receives).
    fn ext_report_params(addr: &[u8; 6], tx_power: u8, rssi: u8, ad: &[u8]) -> Vec<u8> {
        let mut p = vec![0x01u8, 0x00, 0x00, 0x00]; // num_reports, event_type(2), addr_type
        p.extend_from_slice(addr);
        p.extend_from_slice(&[0x01, 0x00, 0x00]); // primary_phy, secondary_phy, adv_sid
        p.push(tx_power);
        p.push(rssi);
        p.extend_from_slice(&[0x00, 0x00, 0x00]); // periodic_interval(2), direct_addr_type
        p.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // direct_address
        p.push(ad.len() as u8);
        p.extend_from_slice(ad);
        p
    }

    #[test]
    fn extended_report_decodes_address_rssi_and_ad() {
        let addr = [0xcc, 0xbb, 0xaa, 0x4e, 0xc9, 0x70];
        let mut ad = vec![0x06u8, AD_COMPLETE_LOCAL_NAME];
        ad.extend_from_slice(b"Probe");
        // tx_power=0x7F (unavailable), rssi=0xC4 (-60)
        let params = ext_report_params(&addr, 0x7f, 0xc4, &ad);

        let reports = parse_le_extended_advertising_report(&params);
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].address, "70:C9:4E:AA:BB:CC");
        assert_eq!(reports[0].addr_type, AddrType::Public); // addr_type byte 0x00
        assert_eq!(reports[0].rssi, Some(-60));
        assert_eq!(reports[0].ad.local_name.as_deref(), Some("Probe"));
        // 0x7F TX-power means "not available" — must not be surfaced.
        assert_eq!(reports[0].ad.tx_power, None);
    }

    #[test]
    fn extended_report_rssi_unavailable_sentinel_is_none() {
        // rssi byte 0x7F = "RSSI is not available"; must be None, not +127 dBm.
        let addr = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        let ad = [0x02u8, AD_COMPLETE_16BIT_UUIDS];
        let params = ext_report_params(&addr, 0xf8, 0x7f, &ad);
        let reports = parse_le_extended_advertising_report(&params);
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].rssi, None);
    }

    #[test]
    fn extended_report_adopts_header_tx_power_when_ad_lacks_it() {
        let addr = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        let ad = [0x02u8, AD_COMPLETE_16BIT_UUIDS]; // no name, no AD tx-power
        let params = ext_report_params(&addr, 0xf8, 0xd0, &ad); // tx=-8 dBm
        let reports = parse_le_extended_advertising_report(&params);
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].ad.tx_power, Some(-8));
    }

    #[test]
    fn extended_report_tolerates_truncation() {
        assert!(parse_le_extended_advertising_report(&[0x01]).is_empty());
        assert!(parse_le_extended_advertising_report(&[0x01, 0x00]).is_empty());
    }

    #[test]
    fn hci_packet_unwraps_extended_advertising_report() {
        let addr = [0xcc, 0xbb, 0xaa, 0x4e, 0xc9, 0x70];
        let mut ad = vec![0x06u8, AD_COMPLETE_LOCAL_NAME];
        ad.extend_from_slice(b"Probe");
        let body = ext_report_params(&addr, 0x7f, 0xc4, &ad);
        let mut sub = vec![HCI_SUBEV_LE_EXT_ADVERTISING_REPORT];
        sub.extend_from_slice(&body);
        let mut pkt = vec![HCI_EVENT_PKT, HCI_EV_LE_META, sub.len() as u8];
        pkt.extend_from_slice(&sub);

        let reports = parse_hci_packet(&pkt);
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].address, "70:C9:4E:AA:BB:CC");
        assert_eq!(reports[0].rssi, Some(-60));
        assert_eq!(reports[0].ad.local_name.as_deref(), Some("Probe"));
    }

    #[test]
    fn command_event_decodes_complete_and_status() {
        // Command Complete for LE Set Scan Enable (0x200C), status 0x00.
        let cc = [0x04u8, 0x0E, 0x04, 0x01, 0x0C, 0x20, 0x00];
        assert_eq!(parse_command_event(&cc), Some((0x200C, 0x00)));
        // Command Status, status 0x0C (Command Disallowed), opcode 0x200B.
        let cs = [0x04u8, 0x0F, 0x04, 0x0C, 0x01, 0x0B, 0x20];
        assert_eq!(parse_command_event(&cs), Some((0x200B, 0x0C)));
        // An advertising report is not a command event.
        assert_eq!(parse_command_event(&[0x04, 0x3E, 0x02, 0x02, 0x00]), None);
    }

    #[test]
    fn command_complete_splits_opcode_and_return_parameters() {
        // Read RSSI complete: opcode 0x1405, then status, handle and RSSI.
        let cc = [0x04u8, 0x0E, 0x07, 0x01, 0x05, 0x14, 0x00, 0x40, 0x00, 0xC4];
        assert_eq!(parse_command_complete(&cc), Some((0x1405, &cc[6..])));
        // No return parameters at all is still a Command Complete.
        assert_eq!(
            parse_command_complete(&[0x04, 0x0E, 0x03, 0x01, 0x0C, 0x20]),
            Some((0x200C, &[][..]))
        );
        // A Command Status, a header too short for the opcode, and a parameter
        // length that overruns the buffer are not.
        assert_eq!(
            parse_command_complete(&[0x04, 0x0F, 0x04, 0x00, 0x01, 0x0C, 0x20]),
            None
        );
        assert_eq!(
            parse_command_complete(&[0x04, 0x0E, 0x02, 0x01, 0x0C]),
            None
        );
        assert_eq!(
            parse_command_complete(&[0x04, 0x0E, 0x09, 0x01, 0x0C, 0x20, 0x00]),
            None
        );
    }

    #[test]
    fn command_outcome_settles_only_on_the_awaited_opcode() {
        let accepted = [0x04u8, 0x0E, 0x04, 0x01, 0x0C, 0x20, 0x00];
        let rejected = [0x04u8, 0x0F, 0x04, 0x0C, 0x01, 0x0C, 0x20];
        let other = [0x04u8, 0x0E, 0x04, 0x01, 0x0B, 0x20, 0x0C];
        let report = [0x04u8, 0x3E, 0x02, 0x02, 0x00];
        assert_eq!(command_outcome(0x200C, &accepted), Some(Ok(())));
        assert_eq!(command_outcome(0x200C, &rejected), Some(Err(0x0C)));
        // Another command's event, even a rejection, an advertising report and
        // an empty read all keep the wait going.
        assert_eq!(command_outcome(0x200C, &other), None);
        assert_eq!(command_outcome(0x200C, &report), None);
        assert_eq!(command_outcome(0x200C, &[]), None);
    }

    #[test]
    fn hci_packet_ignores_non_event_and_non_le() {
        assert!(parse_hci_packet(&[0x02, 0x00, 0x00]).is_empty()); // ACL data
        assert!(parse_hci_packet(&[0x04, 0x0e, 0x01, 0x00]).is_empty()); // Command Complete
        assert!(parse_hci_packet(&[]).is_empty());
    }

    #[test]
    fn is_adv_report_packet_matches_only_advertising_events() {
        // Legacy (sub-event 0x02) and extended (0x0D) advertising reports.
        assert!(is_adv_report_packet(&[0x04, 0x3E, 0x02, 0x02, 0x00]));
        assert!(is_adv_report_packet(&[0x04, 0x3E, 0x02, 0x0D, 0x00]));
        // LE Meta but a different sub-event (connection complete 0x01).
        assert!(!is_adv_report_packet(&[0x04, 0x3E, 0x02, 0x01, 0x00]));
        // Command Complete event (not LE Meta).
        assert!(!is_adv_report_packet(&[
            0x04, 0x0E, 0x04, 0x01, 0x0C, 0x20, 0x00
        ]));
        // ACL data packet, not an event at all.
        assert!(!is_adv_report_packet(&[0x02, 0x00, 0x00, 0x02]));
        // Too short to carry a sub-event byte.
        assert!(!is_adv_report_packet(&[0x04, 0x3E, 0x00]));
    }

    #[test]
    fn truncated_adv_report_is_the_undecoded_case() {
        // Framed as a legacy advertising report (sub-event 0x02) but the body is
        // truncated, so parse_hci_packet yields nothing while is_adv_report_packet
        // is true: an undecoded report, distinct from a non-advertising event
        // that legitimately decodes empty.
        let pkt = [0x04, 0x3E, 0x02, 0x02, 0x01];
        assert!(is_adv_report_packet(&pkt));
        assert!(parse_hci_packet(&pkt).is_empty());
    }
}
