//! BLE adapter enumeration over the Linux HCI ioctl interface.
//!
//! A direct `HCIGETDEVLIST` / `HCIGETDEVINFO` query on an `AF_BLUETOOTH`
//! control socket — what `hciconfig` does, without the BlueZ userland.
//!
//! Same pure/socket split as [`crate::hci`]:
//! - [`parse_dev_info`] (the `hci_dev_info` byte decoder), [`choose`] (name-
//!   based selection) and [`index_from_name`] are pure and unit-tested on every
//!   OS.
//! - [`enumerate`] (the ioctl socket layer) is Linux-only; elsewhere it returns
//!   an error.

use crate::hci::format_addr_le;

/// One enumerated local Bluetooth adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterInfo {
    /// Controller index (`hciN` → `N`).
    pub id: u16,
    /// Interface name, e.g. `"hci0"`.
    pub name: String,
    /// Hardware `BD_ADDR`, MSB-first uppercase (`AA:BB:CC:DD:EE:FF`) to match
    /// [`crate::hci`]'s address form.
    pub address: String,
    /// Controller is up (`HCI_UP`).
    pub up: bool,
    /// Controller is running (`HCI_RUNNING`).
    pub running: bool,
}

// ---------------------------------------------------------------------------
// `struct hci_dev_info` field offsets (Linux BlueZ ABI). The struct begins:
//   uint16_t dev_id;    // @ 0
//   char     name[8];   // @ 2  (char align 1 — no padding after the u16)
//   bdaddr_t bdaddr;    // @ 10 (6 bytes, align 1)
//   uint32_t flags;     // @ 16 (u32 align 4 — 16 is already aligned)
//   ...                 // type, features[8], stats … (not needed here)
// Only these leading, ABI-stable fields are decoded.
// ---------------------------------------------------------------------------
const DEV_INFO_NAME: usize = 2;
const DEV_INFO_NAME_LEN: usize = 8;
const DEV_INFO_BDADDR: usize = 10;
const DEV_INFO_FLAGS: usize = 16;
/// Bytes needed to reach the end of the `flags` field — the minimum a buffer
/// must contain for [`parse_dev_info`] to decode every field it reads.
const DEV_INFO_MIN_LEN: usize = DEV_INFO_FLAGS + 4;

// HCI device flag bit positions (`enum { HCI_UP, HCI_INIT, HCI_RUNNING, … }`).
const HCI_FLAG_UP: u32 = 1 << 0;
const HCI_FLAG_RUNNING: u32 = 1 << 2;

/// Decode the leading fields of a `struct hci_dev_info` buffer into an
/// [`AdapterInfo`]. Returns `None` if the buffer is too short to hold them.
///
/// Pure and platform-independent: the ioctl fills the buffer, this decodes it,
/// so the decode is unit-tested on every OS without a Bluetooth stack.
pub fn parse_dev_info(buf: &[u8]) -> Option<AdapterInfo> {
    if buf.len() < DEV_INFO_MIN_LEN {
        return None;
    }
    let id = u16::from_le_bytes([buf[0], buf[1]]);

    // NUL-terminated, fixed 8-byte name field.
    let name_field = &buf[DEV_INFO_NAME..DEV_INFO_NAME + DEV_INFO_NAME_LEN];
    let name_end = name_field
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(name_field.len());
    let name = String::from_utf8_lossy(&name_field[..name_end]).to_string();

    // BD_ADDR is little-endian on the wire; format_addr_le renders MSB-first.
    let address = format_addr_le(&buf[DEV_INFO_BDADDR..DEV_INFO_BDADDR + 6]);

    let flags = u32::from_le_bytes([
        buf[DEV_INFO_FLAGS],
        buf[DEV_INFO_FLAGS + 1],
        buf[DEV_INFO_FLAGS + 2],
        buf[DEV_INFO_FLAGS + 3],
    ]);

    Some(AdapterInfo {
        id,
        name,
        address,
        up: flags & HCI_FLAG_UP != 0,
        running: flags & HCI_FLAG_RUNNING != 0,
    })
}

/// Pick which enumerated adapter to open: the first whose `name` equals `bface`
/// (e.g. `"hci1"`, case-insensitive), else fall back to the first adapter
/// (index `0`). Returns `(index, matched)`, where `matched` is `false` on the
/// fallback — the signal that a requested interface was not found. Pure and
/// total: index `0` on an empty list is harmless (the caller's "no adapter"
/// handling takes over).
pub fn choose(adapters: &[AdapterInfo], bface: &str) -> (usize, bool) {
    match adapters
        .iter()
        .position(|a| a.name.eq_ignore_ascii_case(bface))
    {
        Some(i) => (i, true),
        None => (0, false),
    }
}

/// The controller index an interface name denotes: `"hci1"` → `Some(1)`.
/// Surrounding whitespace is ignored; anything that is not `hci` followed by a
/// decimal index is `None`. The index is what [`crate::scan::HciScanner::open`]
/// binds, for when enumeration is unavailable and the caller must trust the
/// name it was given.
pub fn index_from_name(name: &str) -> Option<u16> {
    name.trim().strip_prefix("hci")?.parse().ok()
}

// ===========================================================================
// Linux-only ioctl socket layer
// ===========================================================================

#[cfg(target_os = "linux")]
pub use linux_impl::enumerate;

/// Enumerate the host's Bluetooth adapters. This platform has no HCI ioctl
/// interface, so this always fails.
#[cfg(not(target_os = "linux"))]
pub fn enumerate() -> Result<Vec<AdapterInfo>, String> {
    Err("Bluetooth adapter enumeration is only supported on Linux".to_string())
}

#[cfg(target_os = "linux")]
mod linux_impl {
    use super::*;
    use crate::sys::{close, errno, ioctl, socket, AF_BLUETOOTH, BTPROTO_HCI, SOCK_RAW};
    use std::os::raw::{c_ulong, c_void};

    // BlueZ ioctl request numbers, `_IOR('H', 210/211, int)`, using the
    // asm-generic `_IOC` encoding shared by x86 / arm / arm64 / riscv:
    // dir=2 (read) << 30 | size=4 << 16 | 'H'(0x48) << 8 | nr. So
    // `_IOR('H',210,int) = 0x800448D2` and `211 = 0x800448D3`.
    const HCIGETDEVLIST: c_ulong = 0x8004_48D2;
    const HCIGETDEVINFO: c_ulong = 0x8004_48D3;

    // BlueZ caps the controller count at HCI_MAX_DEV.
    const HCI_MAX_DEV: usize = 16;
    // `hci_dev_list_req` = u16 dev_num, then `hci_dev_req[]` (u16 dev_id + u32
    // dev_opt = 8 bytes each, the array starting at offset 4 after u16 + pad).
    const DEV_REQ_SIZE: usize = 8;
    const DEV_LIST_HDR: usize = 4;
    // `hci_dev_info` is ~92 bytes; over-allocate so a kernel with a larger
    // struct still can't write past the buffer (only the stable leading fields
    // are read back).
    const DEV_INFO_BUF: usize = 256;

    /// Enumerate the host's Bluetooth adapters via `HCIGETDEVLIST` +
    /// `HCIGETDEVINFO`. Adapters whose per-device query fails (e.g. one removed
    /// between the list and the info call) are skipped rather than failing the
    /// whole enumeration.
    pub fn enumerate() -> Result<Vec<AdapterInfo>, String> {
        let fd = unsafe { socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI) };
        if fd < 0 {
            return Err(format!(
                "cannot open HCI control socket (errno {}); need CAP_NET_RAW / root",
                unsafe { errno() }
            ));
        }

        // Device-id list: dev_num (in) = capacity, (out) = actual count.
        let mut list = vec![0u8; DEV_LIST_HDR + HCI_MAX_DEV * DEV_REQ_SIZE];
        list[0..2].copy_from_slice(&(HCI_MAX_DEV as u16).to_le_bytes());
        let rc = unsafe { ioctl(fd, HCIGETDEVLIST, list.as_mut_ptr() as *mut c_void) };
        if rc < 0 {
            let e = unsafe { errno() };
            unsafe { close(fd) };
            return Err(format!("HCIGETDEVLIST failed (errno {e})"));
        }
        let count = (u16::from_le_bytes([list[0], list[1]]) as usize).min(HCI_MAX_DEV);

        let mut out = Vec::with_capacity(count);
        for i in 0..count {
            let off = DEV_LIST_HDR + i * DEV_REQ_SIZE;
            let dev_id = u16::from_le_bytes([list[off], list[off + 1]]);

            // hci_dev_info: set dev_id, then the ioctl fills the rest.
            let mut info = vec![0u8; DEV_INFO_BUF];
            info[0..2].copy_from_slice(&dev_id.to_le_bytes());
            let rc = unsafe { ioctl(fd, HCIGETDEVINFO, info.as_mut_ptr() as *mut c_void) };
            if rc < 0 {
                continue; // adapter vanished between list and info — skip it
            }
            if let Some(ai) = parse_dev_info(&info) {
                out.push(ai);
            }
        }

        unsafe { close(fd) };
        Ok(out)
    }
}

// ===========================================================================
// Tests for the pure layer (run on every platform)
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a synthetic `hci_dev_info` buffer with the leading fields set.
    fn dev_info(id: u16, name: &[u8], bdaddr_le: [u8; 6], flags: u32) -> Vec<u8> {
        let mut buf = vec![0u8; 96];
        buf[0..2].copy_from_slice(&id.to_le_bytes());
        // name[8] at offset 2, NUL-padded.
        let n = name.len().min(DEV_INFO_NAME_LEN);
        buf[DEV_INFO_NAME..DEV_INFO_NAME + n].copy_from_slice(&name[..n]);
        buf[DEV_INFO_BDADDR..DEV_INFO_BDADDR + 6].copy_from_slice(&bdaddr_le);
        buf[DEV_INFO_FLAGS..DEV_INFO_FLAGS + 4].copy_from_slice(&flags.to_le_bytes());
        buf
    }

    #[test]
    fn parses_name_address_and_flags() {
        // BD_ADDR little-endian on the wire -> MSB-first display.
        let buf = dev_info(
            0,
            b"hci0",
            [0xcc, 0xbb, 0xaa, 0x4e, 0xc9, 0x70],
            HCI_FLAG_UP | HCI_FLAG_RUNNING,
        );
        let ai = parse_dev_info(&buf).unwrap();
        assert_eq!(ai.id, 0);
        assert_eq!(ai.name, "hci0");
        assert_eq!(ai.address, "70:C9:4E:AA:BB:CC");
        assert!(ai.up);
        assert!(ai.running);
    }

    #[test]
    fn down_adapter_reports_not_up_not_running() {
        let ai = parse_dev_info(&dev_info(2, b"hci2", [0; 6], 0)).unwrap();
        assert_eq!(ai.id, 2);
        assert_eq!(ai.name, "hci2");
        assert!(!ai.up);
        assert!(!ai.running);
    }

    #[test]
    fn up_but_not_running_is_decoded() {
        // HCI_UP set, HCI_RUNNING clear (mid bring-up).
        let ai = parse_dev_info(&dev_info(1, b"hci1", [1, 2, 3, 4, 5, 6], HCI_FLAG_UP)).unwrap();
        assert!(ai.up);
        assert!(!ai.running);
    }

    #[test]
    fn full_width_name_without_terminator_is_read_whole() {
        // An 8-char name fills the field with no room for a NUL terminator.
        let ai = parse_dev_info(&dev_info(9, b"hci12345", [0; 6], 0)).unwrap();
        assert_eq!(ai.name, "hci12345");
    }

    #[test]
    fn too_short_buffer_is_none() {
        // Anything shorter than the flags field can't be decoded.
        assert!(parse_dev_info(&[0u8; DEV_INFO_MIN_LEN - 1]).is_none());
        assert!(parse_dev_info(&[]).is_none());
    }

    fn adapters() -> Vec<AdapterInfo> {
        vec![
            AdapterInfo {
                id: 0,
                name: "hci0".into(),
                address: "AA:AA:AA:AA:AA:AA".into(),
                up: true,
                running: true,
            },
            AdapterInfo {
                id: 1,
                name: "hci1".into(),
                address: "BB:BB:BB:BB:BB:BB".into(),
                up: true,
                running: false,
            },
        ]
    }

    #[test]
    fn choose_prefers_the_named_interface() {
        assert_eq!(choose(&adapters(), "hci1"), (1, true));
        assert_eq!(choose(&adapters(), "hci0"), (0, true));
        // Case-insensitive, matching the interact-path selector.
        assert_eq!(choose(&adapters(), "HCI1"), (1, true));
    }

    #[test]
    fn choose_falls_back_to_first_when_unmatched() {
        // Requested adapter absent -> index 0, matched=false.
        assert_eq!(choose(&adapters(), "hci9"), (0, false));
        // Empty enumeration is harmless (caller handles "no adapter").
        assert_eq!(choose(&[], "hci0"), (0, false));
    }

    #[test]
    fn index_from_name_parses_the_hci_index() {
        assert_eq!(index_from_name("hci0"), Some(0));
        assert_eq!(index_from_name("hci12"), Some(12));
        assert_eq!(index_from_name("  hci1\n"), Some(1));
    }

    #[test]
    fn index_from_name_rejects_other_names() {
        assert_eq!(index_from_name("wlan0"), None);
        assert_eq!(index_from_name("hci"), None);
        assert_eq!(index_from_name("hcix"), None);
        assert_eq!(index_from_name(""), None);
        // Case-sensitive, like the kernel's interface names.
        assert_eq!(index_from_name("HCI0"), None);
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn enumerate_is_unsupported_off_linux() {
        assert!(enumerate().is_err());
    }
}
