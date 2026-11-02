//! Coalesce a scannable advertisement with its scan response.
//!
//! On an active scan a scannable device answers the controller's `SCAN_REQ` with
//! a `SCAN_RSP`, which the controller delivers as a *separate* advertising report
//! from the `ADV_IND` / `ADV_SCAN_IND` that solicited it. General-purpose stacks
//! surface the two already merged; a raw-HCI scanner sees them as two reports.
//! This state machine pairs them back up per device so a consumer sees the
//! whole advertisement rather than each half in isolation.
//!
//! Pure and deterministic: the driving read loop supplies the clock via `now`, so
//! the pairing / flush behaviour is unit-tested without real time.

use crate::hci::{AddrType, AdvPdu, AdvReport, ParsedAd};
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// One advertisement ready for the detection path — either a standalone report or
/// a scannable primary already merged with its `SCAN_RSP`.
#[derive(Debug, PartialEq)]
pub struct MergedAdv {
    pub address: String,
    pub addr_type: AddrType,
    pub rssi: Option<i32>,
    pub ad: ParsedAd,
}

impl MergedAdv {
    fn from_report(r: AdvReport) -> Self {
        MergedAdv {
            address: r.address,
            addr_type: r.addr_type,
            rssi: r.rssi,
            ad: r.ad,
        }
    }
}

/// A scannable primary held back awaiting its `SCAN_RSP`.
struct Pending {
    addr_type: AddrType,
    rssi: Option<i32>,
    ad: ParsedAd,
    since: Instant,
}

/// Pairs scannable primaries with their scan responses, per device.
pub struct ScanMerger {
    pending: HashMap<String, Pending>,
    wait: Duration,
}

impl ScanMerger {
    /// `wait` bounds how long a scannable primary is held for its `SCAN_RSP`
    /// before being emitted alone. Use a small value on the active path (the
    /// response arrives within milliseconds) and [`Duration::ZERO`] on the passive
    /// path, where no `SCAN_REQ` is transmitted so nothing is solicited to wait
    /// for (a scannable primary then flushes on the very next `flush_stale`,
    /// preserving the passive path's per-report emission while still merging a
    /// response that happened to arrive in the same read).
    pub fn new(wait: Duration) -> Self {
        Self {
            pending: HashMap::new(),
            wait,
        }
    }

    /// Offer one decoded report. Returns the advertisements to emit now: zero for
    /// a scannable primary (held for its response, or folded into one already
    /// held for the same device), or one for a standalone report or a merged
    /// primary + response.
    pub fn offer(&mut self, report: AdvReport, now: Instant) -> Vec<MergedAdv> {
        match report.pdu {
            AdvPdu::ScanResponse => {
                // Merge into a held primary if we have one; otherwise the response
                // stands alone (its primary was never seen, or already flushed).
                if let Some(mut p) = self.pending.remove(&report.address) {
                    p.ad.merge_scan_response(report.ad);
                    vec![MergedAdv {
                        address: report.address,
                        addr_type: p.addr_type,
                        // Prefer the response's RSSI (the fresher sample), falling
                        // back to the primary's if the response had none.
                        rssi: report.rssi.or(p.rssi),
                        ad: p.ad,
                    }]
                } else {
                    vec![MergedAdv::from_report(report)]
                }
            }
            AdvPdu::ScannablePrimary => {
                // Hold this primary for its SCAN_RSP. If one is already held for
                // this device (its response hasn't arrived), fold this cycle's
                // advertisement into it and keep waiting — rather than emitting the
                // earlier one alone, which a consumer that judges a device on first
                // sight would classify before the response could complete it. The
                // original `since` is preserved, so a device that re-advertises
                // faster than `wait` still flushes on schedule.
                match self.pending.get_mut(&report.address) {
                    Some(p) => {
                        p.ad.merge_scan_response(report.ad);
                        if report.rssi.is_some() {
                            p.rssi = report.rssi; // freshest sample
                        }
                    }
                    None => {
                        self.pending.insert(
                            report.address,
                            Pending {
                                addr_type: report.addr_type,
                                rssi: report.rssi,
                                ad: report.ad,
                                since: now,
                            },
                        );
                    }
                }
                Vec::new()
            }
            AdvPdu::Standalone => vec![MergedAdv::from_report(report)],
        }
    }

    /// Emit any held primaries at least `wait` old (their `SCAN_RSP` never came).
    /// Call once per read-loop iteration so a device that emits a primary but no
    /// response is still surfaced promptly, and the pending map stays bounded.
    pub fn flush_stale(&mut self, now: Instant) -> Vec<MergedAdv> {
        let ready: Vec<String> = self
            .pending
            .iter()
            .filter(|(_, p)| now.saturating_duration_since(p.since) >= self.wait)
            .map(|(mac, _)| mac.clone())
            .collect();
        ready
            .into_iter()
            .map(|mac| {
                let p = self.pending.remove(&mac).expect("just collected");
                MergedAdv {
                    address: mac,
                    addr_type: p.addr_type,
                    rssi: p.rssi,
                    ad: p.ad,
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(address: &str, pdu: AdvPdu, name: Option<&str>, uuids: &[&str]) -> AdvReport {
        AdvReport {
            address: address.to_string(),
            addr_type: AddrType::Public,
            rssi: Some(-50),
            pdu,
            ad: ParsedAd {
                local_name: name.map(str::to_string),
                service_uuids: uuids.iter().map(|s| s.to_string()).collect(),
                manufacturer_data: Default::default(),
                tx_power: None,
            },
        }
    }

    fn t0() -> Instant {
        Instant::now()
    }

    #[test]
    fn standalone_report_emits_immediately() {
        let mut m = ScanMerger::new(Duration::from_millis(1500));
        let out = m.offer(report("AA", AdvPdu::Standalone, Some("x"), &[]), t0());
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].address, "AA");
    }

    #[test]
    fn scannable_primary_is_held_then_merged_on_response() {
        let now = t0();
        let mut m = ScanMerger::new(Duration::from_millis(1500));
        // ADV_IND with a service UUID, no name — held, nothing emitted yet.
        let out = m.offer(report("AA", AdvPdu::ScannablePrimary, None, &["u"]), now);
        assert!(out.is_empty());
        // SCAN_RSP with the name — merges and emits one advert carrying both.
        let out = m.offer(report("AA", AdvPdu::ScanResponse, Some("Beacon"), &[]), now);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].address, "AA");
        assert_eq!(out[0].ad.local_name.as_deref(), Some("Beacon"));
        assert_eq!(out[0].ad.service_uuids, vec!["u".to_string()]);
    }

    #[test]
    fn scan_response_without_primary_stands_alone() {
        let mut m = ScanMerger::new(Duration::from_millis(1500));
        let out = m.offer(
            report("AA", AdvPdu::ScanResponse, Some("Beacon"), &[]),
            t0(),
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].ad.local_name.as_deref(), Some("Beacon"));
    }

    #[test]
    fn held_primary_flushes_after_wait() {
        let start = t0();
        let mut m = ScanMerger::new(Duration::from_millis(1500));
        assert!(m
            .offer(
                report("AA", AdvPdu::ScannablePrimary, Some("x"), &[]),
                start
            )
            .is_empty());
        // Before the wait elapses, nothing flushes.
        assert!(m.flush_stale(start).is_empty());
        // After the wait, the un-answered primary is emitted alone.
        let later = start + Duration::from_millis(1600);
        let out = m.flush_stale(later);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].address, "AA");
        // And it is gone from the pending set (no double emit).
        assert!(m.flush_stale(later + Duration::from_secs(10)).is_empty());
    }

    #[test]
    fn second_primary_folds_into_the_held_one() {
        let now = t0();
        let mut m = ScanMerger::new(Duration::from_millis(1500));
        assert!(m
            .offer(report("AA", AdvPdu::ScannablePrimary, None, &["u1"]), now)
            .is_empty());
        // A new primary for the same device before any response: folded into the
        // held one (not emitted alone), so a signal-less first advert can't lock
        // the MAC before the response confirms it. Nothing is emitted yet.
        let out = m.offer(
            report("AA", AdvPdu::ScannablePrimary, Some("two"), &["u2"]),
            now,
        );
        assert!(out.is_empty());
        // Its SCAN_RSP then emits the whole accumulation at once.
        let out = m.offer(report("AA", AdvPdu::ScanResponse, None, &["u3"]), now);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].ad.local_name.as_deref(), Some("two"));
        for u in ["u1", "u2", "u3"] {
            assert!(out[0].ad.service_uuids.contains(&u.to_string()));
        }
    }

    #[test]
    fn rapid_readvertising_does_not_reset_the_hold_clock() {
        let start = t0();
        let mut m = ScanMerger::new(Duration::from_millis(1500));
        assert!(m
            .offer(
                report("AA", AdvPdu::ScannablePrimary, Some("x"), &[]),
                start
            )
            .is_empty());
        // A second primary 1s later folds in but must not reset `since`.
        let mid = start + Duration::from_millis(1000);
        assert!(m
            .offer(report("AA", AdvPdu::ScannablePrimary, Some("x"), &[]), mid)
            .is_empty());
        // 1600ms after the FIRST advert (only 600ms after the second) it flushes.
        let out = m.flush_stale(start + Duration::from_millis(1600));
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].address, "AA");
    }

    #[test]
    fn zero_wait_flushes_primary_on_same_tick() {
        // The passive-path configuration: a scannable primary is held during the
        // read (so a same-read response still merges) but flushes immediately after.
        let now = t0();
        let mut m = ScanMerger::new(Duration::ZERO);
        assert!(m
            .offer(report("AA", AdvPdu::ScannablePrimary, Some("x"), &[]), now)
            .is_empty());
        let out = m.flush_stale(now);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].address, "AA");
    }
}
