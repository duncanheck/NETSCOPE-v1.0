//! # history — the opt-in local flow-history log (GROWTH G4.1)
//!
//! NETSCOPE's baseline is deliberately ephemeral: the live world exists in
//! memory, nothing touches disk, and a restart forgets everything
//! (`docs/threat-model.md`). This module is the **opt-in** exception for people
//! who want a record — set `NETSCOPE_HISTORY_DIR` and the agent appends flow
//! *lifecycle* events (open/close, never per-delta activity churn) as JSONL.
//!
//! What lands on disk is exactly the metadata already on the wire — remote
//! endpoint, owning process, org/geo, flags — which is precisely why this is off
//! by default and documented as its own threat-model section: durable connection
//! history is a different blast radius than a live view. Rotation caps the
//! footprint (one live file + one predecessor).

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::capture::CaptureUpdate;

/// Rotate when the live file passes this; the previous file is kept as `.1`.
const MAX_BYTES: u64 = 10 * 1024 * 1024;

pub struct HistoryLog {
    path: PathBuf,
    max_bytes: u64,
    file: Mutex<File>,
}

impl HistoryLog {
    /// Enabled only by `NETSCOPE_HISTORY_DIR` (opt-in by design). A failure to
    /// open is a warning, never fatal — history is an extra, not the product.
    pub fn from_env() -> Option<Arc<Self>> {
        let dir = std::env::var("NETSCOPE_HISTORY_DIR")
            .ok()
            .filter(|d| !d.trim().is_empty())?;
        match Self::open(PathBuf::from(dir), MAX_BYTES) {
            Ok(log) => {
                tracing::info!(path = %log.path.display(), "flow history enabled (opt-in, G4.1)");
                Some(Arc::new(log))
            }
            Err(e) => {
                tracing::warn!(error = %e, "flow history disabled — couldn't open the log");
                None
            }
        }
    }

    fn open(dir: PathBuf, max_bytes: u64) -> std::io::Result<Self> {
        std::fs::create_dir_all(&dir)?;
        let path = dir.join("flows.jsonl");
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        Ok(Self {
            path,
            max_bytes,
            file: Mutex::new(file),
        })
    }

    /// Append this update's lifecycle events: one `open` line per added flow
    /// (full enriched metadata), one `close` line per removed id (the open line
    /// carries the details; the id ties them together). Activity-only updates
    /// write nothing — that churn is what would make history unboundedly noisy.
    pub fn record(&self, update: &CaptureUpdate) {
        if update.delta.adds.is_empty() && update.delta.removes.is_empty() {
            return;
        }
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        let mut buf = String::new();
        for flow in &update.delta.adds {
            if let Ok(flow_json) = serde_json::to_string(flow) {
                buf.push_str(&format!(
                    "{{\"ts\":{ts},\"event\":\"open\",\"flow\":{flow_json}}}\n"
                ));
            }
        }
        for id in &update.delta.removes {
            if let Ok(id_json) = serde_json::to_string(id) {
                buf.push_str(&format!(
                    "{{\"ts\":{ts},\"event\":\"close\",\"id\":{id_json}}}\n"
                ));
            }
        }

        let mut file = self.file.lock().unwrap();
        if file.write_all(buf.as_bytes()).is_err() {
            return; // disk trouble is non-fatal; the live view is unaffected
        }
        // Rotate: current → .1 (replacing any previous .1), reopen fresh.
        let over = file
            .metadata()
            .map(|m| m.len() > self.max_bytes)
            .unwrap_or(false);
        if over {
            let rotated = self.path.with_extension("jsonl.1");
            if std::fs::rename(&self.path, &rotated).is_ok() {
                if let Ok(fresh) = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&self.path)
                {
                    *file = fresh;
                    tracing::info!(path = %self.path.display(), "history log rotated");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::DeltaParts;
    use netscope_protocol::{Category, Flow, L4Proto};

    fn test_flow(id: &str) -> Flow {
        Flow {
            id: id.into(),
            name: "example.com".into(),
            category: Category::Service,
            asn: None,
            location: None,
            process: None,
            port: 443,
            protocol: L4Proto::Tcp,
            encrypted: true,
            ip: "1.2.3.4".into(),
            activity: 0.5,
            alive: true,
            flags: Vec::new(),
        }
    }

    fn update(adds: Vec<Flow>, removes: Vec<String>) -> CaptureUpdate {
        CaptureUpdate {
            generation: 1,
            flows: Vec::new(),
            delta: DeltaParts {
                adds,
                updates: Vec::new(),
                removes,
            },
        }
    }

    fn temp_dir(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!("netscope-history-{tag}-{}", std::process::id()))
    }

    #[test]
    fn records_open_and_close_lines_and_skips_activity_churn() {
        let dir = temp_dir("basic");
        let log = HistoryLog::open(dir.clone(), MAX_BYTES).unwrap();

        log.record(&update(vec![test_flow("f1")], vec!["f0".into()]));
        // Activity-only update: no adds/removes → nothing written.
        log.record(&update(Vec::new(), Vec::new()));

        let body = std::fs::read_to_string(dir.join("flows.jsonl")).unwrap();
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(lines.len(), 2);
        let open: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(open["event"], "open");
        assert_eq!(open["flow"]["id"], "f1");
        let close: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(close["event"], "close");
        assert_eq!(close["id"], "f0");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rotates_past_the_size_cap_and_keeps_one_predecessor() {
        let dir = temp_dir("rotate");
        // A tiny cap so a couple of records trip rotation.
        let log = HistoryLog::open(dir.clone(), 64).unwrap();
        log.record(&update(vec![test_flow("f1")], Vec::new()));
        log.record(&update(vec![test_flow("f2")], Vec::new()));

        assert!(dir.join("flows.jsonl.1").exists(), "predecessor kept");
        // Writes keep landing after rotation. With a cap this tiny every record
        // trips rotation right after its write, so the newest line is in `.1`
        // and the live file is fresh — the invariant is that nothing is lost
        // between the two files.
        log.record(&update(vec![test_flow("f3")], Vec::new()));
        let rotated = std::fs::read_to_string(dir.join("flows.jsonl.1")).unwrap();
        assert!(rotated.contains("\"f3\""));
        assert!(dir.join("flows.jsonl").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
