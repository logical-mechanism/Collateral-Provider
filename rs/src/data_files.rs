//! Stat-identity-aware JSON reloader.
//!
//! Both the ban list and the known-hosts registry are operator-curated data,
//! not code. We don't want a code deploy to be the latency for "ban this
//! scammer." Instead the operator edits the JSON file (atomic write-tmp +
//! rename is the expected workflow) and the service picks up the new content
//! on the next request.
//!
//! The cost on the hot path is one `stat` syscall per access. A reload happens
//! whenever `(mtime_ns, size, inode)` changes, including atomic replacements
//! whose timestamp is equal to or older than the previous file.

use std::path::{Path, PathBuf};
use std::sync::Arc;

/// The fields that identify the observed contents of a file.
pub type FileIdentity = (i128, u64, u64);

/// A validator signals rejection by returning `Err(message)`. The message is
/// what gets logged, so it should name the problem.
pub type Validator = Box<dyn Fn(&serde_json::Value) -> Result<(), String> + Send + Sync>;

/// Stat `path` and return its reload identity.
pub fn file_identity(path: &Path) -> std::io::Result<FileIdentity> {
    Ok(stat_identity(&std::fs::metadata(path)?))
}

/// Return the fields that identify the observed contents of a file.
///
/// Never compare timestamps for "newer": an atomic replacement may carry an
/// equal or older mtime and still be a different document. Only equality of
/// the whole triple means "same contents as last read".
fn stat_identity(metadata: &std::fs::Metadata) -> FileIdentity {
    use std::os::unix::fs::MetadataExt;

    let mtime_ns = i128::from(metadata.mtime()) * 1_000_000_000 + i128::from(metadata.mtime_nsec());
    (mtime_ns, metadata.size(), metadata.ino())
}

/// Cache the parsed JSON of a file and re-read when its identity changes.
///
/// Behavior on edge cases:
/// - File missing on first access: returns the default, doesn't crash.
/// - File missing later: keeps the last successfully-loaded value and logs a
///   warning. A stale cache beats a service outage when an operator pulls a
///   file by accident.
/// - File present but unparseable, or rejected by the validator: same. Logs
///   at ERROR and keeps the last good document, and remembers the rejected
///   identity so the same bad update isn't reparsed and relogged on every
///   request.
pub struct ReloadingJson {
    path: PathBuf,
    inner: std::sync::Mutex<ReloadingState>,
    validator: Option<Validator>,
}

struct ReloadingState {
    identity: Option<FileIdentity>,
    data: Arc<serde_json::Value>,
}

impl ReloadingJson {
    pub fn new(path: PathBuf, default: serde_json::Value, validator: Option<Validator>) -> Self {
        Self {
            path,
            inner: std::sync::Mutex::new(ReloadingState {
                identity: None,
                data: Arc::new(default),
            }),
            validator,
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Return the current document, re-reading from disk if the file's
    /// identity has changed since the last call.
    pub fn get(&self) -> Arc<serde_json::Value> {
        let observed = match file_identity(&self.path) {
            Ok(identity) => identity,
            Err(err) => {
                let state = self.state();
                if err.kind() == std::io::ErrorKind::NotFound {
                    // Only worth a warning once we've served real content;
                    // "never existed" is a supported configuration.
                    if state.identity.is_some() {
                        tracing::warn!("Reloadable file disappeared: {}", self.path.display());
                    }
                } else {
                    tracing::error!("Failed to stat {}: {}", self.path.display(), err);
                }
                return state.data.clone();
            }
        };

        let mut state = self.state();
        if state.identity == Some(observed) {
            return state.data.clone();
        }

        // Re-stat under the lock: another thread may have already reloaded, or
        // the file may have been replaced again while we waited for the lock.
        let identity = match file_identity(&self.path) {
            Ok(identity) => identity,
            Err(err) => {
                tracing::error!("Failed to stat {}: {}", self.path.display(), err);
                return state.data.clone();
            }
        };
        if state.identity == Some(identity) {
            return state.data.clone();
        }

        self.reload(&mut state)
    }

    fn reload(&self, state: &mut ReloadingState) -> Arc<serde_json::Value> {
        let file = match std::fs::File::open(&self.path) {
            Ok(file) => file,
            Err(err) => {
                tracing::error!("Failed to read {}: {}", self.path.display(), err);
                return state.data.clone();
            }
        };

        // Cache the identity of the handle we actually parsed. If the path is
        // atomically replaced after the open, the next access sees the new
        // path identity and reloads instead of trusting this read.
        let attempted = match file.metadata() {
            Ok(metadata) => stat_identity(&metadata),
            Err(err) => {
                tracing::error!("Failed to read {}: {}", self.path.display(), err);
                return state.data.clone();
            }
        };

        let parsed: Result<serde_json::Value, _> =
            serde_json::from_reader(std::io::BufReader::new(file));
        let new_data = match parsed {
            Ok(value) => value,
            // A read failure is transient; a syntax error is an operator
            // mistake and must not be retried on every request.
            Err(err) if err.is_io() => {
                tracing::error!("Failed to read {}: {}", self.path.display(), err);
                return state.data.clone();
            }
            Err(err) => return self.reject(state, attempted, &err.to_string()),
        };

        if let Some(validator) = &self.validator {
            if let Err(message) = validator(&new_data) {
                return self.reject(state, attempted, &message);
            }
        }

        let data = Arc::new(new_data);
        state.data = data.clone();
        state.identity = Some(attempted);
        tracing::info!("Reloaded {}", self.path.display());
        data
    }

    /// Keep the last good document but record the rejected identity, so the
    /// same bad operator update is not reparsed and relogged on every request.
    /// Any in-place correction changes mtime/size; an atomic one changes the
    /// inode, so a fix is still picked up.
    fn reject(
        &self,
        state: &mut ReloadingState,
        attempted: FileIdentity,
        reason: &str,
    ) -> Arc<serde_json::Value> {
        state.identity = Some(attempted);
        tracing::error!(
            "Rejected invalid data in {}: {}",
            self.path.display(),
            reason
        );
        state.data.clone()
    }

    fn state(&self) -> std::sync::MutexGuard<'_, ReloadingState> {
        // A poisoned lock guards a plain cache, not an invariant worth
        // aborting the request over.
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, SystemTime};

    use serde_json::json;

    use super::*;

    struct Fixture {
        _dir: tempfile::TempDir,
        path: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let dir = tempfile::tempdir().expect("tempdir");
            let path = dir.path().join("data.json");
            Self { _dir: dir, path }
        }

        fn write(&self, body: &str) {
            std::fs::write(&self.path, body).expect("write");
        }

        fn mtime(&self) -> SystemTime {
            std::fs::metadata(&self.path)
                .expect("stat")
                .modified()
                .expect("mtime")
        }

        fn set_mtime(&self, when: SystemTime) {
            set_mtime(&self.path, when);
        }

        /// Replace the path with a fresh inode carrying `when` as its mtime.
        fn replace(&self, body: &str, when: SystemTime) {
            let tmp = self.path.with_extension("tmp");
            std::fs::write(&tmp, body).expect("write tmp");
            set_mtime(&tmp, when);
            std::fs::rename(&tmp, &self.path).expect("rename");
        }

        fn loader(&self, validator: Option<Validator>) -> ReloadingJson {
            ReloadingJson::new(self.path.clone(), json!({}), validator)
        }
    }

    fn set_mtime(path: &Path, when: SystemTime) {
        let file = std::fs::File::options()
            .write(true)
            .open(path)
            .expect("open");
        file.set_times(std::fs::FileTimes::new().set_modified(when))
            .expect("set_times");
    }

    #[test]
    fn returns_default_when_file_missing() {
        let fixture = Fixture::new();
        let loader = ReloadingJson::new(fixture.path.clone(), json!({"x": 1}), None);
        assert_eq!(*loader.get(), json!({"x": 1}));
    }

    #[test]
    fn loads_initial_content() {
        let fixture = Fixture::new();
        fixture.write(r#"{"hello": "world"}"#);
        assert_eq!(*fixture.loader(None).get(), json!({"hello": "world"}));
    }

    #[test]
    fn reloads_when_mtime_advances() {
        let fixture = Fixture::new();
        fixture.write(r#"{"v": 1}"#);
        let loader = fixture.loader(None);
        assert_eq!(*loader.get(), json!({"v": 1}));

        let later = fixture.mtime() + Duration::from_secs(1);
        fixture.write(r#"{"v": 2}"#);
        fixture.set_mtime(later);
        assert_eq!(*loader.get(), json!({"v": 2}));
    }

    #[test]
    fn does_not_reread_when_identity_unchanged() {
        let fixture = Fixture::new();
        fixture.write(r#"{"v": 1}"#);
        let loader = fixture.loader(None);
        loader.get();

        // Same inode, same size, same mtime: indistinguishable from the read.
        let before = fixture.mtime();
        fixture.write(r#"{"v": 2}"#);
        fixture.set_mtime(before);
        assert_eq!(*loader.get(), json!({"v": 1}));
    }

    #[test]
    fn reloads_equal_mtime_atomic_replacement() {
        let fixture = Fixture::new();
        fixture.write(r#"{"v": 1}"#);
        let loader = fixture.loader(None);
        assert_eq!(*loader.get(), json!({"v": 1}));

        fixture.replace(r#"{"v": 2}"#, fixture.mtime());
        assert_eq!(*loader.get(), json!({"v": 2}));
    }

    #[test]
    fn reloads_older_mtime_atomic_replacement() {
        let fixture = Fixture::new();
        fixture.write(r#"{"v": 1}"#);
        let loader = fixture.loader(None);
        assert_eq!(*loader.get(), json!({"v": 1}));

        let older = fixture.mtime() - Duration::from_secs(60);
        fixture.replace(r#"{"v": 2}"#, older);
        assert_eq!(*loader.get(), json!({"v": 2}));
    }

    #[test]
    fn keeps_last_good_value_when_file_disappears() {
        let fixture = Fixture::new();
        fixture.write(r#"{"v": 1}"#);
        let loader = ReloadingJson::new(fixture.path.clone(), json!({"sentinel": true}), None);
        loader.get();

        std::fs::remove_file(&fixture.path).expect("unlink");
        assert_eq!(*loader.get(), json!({"v": 1}));
    }

    #[test]
    fn keeps_last_good_value_on_invalid_json() {
        let fixture = Fixture::new();
        fixture.write(r#"{"v": 1}"#);
        let loader = fixture.loader(None);
        loader.get();

        let later = fixture.mtime() + Duration::from_secs(1);
        fixture.write("{not json");
        fixture.set_mtime(later);
        assert_eq!(*loader.get(), json!({"v": 1}));
    }

    #[test]
    fn keeps_last_good_value_on_schema_failure_without_reparsing() {
        let fixture = Fixture::new();
        fixture.write(r#"{"v": 1}"#);
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = calls.clone();
        let loader = fixture.loader(Some(Box::new(move |value: &serde_json::Value| {
            counter.fetch_add(1, Ordering::SeqCst);
            if value.is_object() {
                Ok(())
            } else {
                Err("expected an object".to_string())
            }
        })));
        assert_eq!(*loader.get(), json!({"v": 1}));
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        let later = fixture.mtime() + Duration::from_secs(1);
        fixture.write(r#"["syntactically-valid", "wrong-shape"]"#);
        fixture.set_mtime(later);
        assert_eq!(*loader.get(), json!({"v": 1}));
        assert_eq!(calls.load(Ordering::SeqCst), 2);

        // The rejected identity is remembered: no reparse, no repeated log.
        assert_eq!(*loader.get(), json!({"v": 1}));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn corrected_document_after_rejection_is_picked_up() {
        let fixture = Fixture::new();
        fixture.write(r#"["bad"]"#);
        let loader = fixture.loader(Some(Box::new(|value: &serde_json::Value| {
            if value.is_object() {
                Ok(())
            } else {
                Err("expected an object".to_string())
            }
        })));
        assert_eq!(*loader.get(), json!({}));

        let later = fixture.mtime() + Duration::from_secs(1);
        fixture.write(r#"{"v": 3}"#);
        fixture.set_mtime(later);
        assert_eq!(*loader.get(), json!({"v": 3}));
    }
}
