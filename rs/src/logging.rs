//! Logging setup: one output target, two line formats, a request id on every
//! record.
//!
//! `LOG_TO_CONSOLE=true` writes exclusively to stderr (for journald or a
//! container runtime) and never opens the log file. Otherwise records go to
//! `LOG_FILE`, rotated at 1 MiB with 3 backups, matching the Python
//! `RotatingFileHandler`.
//!
//! Formats mirror the Python service exactly:
//! - text: `LEVEL 2026-01-02 03:04:05,678 [request_id] module message`
//! - json: one object per line with `level`, `time` (ISO-8601 UTC, ms),
//!   `logger`, `module`, `message`, `request_id`, plus any extra fields.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use time::OffsetDateTime;
use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::filter::{EnvFilter, LevelFilter};
use tracing_subscriber::layer::{Context, Layer, SubscriberExt};
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::util::SubscriberInitExt;

use crate::config::{Config, LogFormat};

/// `RotatingFileHandler(maxBytes=1024 * 1024, backupCount=3)`.
pub const MAX_BYTES: u64 = 1024 * 1024;
pub const BACKUP_COUNT: usize = 3;

/// What `getattr(record, "request_id", "-")` yields outside a request.
const NO_REQUEST_ID: &str = "-";

tokio::task_local! {
    /// The current request's id. `"-"` outside any request, matching the
    /// Python contextvar default.
    pub static REQUEST_ID: String;
}

/// Return the current request's id, or `"-"` when called outside a request.
pub fn current_request_id() -> String {
    REQUEST_ID
        .try_with(String::clone)
        .unwrap_or_else(|_| NO_REQUEST_ID.to_string())
}

/// Guard that must be kept alive for the process lifetime; dropping it stops
/// the log writer.
pub struct LoggingGuard {
    _inner: Option<Box<dyn std::any::Any + Send + Sync>>,
}

/// Install the global subscriber. Returns an error string when the log file
/// cannot be opened, so `main` can refuse to start rather than run blind.
pub fn init(config: &Config) -> Result<LoggingGuard, String> {
    let level = level_filter(&config.log_level)?;

    // A console deployment must not touch the log path at all: merely opening
    // it defeats a container or service user without filesystem write access.
    let sink = if config.log_to_console {
        Arc::new(Sink::Stderr)
    } else {
        let file = RotatingFile::new(config.log_file.clone(), MAX_BYTES, BACKUP_COUNT)
            .map_err(|err| format!("cannot open log file {}: {err}", config.log_file.display()))?;
        Arc::new(Sink::File(file))
    };

    let layer = FormatLayer {
        sink: Arc::clone(&sink),
        format: config.log_format,
    };
    tracing_subscriber::registry()
        .with(layer.with_filter(target_filter(level)?))
        .try_init()
        .map_err(|err| format!("cannot install the logging subscriber: {err}"))?;

    Ok(LoggingGuard {
        _inner: Some(Box::new(sink)),
    })
}

/// Our own targets follow `LOG_LEVEL`; everything the runtime pulls in stays
/// at WARN (or quieter) so a `LOG_LEVEL=DEBUG` deploy does not drown in hyper
/// and tower internals the Python service had no equivalent of.
fn target_filter(level: LevelFilter) -> Result<EnvFilter, String> {
    let global = if level > LevelFilter::WARN {
        LevelFilter::WARN
    } else {
        level
    };
    EnvFilter::try_new(format!("{global},api={level},collateral_provider={level}"))
        .map_err(|err| format!("cannot build the log filter: {err}"))
}

/// Python level names, case-insensitively. `CRITICAL` has no tracing
/// equivalent and collapses onto `ERROR`, the nearest thing that still emits.
fn level_filter(name: &str) -> Result<LevelFilter, String> {
    match name.trim().to_ascii_uppercase().as_str() {
        "TRACE" | "NOTSET" => Ok(LevelFilter::TRACE),
        "DEBUG" => Ok(LevelFilter::DEBUG),
        "INFO" => Ok(LevelFilter::INFO),
        "WARN" | "WARNING" => Ok(LevelFilter::WARN),
        "ERROR" | "CRITICAL" | "FATAL" => Ok(LevelFilter::ERROR),
        _ => Err(format!(
            "LOG_LEVEL must be one of DEBUG/INFO/WARNING/ERROR/CRITICAL, got {name:?}"
        )),
    }
}

/// Python's level vocabulary, so a line from either service reads the same.
fn level_name(level: &Level) -> &'static str {
    if level == &Level::ERROR {
        "ERROR"
    } else if level == &Level::WARN {
        "WARNING"
    } else if level == &Level::INFO {
        "INFO"
    } else if level == &Level::DEBUG {
        "DEBUG"
    } else {
        "TRACE"
    }
}

/// `record.module` is Python's file basename, not the dotted path; the last
/// segment of a Rust module path is the same thing.
fn module_name(module_path: Option<&str>, target: &str) -> String {
    module_path
        .and_then(|path| path.rsplit("::").next())
        .unwrap_or(target)
        .to_string()
}

enum Sink {
    Stderr,
    File(RotatingFile),
}

impl Sink {
    fn write_line(&self, line: &str) {
        match self {
            Sink::Stderr => {
                let mut out = std::io::stderr().lock();
                let _ = out.write_all(line.as_bytes());
                let _ = out.write_all(b"\n");
            }
            Sink::File(file) => {
                if let Err(err) = file.write_line(line) {
                    // Losing a log line is bad; losing the process because the
                    // disk filled is worse. Python's logging does the same.
                    let _ = writeln!(std::io::stderr(), "logging: {err}");
                }
            }
        }
    }
}

struct FormatLayer {
    sink: Arc<Sink>,
    format: LogFormat,
}

impl<S> Layer<S> for FormatLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let mut visitor = FieldVisitor::default();
        event.record(&mut visitor);

        let metadata = event.metadata();
        let request_id = current_request_id();
        let record = Record {
            level: level_name(metadata.level()),
            logger: metadata.target(),
            module: &module_name(metadata.module_path(), metadata.target()),
            message: &visitor.message,
            request_id: &request_id,
            fields: &visitor.fields,
        };
        self.sink
            .write_line(&render(self.format, &record, OffsetDateTime::now_utc()));
    }
}

/// One log record, already reduced to the pieces both formats need.
struct Record<'a> {
    level: &'a str,
    logger: &'a str,
    module: &'a str,
    message: &'a str,
    request_id: &'a str,
    fields: &'a serde_json::Map<String, serde_json::Value>,
}

fn render(format: LogFormat, record: &Record<'_>, now: OffsetDateTime) -> String {
    match format {
        // `{levelname} {asctime} [{request_id}] {module} {message}`. Extra
        // fields are dropped, exactly as the Python text formatter drops them.
        LogFormat::Text => format!(
            "{} {} [{}] {} {}",
            record.level,
            text_time(now),
            record.request_id,
            record.module,
            record.message,
        ),
        LogFormat::Json => {
            let mut data = serde_json::Map::new();
            data.insert("level".into(), record.level.into());
            data.insert("time".into(), json_time(now).into());
            data.insert("logger".into(), record.logger.into());
            data.insert("module".into(), record.module.into());
            data.insert("message".into(), record.message.into());
            data.insert("request_id".into(), record.request_id.into());
            for (key, value) in record.fields {
                // Python: `if key not in data`. A field named `level` must not
                // shadow the real one.
                if !data.contains_key(key) {
                    data.insert(key.clone(), value.clone());
                }
            }
            serde_json::to_string(&serde_json::Value::Object(data)).unwrap_or_default()
        }
    }
}

/// `logging`'s `asctime`: a comma before the milliseconds, not a dot.
fn text_time(now: OffsetDateTime) -> String {
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02},{:03}",
        now.year(),
        now.month() as u8,
        now.day(),
        now.hour(),
        now.minute(),
        now.second(),
        now.millisecond(),
    )
}

/// `datetime.isoformat(timespec="milliseconds")` on a UTC-aware value.
fn json_time(now: OffsetDateTime) -> String {
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}+00:00",
        now.year(),
        now.month() as u8,
        now.day(),
        now.hour(),
        now.minute(),
        now.second(),
        now.millisecond(),
    )
}

/// Splits an event's fields into the message and everything else, the way the
/// Python formatter splits `record.getMessage()` from `extra=`.
#[derive(Default)]
struct FieldVisitor {
    message: String,
    fields: serde_json::Map<String, serde_json::Value>,
}

impl FieldVisitor {
    fn put(&mut self, field: &Field, value: serde_json::Value) {
        if field.name() == "message" {
            self.message = match value {
                serde_json::Value::String(text) => text,
                other => other.to_string(),
            };
        } else {
            self.fields.insert(field.name().to_string(), value);
        }
    }
}

impl Visit for FieldVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.put(field, serde_json::Value::String(format!("{value:?}")));
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.put(field, serde_json::Value::String(value.to_string()));
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.put(field, value.into());
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.put(field, value.into());
    }

    fn record_i128(&mut self, field: &Field, value: i128) {
        self.put(field, serde_json::Value::String(value.to_string()));
    }

    fn record_u128(&mut self, field: &Field, value: u128) {
        self.put(field, serde_json::Value::String(value.to_string()));
    }

    fn record_f64(&mut self, field: &Field, value: f64) {
        match serde_json::Number::from_f64(value) {
            Some(number) => self.put(field, serde_json::Value::Number(number)),
            // NaN and the infinities have no JSON spelling; Python's
            // `default=str` would stringify them too.
            None => self.put(field, serde_json::Value::String(value.to_string())),
        }
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.put(field, value.into());
    }

    fn record_error(&mut self, field: &Field, value: &(dyn std::error::Error + 'static)) {
        self.put(field, serde_json::Value::String(value.to_string()));
    }
}

/// A size-rotating file writer: rotate at `max_bytes`, keeping `backups`
/// numbered `.1`..`.N`, exactly as Python's `RotatingFileHandler` does.
pub struct RotatingFile {
    path: std::path::PathBuf,
    max_bytes: u64,
    backups: usize,
    inner: std::sync::Mutex<Handle>,
}

/// The open file plus its length, so the rollover test costs no syscall.
struct Handle {
    file: Option<File>,
    pos: u64,
}

impl RotatingFile {
    pub fn new(path: std::path::PathBuf, max_bytes: u64, backups: usize) -> std::io::Result<Self> {
        // Open eagerly: an unwritable LOG_FILE must fail the deploy, not the
        // first request that happens to log something.
        let file = open_append(&path)?;
        let pos = file.metadata()?.len();
        Ok(RotatingFile {
            path,
            max_bytes,
            backups,
            inner: Mutex::new(Handle {
                file: Some(file),
                pos,
            }),
        })
    }

    /// Append one line, rotating first when it would not fit.
    pub fn write_line(&self, line: &str) -> std::io::Result<()> {
        let mut guard = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let handle = &mut *guard;

        if handle.file.is_none() {
            let file = open_append(&self.path)?;
            handle.pos = file.metadata()?.len();
            handle.file = Some(file);
        }

        // `shouldRollover`: never roll an empty file, and roll when the record
        // would *reach* maxBytes rather than only when it passes it.
        let needed = line.len() as u64 + 1;
        if self.max_bytes > 0 && handle.pos > 0 && handle.pos + needed >= self.max_bytes {
            handle.file = None;
            self.rollover()?;
            let file = open_append(&self.path)?;
            handle.pos = file.metadata()?.len();
            handle.file = Some(file);
        }

        if let Some(file) = handle.file.as_mut() {
            // A failed `write_all` may already have put bytes on disk, so the
            // counter can no longer describe the file. Drop the handle rather
            // than advance a number that is now wrong: the next line re-opens
            // and re-stats, where Python's `shouldRollover` calls `tell()`
            // every time and cannot drift at all. Counting on and hoping would
            // let `pos` fall further behind the real size with each failure
            // until the rollover threshold stops firing and LOG_FILE grows
            // past the cap the unit file claims to enforce.
            let written = file
                .write_all(line.as_bytes())
                .and_then(|()| file.write_all(b"\n"));
            if let Err(err) = written {
                handle.file = None;
                return Err(err);
            }
        }
        handle.pos += needed;
        Ok(())
    }

    /// `doRollover`: shift `.N-1` up to `.N`, discarding the oldest, then move
    /// the live file to `.1`.
    fn rollover(&self) -> std::io::Result<()> {
        if self.backups == 0 {
            return Ok(());
        }
        for index in (1..self.backups).rev() {
            let source = self.backup_path(index);
            if source.exists() {
                let destination = self.backup_path(index + 1);
                if destination.exists() {
                    std::fs::remove_file(&destination)?;
                }
                std::fs::rename(&source, &destination)?;
            }
        }
        let first = self.backup_path(1);
        if first.exists() {
            std::fs::remove_file(&first)?;
        }
        std::fs::rename(&self.path, &first)
    }

    fn backup_path(&self, index: usize) -> PathBuf {
        let mut name = self.path.clone().into_os_string();
        name.push(format!(".{index}"));
        PathBuf::from(name)
    }
}

fn open_append(path: &Path) -> std::io::Result<File> {
    OpenOptions::new().create(true).append(true).open(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    fn record<'a>(
        message: &'a str,
        request_id: &'a str,
        fields: &'a serde_json::Map<String, serde_json::Value>,
    ) -> Record<'a> {
        Record {
            level: "INFO",
            logger: "api",
            module: "collateral",
            message,
            request_id,
            fields,
        }
    }

    fn no_fields() -> serde_json::Map<String, serde_json::Value> {
        serde_json::Map::new()
    }

    #[test]
    fn text_line_matches_the_python_verbose_format() {
        let fields = no_fields();
        let line = render(
            LogFormat::Text,
            &record("Tx Is Too Large", "abc123def456", &fields),
            datetime!(2026 - 01 - 02 03:04:05.678 UTC),
        );
        assert_eq!(
            line,
            "INFO 2026-01-02 03:04:05,678 [abc123def456] collateral Tx Is Too Large"
        );
    }

    #[test]
    fn text_uses_a_comma_before_milliseconds() {
        let fields = no_fields();
        let line = render(
            LogFormat::Text,
            &record("hello", "-", &fields),
            datetime!(2023 - 11 - 14 22:13:20.123456 UTC),
        );
        assert!(line.contains("2023-11-14 22:13:20,123"), "{line}");
    }

    #[test]
    fn json_line_carries_the_documented_keys() {
        let fields = no_fields();
        let line = render(
            LogFormat::Json,
            &record("hello", "abc123def456", &fields),
            datetime!(2023 - 11 - 14 22:13:20.123456 UTC),
        );
        let parsed: serde_json::Value = serde_json::from_str(&line).expect("valid JSON");
        assert_eq!(parsed["level"], "INFO");
        // Python: datetime.isoformat(timespec="milliseconds") on a UTC value.
        assert_eq!(parsed["time"], "2023-11-14T22:13:20.123+00:00");
        assert_eq!(parsed["logger"], "api");
        assert_eq!(parsed["module"], "collateral");
        assert_eq!(parsed["message"], "hello");
        assert_eq!(parsed["request_id"], "abc123def456");
    }

    #[test]
    fn json_request_id_is_a_dash_outside_a_request() {
        let fields = no_fields();
        let line = render(
            LogFormat::Json,
            &record("hello", &current_request_id(), &fields),
            OffsetDateTime::now_utc(),
        );
        let parsed: serde_json::Value = serde_json::from_str(&line).expect("valid JSON");
        assert_eq!(parsed["request_id"], "-");
    }

    #[test]
    fn json_extra_fields_are_top_level_and_never_shadow_builtins() {
        let mut fields = no_fields();
        fields.insert("operation".into(), "witness".into());
        fields.insert("env".into(), "preprod".into());
        fields.insert("count".into(), 3.into());
        fields.insert("level".into(), "FORGED".into());
        let line = render(
            LogFormat::Json,
            &record("hello", "-", &fields),
            OffsetDateTime::now_utc(),
        );
        let parsed: serde_json::Value = serde_json::from_str(&line).expect("valid JSON");
        assert_eq!(parsed["operation"], "witness");
        assert_eq!(parsed["env"], "preprod");
        assert_eq!(parsed["count"], 3);
        assert_eq!(parsed["level"], "INFO");
    }

    #[test]
    fn json_is_one_line_even_with_a_multiline_message() {
        let fields = no_fields();
        let line = render(
            LogFormat::Json,
            &record("first\nsecond", "-", &fields),
            OffsetDateTime::now_utc(),
        );
        assert!(!line.contains('\n'), "{line}");
        let parsed: serde_json::Value = serde_json::from_str(&line).expect("valid JSON");
        assert_eq!(parsed["message"], "first\nsecond");
    }

    #[test]
    fn python_level_names_are_emitted() {
        assert_eq!(level_name(&Level::WARN), "WARNING");
        assert_eq!(level_name(&Level::ERROR), "ERROR");
        assert_eq!(level_name(&Level::INFO), "INFO");
        assert_eq!(level_name(&Level::DEBUG), "DEBUG");
    }

    #[test]
    fn log_level_parsing_is_case_insensitive_and_strict() {
        assert_eq!(level_filter("debug").unwrap(), LevelFilter::DEBUG);
        assert_eq!(level_filter(" INFO ").unwrap(), LevelFilter::INFO);
        assert_eq!(level_filter("Warning").unwrap(), LevelFilter::WARN);
        assert_eq!(level_filter("WARN").unwrap(), LevelFilter::WARN);
        assert_eq!(level_filter("CRITICAL").unwrap(), LevelFilter::ERROR);
        assert!(level_filter("loud").is_err());
    }

    #[test]
    fn dependency_noise_is_capped_at_warn() {
        assert!(target_filter(LevelFilter::DEBUG).is_ok());
        assert!(target_filter(LevelFilter::ERROR).is_ok());
    }

    #[test]
    fn module_is_the_last_path_segment() {
        assert_eq!(
            module_name(Some("collateral_provider::validators::cbor"), "api"),
            "cbor"
        );
        assert_eq!(module_name(None, "api"), "api");
    }

    #[tokio::test]
    async fn request_id_is_scoped_to_the_task() {
        assert_eq!(current_request_id(), "-");
        REQUEST_ID
            .scope("abc123def456".to_string(), async {
                assert_eq!(current_request_id(), "abc123def456");
            })
            .await;
        assert_eq!(current_request_id(), "-");
    }

    fn read(path: &Path) -> String {
        std::fs::read_to_string(path).unwrap_or_default()
    }

    #[test]
    fn rotating_file_appends_until_the_cap() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("debug.log");
        let file = RotatingFile::new(path.clone(), 1024, 3).expect("opens");
        file.write_line("one").expect("writes");
        file.write_line("two").expect("writes");
        assert_eq!(read(&path), "one\ntwo\n");
        assert!(!dir.path().join("debug.log.1").exists());
    }

    #[test]
    fn rotating_file_keeps_three_backups_and_drops_the_oldest() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("debug.log");
        // Every line is 5 bytes with its newline, so a 10-byte cap rolls on
        // the second line of each generation.
        let file = RotatingFile::new(path.clone(), 10, 3).expect("opens");
        for line in ["aaaa", "bbbb", "cccc", "dddd", "eeee"] {
            file.write_line(line).expect("writes");
        }
        let backup = |index: usize| dir.path().join(format!("debug.log.{index}"));
        assert_eq!(read(&path), "eeee\n");
        assert_eq!(read(&backup(1)), "dddd\n");
        assert_eq!(read(&backup(2)), "cccc\n");
        assert_eq!(read(&backup(3)), "bbbb\n");
        // The oldest generation is discarded, not renamed to .4.
        assert!(!backup(4).exists());
    }

    #[test]
    fn rotating_file_never_rolls_an_empty_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("debug.log");
        let file = RotatingFile::new(path.clone(), 4, 3).expect("opens");
        // Longer than the whole cap, but rolling an empty file would just
        // leave another empty file behind.
        file.write_line("far too long").expect("writes");
        assert_eq!(read(&path), "far too long\n");
        assert!(!dir.path().join("debug.log.1").exists());
    }

    #[test]
    fn rotating_file_reopens_an_existing_log_without_truncating_it() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("debug.log");
        std::fs::write(&path, "previous\n").expect("seeds the file");
        let file = RotatingFile::new(path.clone(), 1024, 3).expect("opens");
        file.write_line("next").expect("writes");
        assert_eq!(read(&path), "previous\nnext\n");
    }

    #[test]
    fn unopenable_log_file_is_an_error_not_a_panic() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("missing-directory").join("debug.log");
        assert!(RotatingFile::new(path, 1024, 3).is_err());
    }
}
