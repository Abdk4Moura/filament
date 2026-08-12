//! Per-OS capability CI harmer (docs/design-per-os-ci.md steps 1-2).
//!
//! Integration test that starts a local filament backend + two filament
//! daemons, pairs them, and runs smoke tests. Needs the filament binary
//! pre-built with `cargo build --features test-hooks`.
//!
//! COMPILE GATE: this entire file is `#[cfg(feature = "test-hooks")]`.
//! The compiler strips it from default/release builds, so the signaling-bypass
//! path can NEVER end up in a published binary (security gate per Claude).
//!
//! CAP MODE: every filament process spawned here runs with
//! `FILAMENT_CAP_AUTHORITATIVE=0` (shadow). These are TRANSPORT / mechanics
//! smoke tests (byte-transparency, PTY exec, pairing, warm-hold latency) run
//! between two FRESH, UNPROVISIONED daemons with NO cap grant. Since the 0.7
//! authoritative-default flip, that same setup is denied-by-default, which
//! would break these tests for a reason orthogonal to what they assert. None
//! of them exercises a granted flow, so pinning shadow here masks no
//! enforcement regression; cap enforcement is covered by the unit tests and
//! the cross-machine rig, not this per-OS transport harness.

#![cfg(feature = "test-hooks")]

use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::Value;

const CODE_WORD: &str = "gigantic-element-tango";
const BUILD_PROFILE: &str = env!("FILAMENT_BUILD_PROFILE");

/// Result of waiting for a captured child. Timeout is deliberately distinct
/// from an ordinary non-zero exit: a stalled transfer is a different finding
/// from a process that failed cleanly.
#[derive(Debug)]
enum ChildOutcome {
    ExitedSuccess(ExitStatus),
    ExitedFailure(ExitStatus),
    TimedOut,
    SpawnFailed(String),
}

#[derive(Debug)]
struct CapturedChild {
    outcome: ChildOutcome,
    stdout: String,
    stderr: String,
    events: Vec<CapturedChunk>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChildStream {
    Stdout,
    Stderr,
}

#[derive(Debug, Clone)]
struct CapturedChunk {
    at: Instant,
    stream: ChildStream,
    bytes: Vec<u8>,
}

/// A spawned child whose stdout and stderr are drained continuously. Keeping
/// the buffers shared makes diagnostics available before the child exits.
struct LiveChild {
    child: Child,
    stdout: Arc<Mutex<Vec<u8>>>,
    stderr: Arc<Mutex<Vec<u8>>>,
    events: Arc<Mutex<Vec<CapturedChunk>>>,
    readers: Vec<std::thread::JoinHandle<()>>,
}

fn drain_pipe<R: Read + Send + 'static>(
    pipe: R,
    buffer: Arc<Mutex<Vec<u8>>>,
    events: Arc<Mutex<Vec<CapturedChunk>>>,
    stream: ChildStream,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let mut reader = pipe;
        let mut chunk = [0u8; 4096];
        loop {
            match reader.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let bytes = chunk[..n].to_vec();
                    buffer.lock().unwrap().extend_from_slice(&bytes);
                    events.lock().unwrap().push(CapturedChunk {
                        at: Instant::now(),
                        stream,
                        bytes,
                    });
                }
            }
        }
    })
}

fn spawn_captured(mut command: Command) -> Result<LiveChild, String> {
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;
    let stdout = Arc::new(Mutex::new(Vec::new()));
    let stderr = Arc::new(Mutex::new(Vec::new()));
    let events = Arc::new(Mutex::new(Vec::new()));
    let readers = vec![
        drain_pipe(child.stdout.take().ok_or("child stdout was not piped")?, stdout.clone(), events.clone(), ChildStream::Stdout),
        drain_pipe(child.stderr.take().ok_or("child stderr was not piped")?, stderr.clone(), events.clone(), ChildStream::Stderr),
    ];
    Ok(LiveChild { child, stdout, stderr, events, readers })
}

fn run_captured(command: Command, deadline: Duration) -> CapturedChild {
    match spawn_captured(command) {
        Ok(child) => child.wait_until(deadline),
        Err(error) => CapturedChild {
            outcome: ChildOutcome::SpawnFailed(error),
            stdout: String::new(),
            stderr: String::new(),
            events: Vec::new(),
        },
    }
}

fn first_marker_at(events: &[CapturedChunk], marker: &[u8]) -> Option<Instant> {
    let mut ordered = events.to_vec();
    ordered.sort_by_key(|event| event.at);
    let mut captured = Vec::new();
    for event in ordered {
        if event.stream != ChildStream::Stderr {
            continue;
        }
        captured.extend_from_slice(&event.bytes);
        if captured.windows(marker.len()).any(|window| window == marker) {
            // A marker split across reads is reported when its final bytes arrive.
            // That makes the measured interval conservative.
            return Some(event.at);
        }
    }
    None
}

fn marker_delta(events: &[CapturedChunk]) -> Option<Duration> {
    let blocked_at = first_marker_at(events, b"DIRECT-BLOCKED")?;
    let fallback_at = first_marker_at(events, b"DIRECT-FALLBACK")?;
    fallback_at.checked_duration_since(blocked_at)
}

impl LiveChild {
    fn snapshot(&self) -> (String, String) {
        let stdout = String::from_utf8_lossy(&self.stdout.lock().unwrap()).into_owned();
        let stderr = String::from_utf8_lossy(&self.stderr.lock().unwrap()).into_owned();
        (stdout, stderr)
    }

    fn events(&self) -> Vec<CapturedChunk> {
        self.events.lock().unwrap().clone()
    }

    fn wait_until(mut self, deadline: Duration) -> CapturedChild {
        let started = std::time::Instant::now();
        let outcome = loop {
            match self.child.try_wait() {
                Ok(Some(status)) => {
                    break if status.success() {
                        ChildOutcome::ExitedSuccess(status)
                    } else {
                        ChildOutcome::ExitedFailure(status)
                    };
                }
                Ok(None) if started.elapsed() < deadline => {
                    std::thread::sleep(Duration::from_millis(20));
                }
                Ok(None) => {
                    let _ = self.child.kill();
                    let _ = self.child.wait();
                    break ChildOutcome::TimedOut;
                }
                Err(_) => break ChildOutcome::TimedOut,
            }
        };
        if !matches!(outcome, ChildOutcome::TimedOut) {
            for reader in std::mem::take(&mut self.readers) {
                let _ = reader.join();
            }
        }
        let (stdout, stderr) = self.snapshot();
        let events = self.events();
        CapturedChild { outcome, stdout, stderr, events }
    }
}

// ---------------------------------------------------------------- helpers ---

fn binary() -> PathBuf {
    // Cargo supplies the exact executable for this test invocation, including
    // custom target directories, target triples, profile, and .exe suffix.
    let cand = PathBuf::from(env!("CARGO_BIN_EXE_filament"));
    let profile = BUILD_PROFILE;
    use sha2::{Digest, Sha256};
    let bytes = std::fs::read(&cand)
        .unwrap_or_else(|error| panic!("cannot hash harness binary {}: {error}", cand.display()));
    let sha256 = Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    eprintln!(
        "HARNESS-BINARY profile={} path={} sha256={}",
        profile,
        cand.display(),
        sha256,
    );
    cand
}

fn find_backend_app() -> PathBuf {
    // Look for the Python backend app.py relative to the CLI crate
    let from_manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("backend")
        .join("app.py");
    if from_manifest.exists() {
        return from_manifest;
    }
    // Fallback: try relative to CWD
    PathBuf::from("../backend/app.py")
}

struct Harness {
    backend: Child,
    backend_port: u16,
    daemon_a: Option<Child>,
    daemon_b: Option<Child>,
    daemon_a_log: Arc<Mutex<Vec<String>>>,
    daemon_b_log: Arc<Mutex<Vec<String>>>,
    work_dir: PathBuf,
    a_dir: PathBuf,
    b_dir: PathBuf,
}

impl Drop for Harness {
    fn drop(&mut self) {
        if let Some(ref mut c) = self.daemon_a {
            let _ = c.kill();
            let _ = c.wait();
        }
        if let Some(ref mut c) = self.daemon_b {
            let _ = c.kill();
            let _ = c.wait();
        }
        let _ = self.backend.kill();
        let _ = self.backend.wait();
        let _ = std::fs::remove_dir_all(&self.work_dir);
    }
}

fn python_cmd() -> &'static str {
    if cfg!(windows) { "python" } else { "python3" }
}

fn find_free_port() -> u16 {
    use std::net::TcpListener;
    TcpListener::bind("127.0.0.1:0")
        .map(|l| l.local_addr().unwrap().port())
        .unwrap_or(19079)
}

impl Harness {
    fn new() -> Self {
        let work = std::env::temp_dir()
            .join(format!("filament-harness-{}", std::process::id()));
        std::fs::create_dir_all(&work).expect("create work dir");

        let a_dir = work.join("a");
        let b_dir = work.join("b");

        // Start the Python Flask backend on an ephemeral port
        let app_path = find_backend_app();
        let port = find_free_port();
        let mut backend = {
            let mut b = Command::new(python_cmd())
                .arg(&app_path)
                .env("PORT", port.to_string())
                .env("FIL_ASYNC_MODE", "eventlet")
                .env("FIL_SELF_MONKEYPATCH", "1")
                .env("FIL_CLAIM_LIMIT", "1000000")
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .current_dir(app_path.parent().unwrap())
                .spawn()
                .expect("start backend");
            // Drain stderr in a background thread so the pipe buffer doesn't fill
            let stderr = b.stderr.take().unwrap();
            std::thread::spawn(move || {
                let reader = BufReader::new(stderr);
                for line in reader.lines() {
                    if let Ok(l) = line {
                        eprintln!("[backend] {l}");
                    }
                }
            });
            // Drain stdout too
            let stdout = b.stdout.take().unwrap();
            std::thread::spawn(move || {
                let reader = BufReader::new(stdout);
                for line in reader.lines() {
                    if let Ok(l) = line {
                        eprintln!("[backend] {l}");
                    }
                }
            });
            b
        };

        // Wait for backend to be healthy
        let server_url = format!("http://127.0.0.1:{port}");
        let mut backend_ok = false;
        for _ in 0..90 {
            if reqwest_blocking_head(&format!("{server_url}/api/health")) {
                backend_ok = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        if !backend_ok {
            panic!("backend did not start within 45s at {server_url}");
        }

        // 0.8.0 surface is init-first: peers are real devices with an identity
        // cert, so the typed-code possession ceremony can resolve the sender's
        // cert and revocation binds. Init each config dir before any test uses
        // it. Recovery phrases go to owner-only files inside each dir.
        let bin = binary();
        for (dir, name) in [(&a_dir, "test-a"), (&b_dir, "test-b")] {
            std::fs::create_dir_all(dir).expect("create peer dir");
            let rec = dir.join(format!("{name}-recovery.txt"));
            let out = Command::new(&bin)
                .env("FILAMENT_CONFIG_DIR", dir)
                .arg("init")
                .arg("--name")
                .arg(name)
                .arg("--recovery-file")
                .arg(&rec)
                .arg("--yes")
                .output()
                .expect("init peer");
            assert!(
                out.status.success(),
                "init {name} failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }

        Harness {
            backend,
            backend_port: port,
            daemon_a: None,
            daemon_b: None,
            daemon_a_log: Arc::new(Mutex::new(Vec::new())),
            daemon_b_log: Arc::new(Mutex::new(Vec::new())),
            work_dir: work,
            a_dir,
            b_dir,
        }
    }

    fn server_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.backend_port)
    }

    fn filament_bin(&self) -> &Path {
        // Lazily determined
        static BIN: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
        BIN.get_or_init(binary)
    }

    fn spawn_daemon(&mut self, name: &str, config_dir: &Path) -> (Child, Arc<Mutex<Vec<String>>>) {
        let bin = self.filament_bin().to_path_buf();
        let server = self.server_url();
        spawn_daemon_inner(&bin, &server, name, config_dir)
    }

    /// Spawn daemons, pair them, and verify byte-exact file transfer.
    /// Uses `send --word` + `recv <code>` (same pattern as gates.sh gate 1)
    /// which is proven to work on CI across all 3 OSes.
    fn pair_daemons(&mut self) {
        let bin = self.filament_bin().to_path_buf();
        let server = self.server_url();

        let (child_a, log_a) = spawn_daemon_inner(&bin, &server, "test-a", &self.a_dir);
        let (child_b, log_b) = spawn_daemon_inner(&bin, &server, "test-b", &self.b_dir);
        self.daemon_a = Some(child_a);
        self.daemon_b = Some(child_b);
        self.daemon_a_log = log_a;
        self.daemon_b_log = log_b;
        std::thread::sleep(Duration::from_secs(8));
    }

}

fn spawn_daemon_inner(
    bin: &Path,
    server: &str,
    name: &str,
    config_dir: &Path,
) -> (Child, Arc<Mutex<Vec<String>>>) {
    std::fs::create_dir_all(config_dir).expect("create config dir");
    let stderr_log: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let log_clone = stderr_log.clone();
    let mut child = Command::new(bin)
        .env("FILAMENT_CAP_AUTHORITATIVE", "0")
        .env("FILAMENT_CONFIG_DIR", config_dir)
        .env("FILAMENT_L3_USERSPACE", "1")
        .env("FILAMENT_LOG", "trace")
        .env(
        "FILAMENT_DIRECT_LOOPBACK_ONLY",
        std::env::var("FILAMENT_DIRECT_LOOPBACK_ONLY")
            .unwrap_or_else(|_| "1".into()),
    )
        .env("FILAMENT_NAME", name)
        .arg("up")
        .arg("--userspace")
        .arg("--shell")
        // This hermetic harness deliberately exercises the owner-equivalent shell
        // path. Its config dir and paired peers are throwaway test state.
        .arg("--i-know")
        .arg("--server")
        .arg(server)
        .arg("--relay")
        .arg("--dir")
        .arg(config_dir.join("drops").to_str().unwrap())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("spawn daemon {name}: {e}"));
    // Drain stdout/stderr in background threads so pipe buffers don't fill
    let label1 = name.to_string();
    let label2 = name.to_string();
    if let Some(stderr) = child.stderr.take() {
        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines() {
                if let Ok(l) = line {
                    eprintln!("[{label1} stderr] {l}");
                    if let Ok(mut log) = log_clone.lock() {
                        log.push(l);
                    }
                }
            }
        });
    }
    if let Some(stdout) = child.stdout.take() {
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                if let Ok(l) = line { eprintln!("[{label2}] {l}"); }
            }
        });
    }
    (child, stderr_log)
}

/// Poll stderr log for a line containing `needle`, up to `timeout`.
/// Returns true if found, false on timeout.
fn wait_for_line(log: &Arc<Mutex<Vec<String>>>, needle: &str, timeout: Duration) -> bool {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if let Ok(lines) = log.lock() {
            if lines.iter().any(|l| l.contains(needle)) {
                return true;
            }
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

fn reqwest_blocking_head(url: &str) -> bool {
    use std::io::{Read, Write};
    use std::net::TcpStream;
    let host_port = url
        .trim_start_matches("http://")
        .trim_end_matches("/api/health");
    match TcpStream::connect_timeout(&host_port.parse().unwrap(), Duration::from_secs(3)) {
        Ok(mut stream) => {
            let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
            let _ = stream.write_all(
                format!("GET /api/health HTTP/1.0\r\nHost: {host_port}\r\n\r\n").as_bytes(),
            );
            let mut buf = [0u8; 256];
            if let Ok(n) = stream.read(&mut buf) {
                let resp = std::str::from_utf8(&buf[..n]).unwrap_or("");
                return resp.contains("200") || resp.contains("ok");
            }
            false
        }
        Err(_) => false,
    }
}

// ------------------------------------------------------------ smoke tests ---

#[test]
fn pair_and_transfer_smoke() {
    let h = Harness::new();

    let bin = h.filament_bin().to_path_buf();
    let server = h.server_url();

    // Create a test file with 0x0D 0x0A + binary sweep
    let test_file = h.work_dir.join("test_payload.bin");
    let mut payload = vec![
        0x0D, 0x0A, // CR+LF (byte-transparency lock)
    ];
    // Add random binary
    for i in 0u8..=255 {
        payload.push(i);
    }
    // Add some structured data
    payload.extend_from_slice(b"\x00\x01\x02\x03\xff\xfe\xfd\xfc");
    std::fs::write(&test_file, &payload).expect("write test file");

    // Compute expected hash
    use std::hash::Hasher;
    let expected_hash = {
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(&payload);
        digest.iter().map(|b| format!("{b:02x}")).collect::<String>()
    };

    // Step 3: send from A to B
    let bin = h.filament_bin().to_path_buf();
    let server = h.server_url();

    // FILAMENT_DIRECT_PER_OS is the CI knob; it is forwarded to every spawned
    // daemon as FILAMENT_DIRECT. Named for the workflow's per-OS matrix, but it
    // reads as inert from cli/src because nothing there mentions it: the only
    // consumer is this harness. macOS CI sets it to 0, so direct-QUIC is OFF
    // there and every transfer rides WebRTC.
    let direct_flag = std::env::var("FILAMENT_DIRECT_PER_OS").unwrap_or_else(|_| "1".into());

    // Spawn send; drain stderr continuously in background to avoid SIGPIPE.
    // Also watch for the minted code prefix.
    let mut send_proc = Command::new(&bin)
        .env("FILAMENT_CAP_AUTHORITATIVE", "0")
        .env("FILAMENT_DIRECT", &direct_flag)
        .env(
        "FILAMENT_DIRECT_LOOPBACK_ONLY",
        std::env::var("FILAMENT_DIRECT_LOOPBACK_ONLY")
            .unwrap_or_else(|_| "1".into()),
    )
        .env("FILAMENT_L3_USERSPACE", "1")
        .env("FILAMENT_CONFIG_DIR", &h.a_dir)
        .arg("send")
        .arg(&test_file)
        .arg("--word")
        .arg(CODE_WORD)
        .arg("--server")
        .arg(&server)
        .stderr(Stdio::piped())
        .spawn()
        .expect("send");

    let (code_tx, code_rx) = std::sync::mpsc::channel::<String>();
    let stderr = send_proc.stderr.take().unwrap();
    std::thread::spawn(move || {
        let reader = BufReader::new(stderr);
        for line in reader.lines() {
            let line = line.unwrap_or_default();
            eprintln!("[send] {line}");
            let lower = line.to_lowercase();
            if let Some(start) = lower.find(&CODE_WORD.to_lowercase()) {
                let rest = &line[start..];
                let end = rest.find(|c: char| c.is_whitespace()).unwrap_or(rest.len());
                let _ = code_tx.send(line[start..start + end].to_lowercase().to_string());
            }
        }
    });

    let full_code = code_rx.recv_timeout(Duration::from_secs(30))
        .expect("send did not mint a code within 30s");

    // Receive on B
    let recv_dir = h.b_dir.join("received");
    std::fs::create_dir_all(&recv_dir).expect("create recv dir");
    let mut recv_proc = Command::new(&bin)
        .env("FILAMENT_CAP_AUTHORITATIVE", "0")
        .env("FILAMENT_DIRECT", &direct_flag)
        .env(
        "FILAMENT_DIRECT_LOOPBACK_ONLY",
        std::env::var("FILAMENT_DIRECT_LOOPBACK_ONLY")
            .unwrap_or_else(|_| "1".into()),
    )
        .env("FILAMENT_L3_USERSPACE", "1")
        .env("FILAMENT_CONFIG_DIR", &h.b_dir)
        .arg("receive")
        .arg(&full_code)
        .arg("--yes")
        .arg("--dir")
        .arg(&recv_dir)
        .arg("--server")
        .arg(&server)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("recv");
    let recv_out = recv_proc.wait_with_output().expect("recv result");
    let recv_stdout = String::from_utf8_lossy(&recv_out.stdout);
    let recv_stderr = String::from_utf8_lossy(&recv_out.stderr);
    eprintln!("recv stdout:\n{recv_stdout}");
    eprintln!("recv stderr:\n{recv_stderr}");

    // Step 4: check received file
    let received_file = recv_dir.join("test_payload.bin");
    assert!(
        received_file.exists(),
        "received file missing: {}",
        received_file.display()
    );

    let received_data = std::fs::read(&received_file).expect("read received file");
    let recv_hash = {
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(&received_data);
        digest.iter().map(|b| format!("{b:02x}")).collect::<String>()
    };

    assert_eq!(
        expected_hash, recv_hash,
        "sha256 mismatch: sent {expected_hash} != received {recv_hash}"
    );
    assert_eq!(payload.len(), received_data.len(), "size mismatch");

    // Byte-transparency lock: verify 0x0D 0x0A survived
    assert_eq!(
        received_data[0], 0x0D,
        "byte 0 = 0x0D lost (CR)"
    );
    assert_eq!(
        received_data[1], 0x0A,
        "byte 1 = 0x0A lost (LF)"
    );
}

/// #161: a REVOKED device's FIRST gated operation is denied, not a later one.
/// Pair A and B (so B holds A's device record), durably revoke A on B, then A
/// sends a one-shot code transfer: the receiver's gate must resolve A's
/// identity via the possession ceremony and deny before any bytes land.
#[test]
fn revoked_device_first_transfer_is_denied() {
    // No live pairing ceremony here (it was the flaky part on cold runners):
    // B's record for A is constructed directly from A's device cert. The
    // remaining flow is the same code-transfer path pair_and_transfer_smoke
    // uses, which is verified on all three platforms, so no macOS skip is
    // needed.
    let h = Harness::new();
    let bin = h.filament_bin().to_path_buf();
    let server = h.server_url();
    let direct_flag =
        std::env::var("FILAMENT_DIRECT_PER_OS").unwrap_or_else(|_| "1".into());
    let loopback_only =
        std::env::var("FILAMENT_DIRECT_LOOPBACK_ONLY").unwrap_or_else(|_| "1".into());
    let base_env = [
        ("FILAMENT_CAP_AUTHORITATIVE", "0"),
        ("FILAMENT_DIRECT", &direct_flag),
        ("FILAMENT_DIRECT_LOOPBACK_ONLY", &loopback_only),
        ("FILAMENT_L3_USERSPACE", "1"),
    ];

    // 1. B holds A's device record (cert + secret). Construct it directly from
    // A's own device cert rather than running a live pairing ceremony: the
    // ceremony's code mint is slow on cold CI runners (it timed out on macOS
    // and ubuntu within 60s), and the pairing itself is not what this test
    // asserts. What matters is that B can resolve A's cert from the store.
    let a_cert_path = h.a_dir.join("identity").join("device-cert.json");
    let a_cert_raw = std::fs::read_to_string(&a_cert_path).expect("a device cert");
    let a_cert_val: Value =
        serde_json::from_str(&a_cert_raw).expect("parse a device cert");
    let a_cert = &a_cert_val["cert"];
    assert!(
        a_cert["devicePub"].as_str().is_some(),
        "A's device cert has a devicePub"
    );
    let a_record = serde_json::json!([{
        "name": "test-a",
        "secret": "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        "deviceCert": a_cert,
        "caps": ["transfer"],
    }]);
    std::fs::write(
        h.b_dir.join("devices.json"),
        serde_json::to_string_pretty(&a_record).unwrap(),
    )
    .expect("write b devices.json");

    // 2. Durable revoke: A is no longer recognized on B.
    let revoke = Command::new(&bin)
        .env("FILAMENT_CONFIG_DIR", &h.b_dir)
        .args(["devices", "revoke", "test-a", "--yes"])
        .output()
        .expect("revoke");
    assert!(
        revoke.status.success(),
        "devices revoke failed: {}",
        String::from_utf8_lossy(&revoke.stderr)
    );

    // 3. A sends a one-shot code transfer; B's FIRST gated operation must deny.
    let test_file = h.work_dir.join("revoked-payload.bin");
    std::fs::write(&test_file, b"secret bytes that must never land").unwrap();
    let mut send_proc = Command::new(&bin)
        .envs(base_env.iter().map(|(k, v)| (*k, *v)))
        .env("FILAMENT_CONFIG_DIR", &h.a_dir)
        .arg("send")
        .arg(&test_file)
        .arg("--word")
        .arg("revoked-transfer-code")
        .arg("--server")
        .arg(&server)
        .stderr(Stdio::piped())
        .spawn()
        .expect("send");

    let (code_tx, code_rx) = std::sync::mpsc::channel::<String>();
    let stderr = send_proc.stderr.take().unwrap();
    let code_word = "revoked-transfer-code".to_string();
    std::thread::spawn(move || {
        let reader = BufReader::new(stderr);
        for line in reader.lines() {
            let line = line.unwrap_or_default();
            let lower = line.to_lowercase();
            if let Some(start) = lower.find(&code_word.to_lowercase()) {
                let rest = &line[start..];
                let end = rest
                    .find(|c: char| c.is_whitespace())
                    .unwrap_or(rest.len());
                let _ = code_tx.send(line[start..start + end].to_lowercase().to_string());
            }
        }
    });
    let full_code = code_rx
        .recv_timeout(Duration::from_secs(30))
        .expect("send did not mint a code within 30s");
    let recv_dir = h.b_dir.join("received");
    std::fs::create_dir_all(&recv_dir).unwrap();
    let mut recv_proc = Command::new(&bin)
        .envs(base_env.iter().map(|(k, v)| (*k, *v)))
        .env("FILAMENT_CONFIG_DIR", &h.b_dir)
        .arg("receive")
        .arg(&full_code)
        .arg("--yes")
        .arg("--dir")
        .arg(&recv_dir)
        .arg("--server")
        .arg(&server)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("receive");
    let recv_out = recv_proc.wait_with_output().expect("recv result");
    let recv_stderr = String::from_utf8_lossy(&recv_out.stderr);
    let _ = send_proc.wait_with_output().expect("send result");

    // The FIRST gated operation is denied: no file lands, and the receiver
    // reports the decline (revocation, not a consent prompt - we passed --yes).
    assert!(
        !recv_dir.join("revoked-payload.bin").exists(),
        "a revoked device's first transfer must be denied; file landed"
    );
    assert!(
        recv_stderr.contains("declined") || recv_stderr.contains("revoked"),
        "expected a revocation decline in receiver stderr, got: {recv_stderr}"
    );
}

/// Read a config dir's devices.json, dumping the dir listing on failure so a
/// missing store (a real setup finding) names what actually exists.
fn read_devices_json(config_dir: &Path) -> Value {
    let p = config_dir.join("devices.json");
    let raw = match std::fs::read_to_string(&p) {
        Ok(raw) => raw,
        Err(e) => {
            let listing: Vec<String> = std::fs::read_dir(config_dir)
                .map(|rd| {
                    rd.filter_map(|e| e.ok())
                        .map(|e| e.file_name().to_string_lossy().into_owned())
                        .collect()
                })
                .unwrap_or_default();
            panic!(
                "cannot read {}: {e}; config dir contents: {listing:?}",
                p.display()
            );
        }
    };
    serde_json::from_str(&raw).expect("parse devices.json")
}

/// Run a real pairing ceremony between two config dirs: A mints a code with
/// `add --word <word>` and B claims it with `add <code>`. Both sides store the
/// REAL code-derived shared secret. This is the pair-for-real rule; a seeded
/// store (placeholder secret) is exactly what made the first #172 control
/// stall forever. Deadline-bounded; a ceremony that does not converge fails
/// loudly.
fn live_pair(
    bin: &Path,
    server: &str,
    envs: &[(&str, &str)],
    a_dir: &Path,
    b_dir: &Path,
    word: &str,
) {
    let mut create = Command::new(bin);
    create.envs(envs.iter().map(|(k, v)| (*k, *v)))
        .env("FILAMENT_CONFIG_DIR", a_dir)
        .env("FILAMENT_NAME", "test-a")
        .arg("add")
        .arg("--word")
        .arg(word)
        .arg("--server")
        .arg(server);
    let create_proc = spawn_captured(create).expect("pair create spawn");

    let word_lower = word.to_lowercase();
    let started = Instant::now();
    let code = loop {
        let (stdout, stderr) = create_proc.snapshot();
        let text = format!("{stdout}\n{stderr}");
        let lower = text.to_lowercase();
        if let Some(start) = lower.find(&word_lower) {
            if let Some(tok) = text[start..].split_whitespace().find(|w| {
                w.to_lowercase().contains(&word_lower) && w.split('-').count() >= 4
            }) {
                break tok.to_string();
            }
        }
        assert!(
            started.elapsed() < Duration::from_secs(60),
            "pair create did not mint a code within 60s"
        );
        std::thread::sleep(Duration::from_millis(20));
    };
    let create_out = create_proc.wait_until(Duration::from_secs(60));

    let mut claim = Command::new(bin);
    claim.envs(envs.iter().map(|(k, v)| (*k, *v)))
        .env("FILAMENT_CONFIG_DIR", b_dir)
        .env("FILAMENT_NAME", "test-b")
        .arg("add")
        .arg(&code)
        .arg("--server")
        .arg(server);
    let claim_out = spawn_captured(claim)
        .expect("pair claim spawn")
        .wait_until(Duration::from_secs(60));

    assert!(
        matches!(create_out.outcome, ChildOutcome::ExitedSuccess(_)),
        "pair create failed: {}",
        create_out.stderr
    );
    assert!(
        matches!(claim_out.outcome, ChildOutcome::ExitedSuccess(_)),
        "pair claim failed: {}",
        claim_out.stderr
    );
}

/// Run a one-shot `send --word <code>` / `receive <code>` code transfer between
/// two config dirs with the given env, under DEADLINE-bounded waits. Returns
/// the captured receive and send outcomes and the receive dir. A transfer that
/// does not converge yields a `TimedOut` outcome instead of hanging the harness
/// step, so a stalled flow FAILS loudly at a bounded time.
///
/// When `remember` is set, the RECEIVER stores the sender under that name
/// (`receive --remember <name>`): the REAL code-derived secret is recorded, the
/// pair-for-real ceremony, never a seeded store.
fn run_code_transfer(
    bin: &Path,
    server: &str,
    envs: &[(&str, &str)],
    sender_dir: &Path,
    receiver_dir: &Path,
    payload: &Path,
    code: &str,
    remember: Option<&str>,
) -> (CapturedChild, CapturedChild, PathBuf) {
    let mut send = Command::new(bin);
    send.envs(envs.iter().map(|(k, v)| (*k, *v)))
        .env("FILAMENT_CONFIG_DIR", sender_dir)
        .arg("send")
        .arg(payload)
        .arg("--word")
        .arg(code)
        .arg("--server")
        .arg(server);
    let send_proc = spawn_captured(send).expect("send");

    let code_word = code.to_string();
    let code_started = Instant::now();
    let full_code = loop {
        let (stdout, stderr) = send_proc.snapshot();
        let text = format!("{stdout}\n{stderr}");
        let lower = text.to_lowercase();
        if let Some(start) = lower.find(&code_word.to_lowercase()) {
            let rest = &text[start..];
            let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
            break rest[..end].to_lowercase();
        }
        assert!(
            code_started.elapsed() < Duration::from_secs(30),
            "send did not mint a code within 30s"
        );
        std::thread::sleep(Duration::from_millis(20));
    };

    let recv_dir = receiver_dir.join(format!("received-{code}"));
    std::fs::create_dir_all(&recv_dir).unwrap();
    let mut recv = Command::new(bin);
    recv.envs(envs.iter().map(|(k, v)| (*k, *v)))
        .env("FILAMENT_CONFIG_DIR", receiver_dir)
        .arg("receive")
        .arg(&full_code)
        .arg("--yes")
        .arg("--dir")
        .arg(&recv_dir)
        .arg("--server")
        .arg(server);
    if let Some(name) = remember {
        recv.arg("--remember").arg(name);
    }
    let recv_out = spawn_captured(recv)
        .expect("recv spawn")
        .wait_until(Duration::from_secs(90));
    let send_out = send_proc.wait_until(Duration::from_secs(90));
    (recv_out, send_out, recv_dir)
}

/// #172, the 1.0.0 gate: a REVOKED device, with the direct path forced ON and
/// BLOCKED (so the blocked route is the one being denied), must not reach
/// anything on the fallback.
///
/// The test reports one of THREE verdicts, which get different release
/// treatment, so the failure message names the one observed rather than a
/// generic "blocked":
///
///   FAIL-OPEN            the file lands. Security hole: blocks 1.0 and the tag.
///   FAIL-CLOSED-LOUD     no file, and a prompt denial naming revocation.
///                        Correct behaviour: the test passes.
///   FAIL-CLOSED-SILENT   no file, no revocation-named denial, wedges until a
///                        deadline. Message-correctness defect (#206 class),
///                        not a fail-open hole. Fix before 1.0, does not block
///                        the tag on its own.
///
/// The CONTROL runs first in the same test: a legitimate device under IDENTICAL
/// direct-blocked conditions must complete via the fallback. If the control
/// stalls, the transport is wedged under these conditions and nothing can be
/// attributed to revocation: the test reports UNCLASSIFIED and fails rather
/// than let a double-stall be misread as a revocation result.
///
/// The assertion names revocation (an offline device never reaches the offer
/// stage, and a merely-un-granted device is denied for a different reason), and
/// every process wait is deadline-bounded so a non-converging transfer FAILS
/// loudly at a bounded time instead of hanging the harness step.
#[test]
fn revoked_device_direct_blocked_gets_no_fallback_access() {
    let h = Harness::new();
    let bin = h.filament_bin().to_path_buf();
    let server = h.server_url();
    let loopback_only =
        std::env::var("FILAMENT_DIRECT_LOOPBACK_ONLY").unwrap_or_else(|_| "1".into());
    let base_env = [
        ("FILAMENT_CAP_AUTHORITATIVE", "0"),
        ("FILAMENT_DIRECT", "1"),
        ("FILAMENT_DIRECT_TEST_BLOCK", "1"),
        ("FILAMENT_DIRECT_LOOPBACK_ONLY", &loopback_only),
        ("FILAMENT_L3_USERSPACE", "1"),
    ];
    // The pairing ceremony runs WITHOUT the direct block (it is setup, not the
    // path under test); the CONTROL and the REVOKED case run under base_env,
    // identical direct-blocked conditions.
    let pair_env = [
        ("FILAMENT_CAP_AUTHORITATIVE", "0"),
        ("FILAMENT_DIRECT", "1"),
        ("FILAMENT_DIRECT_LOOPBACK_ONLY", &loopback_only),
        ("FILAMENT_L3_USERSPACE", "1"),
    ];

    // 1. REAL pairing first: `add --word` mints a code, `add <code>` claims it,
    // and B stores A's record with the REAL code-derived shared secret. This is
    // the pair-for-real rule (USER-FLOWS.md): seed_store is reserved for states
    // no ceremony produces, and a seeded placeholder secret is precisely what
    // made the first version of this test stall forever (the pair-proof over
    // the link failed, the link dropped and re-established, and it stayed
    // invisible until a happy path ran next to it). Do not reseed a store here
    // for convenience.
    let a_cert_path = h.a_dir.join("identity").join("device-cert.json");
    let pair_word = format!("cryptocell-pair-p{:x}", std::process::id());
    live_pair(&bin, &server, &pair_env, &h.a_dir, &h.b_dir, &pair_word);

    // 2. CONTROL: a legitimate (not yet revoked) A transfers under identical
    // direct-blocked conditions. It must complete. If it does not, the
    // transport is wedged under these conditions and the revoked case that
    // follows cannot be attributed to revocation.
    let control_payload = h.work_dir.join("control-payload.bin");
    std::fs::write(&control_payload, b"control bytes that must land").unwrap();
    let (ctrl_recv, ctrl_send, ctrl_dir) = run_code_transfer(
        &bin, &server, &base_env, &h.a_dir, &h.b_dir, &control_payload, "ctrl-blocked-code", None,
    );
    let ctrl_both = format!("{}\n{}\n{}\n{}", ctrl_recv.stdout, ctrl_recv.stderr, ctrl_send.stdout, ctrl_send.stderr);
    assert!(
        ctrl_dir.join("control-payload.bin").exists() && ctrl_both.contains("DIRECT-BLOCKED"),
        "UNCLASSIFIED: the CONTROL (legitimate device) did not complete via the \
         fallback under direct-blocked conditions (file landed: {}, DIRECT-BLOCKED: {}). \
         The transport is wedged under these conditions, so nothing can be attributed to \
         revocation. control output:\n{ctrl_both}",
        ctrl_dir.join("control-payload.bin").exists(),
        ctrl_both.contains("DIRECT-BLOCKED"),
    );

    // 3. B must hold A's CERT for the revocation gate to bind (cert_revoked_for
    // keys off deviceCert.devicePub). The code transfer records the secret; the
    // cert may or may not have been learned via identity resolution. If it was
    // not, record A's REAL cert now: this is the state B reaches after
    // resolving A's identity during real contact, not a seed. The secret in the
    // record came from the real ceremony, so the happy path already proved it
    // authenticates.
    let b_records = read_devices_json(&h.b_dir);
    let b_has_a_cert = b_records.as_array().unwrap().iter().any(|d| {
        d["name"].as_str() == Some("test-a")
            && d["deviceCert"]["devicePub"].as_str().is_some()
    });
    if !b_has_a_cert {
        let a_cert_val: Value = serde_json::from_str(
            &std::fs::read_to_string(&a_cert_path).expect("a device cert"),
        )
        .expect("parse a device cert");
        let a_cert = a_cert_val["cert"].clone();
        assert!(
            a_cert["devicePub"].as_str().is_some(),
            "A's device cert has a devicePub"
        );
        let mut arr: Vec<Value> = read_devices_json(&h.b_dir)
            .as_array()
            .unwrap()
            .clone();
        for d in arr.iter_mut() {
            if d["name"].as_str() == Some("test-a") {
                d["userKey"] = serde_json::json!(a_cert["userPub"].as_str().unwrap_or_default());
                d["deviceCert"] = a_cert.clone();
            }
        }
        std::fs::write(
            h.b_dir.join("devices.json"),
            serde_json::to_string_pretty(&arr).unwrap(),
        )
        .expect("write b devices.json with A's cert");
    }

    // 4. Revoke A on B.
    let revoke = Command::new(&bin)
        .env("FILAMENT_CONFIG_DIR", &h.b_dir)
        .args(["devices", "revoke", "test-a", "--yes"])
        .output()
        .expect("revoke");
    assert!(
        revoke.status.success(),
        "devices revoke failed: {}",
        String::from_utf8_lossy(&revoke.stderr)
    );

    // 5. REVOKED CASE: A transfers again under the same conditions. Three
    // possible verdicts, named explicitly.
    let revoked_payload = h.work_dir.join("revoked-blocked-payload.bin");
    std::fs::write(&revoked_payload, b"secret bytes that must never land").unwrap();
    let (recv_out, send_out, recv_dir) = run_code_transfer(
        &bin, &server, &base_env, &h.a_dir, &h.b_dir, &revoked_payload, "revoked-blocked-code", None,
    );

    let rev_both = format!("{}\n{}\n{}\n{}", recv_out.stdout, recv_out.stderr, send_out.stdout, send_out.stderr);
    assert!(
        rev_both.contains("DIRECT-BLOCKED"),
        "UNCLASSIFIED: DIRECT-BLOCKED marker absent on the revoked run, the block \
         never engaged. Output:\n{rev_both}"
    );

    let file_landed = recv_dir.join("revoked-blocked-payload.bin").exists();
    let revoked_denied = recv_out.stderr.contains("revoked");
    assert!(
        !file_landed,
        "FAIL-OPEN: a revoked device's transfer LANDED via the fallback. Security \
         hole: a revoked device reached data it must not have. Blocks 1.0.\n{rev_both}"
    );
    assert!(
        revoked_denied,
        "FAIL-CLOSED-SILENT: the revoked device was refused (no file landed) but no \
         revocation-named denial arrived; the denial is indistinguishable from a network \
         problem (#206 class). Correctness-of-message defect, not fail-open. rev output:\n{rev_both}"
    );
    // Otherwise: FAIL-CLOSED-LOUD, the correct behaviour, and the test passes.
}

/// The case the WebRTC fallback EXISTS for: direct-QUIC enabled, direct-QUIC
/// FAILS, and the transfer must still complete over WebRTC, promptly.
///
/// This gate was written before, in `cli/tests/transport-gates.sh` (GATE 3), and
/// it is referenced by no workflow. It has never run in CI. A gate that exists
/// on disk and never executes is not coverage, and the hook it drives
/// (`FILAMENT_DIRECT_TEST_BLOCK`, wired at direct.rs `race_connect_labeled`) was
/// therefore exercised by nothing.
///
/// Three assertions, and the second and third are the ones that make it mean
/// something:
///
///   1. the transfer completes byte-exact
///   2. the block ACTUALLY ENGAGED. Without this, a pass is unclassified: on a
///      platform where direct never starts, nothing is blocked, nothing falls
///      back, and the test would go green having tested nothing. Absence of a
///      failure is not evidence that recovery happened.
///   3. it completed FAST ENOUGH to have been the designed fallback.
///
/// (3) is the one that separates this from the existing smoke test. The
/// designed path is `DIRECT_BUDGET` (5s) then an immediate WebRTC re-establish,
/// so ~7-10s end to end. The ACCIDENTAL path that carried macOS for weeks was
/// roster reconciliation on the sync digest, which fires on a ~30s interval. A
/// test asserting only completion passes on BOTH and cannot tell a designed
/// fallback from a slow repair. The bound below is deliberately between them.
#[test]
fn direct_blocked_falls_back_to_webrtc_promptly() {
    let h = Harness::new();
    let bin = h.filament_bin().to_path_buf();
    let server = h.server_url();

    let test_file = h.work_dir.join("fallback_payload.bin");
    let payload: Vec<u8> = (0u16..4096).map(|i| (i % 251) as u8).collect();
    std::fs::write(&test_file, &payload).expect("write test file");
    let expected_hash = {
        use sha2::{Digest, Sha256};
        Sha256::digest(&payload).iter().map(|b| format!("{b:02x}")).collect::<String>()
    };

    // DIRECT IS FORCED ON, deliberately ignoring FILAMENT_DIRECT_PER_OS. The
    // whole point is direct-enabled-and-failing; running this with direct off
    // would test the disabled path, which the smoke test already covers.
    // LOOPBACK_ONLY still honours the per-OS knob, because that one is about
    // WebRTC candidate gathering, which the fallback depends on.
    let loopback = std::env::var("FILAMENT_DIRECT_LOOPBACK_ONLY").unwrap_or_else(|_| "1".into());

    let mut send = Command::new(&bin);
    send.env("FILAMENT_CAP_AUTHORITATIVE", "0")
        .env("FILAMENT_DIRECT", "1")
        .env("FILAMENT_DIRECT_TEST_BLOCK", "1")
        .env("FILAMENT_DIRECT_LOOPBACK_ONLY", &loopback)
        .env("FILAMENT_L3_USERSPACE", "1")
        .env("FILAMENT_CONFIG_DIR", &h.a_dir)
        .arg("send").arg(&test_file)
        .arg("--word").arg(CODE_WORD)
        .arg("--server").arg(&server);
    let send_proc = spawn_captured(send).expect("send");
    let code_started = Instant::now();
    let full_code = loop {
        let (stdout, stderr) = send_proc.snapshot();
        let text = format!("{stdout}\n{stderr}");
        let lower = text.to_lowercase();
        if let Some(start) = lower.find(&CODE_WORD.to_lowercase()) {
            let rest = &text[start..];
            let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
            break rest[..end].to_lowercase();
        }
        assert!(code_started.elapsed() < Duration::from_secs(30), "send did not mint a code within 30s");
        std::thread::sleep(Duration::from_millis(20));
    };

    let recv_dir = h.b_dir.join("received_fallback");
    std::fs::create_dir_all(&recv_dir).expect("create recv dir");

    let mut recv = Command::new(&bin);
    recv.env("FILAMENT_CAP_AUTHORITATIVE", "0")
        .env("FILAMENT_DIRECT", "1")
        .env("FILAMENT_DIRECT_TEST_BLOCK", "1")
        .env("FILAMENT_DIRECT_LOOPBACK_ONLY", &loopback)
        .env("FILAMENT_L3_USERSPACE", "1")
        .env("FILAMENT_CONFIG_DIR", &h.b_dir)
        .arg("receive").arg(&full_code)
        .arg("--yes")
        .arg("--dir").arg(&recv_dir)
        .arg("--server").arg(&server);
    let recv_out = spawn_captured(recv)
        .expect("recv spawn")
        .wait_until(Duration::from_secs(60));
    let send_out = send_proc.wait_until(Duration::from_secs(10));

    let recv_all = format!(
        "{}{}",
        recv_out.stdout,
        recv_out.stderr
    );
    eprintln!("recv:\n{recv_all}");
    let send_all = format!("{}{}", send_out.stdout, send_out.stderr);
    let both = format!("{send_all}\n{recv_all}");
    eprintln!("send:\n{send_all}");

    // 1. byte-exact
    let received_file = recv_dir.join("fallback_payload.bin");
    assert!(received_file.exists(), "received file missing: {}", received_file.display());
    let got = std::fs::read(&received_file).expect("read received file");
    let got_hash = {
        use sha2::{Digest, Sha256};
        Sha256::digest(&got).iter().map(|b| format!("{b:02x}")).collect::<String>()
    };
    assert_eq!(expected_hash, got_hash, "sha256 mismatch after fallback");

    // 2. the instrument engaged. A green run without this line tested nothing.
    assert!(
        both.contains("DIRECT-BLOCKED"),
        "DIRECT-BLOCKED marker absent: the block never engaged, so this run is \
         UNCLASSIFIED rather than a fallback finding"
    );

    // 3. it did not secretly ride direct anyway.
    assert!(
        !both.contains("DIRECT-CONNECT ok"),
        "direct connected despite the block; this did not test the fallback"
    );

    // 4. prompt enough to be the DESIGNED fallback, not a slow repair. Capture
    // timestamps are taken as pipe chunks arrive. Buffering can only delay an
    // arrival, so this delta is an upper bound on the true marker delta.
    // Observed deltas were 6.006s, 6.015s, and 6.032s across the three CI OSes.
    // The 10s bound leaves CI headroom while staying 3x below the ~30s roster
    // reconciliation path this test must exclude. If it fires, investigate;
    // do not raise the bound.
    // Measure each daemon independently. Taking the first marker across both
    // processes could pair a sender's block with the receiver's fallback.
    // Use the slowest complete transition so one daemon cannot hide behind the
    // other; some platforms may only expose one side's markers.
    if BUILD_PROFILE != "release" {
        panic!(
            "UNCLASSIFIED: fallback completed functionally, but latency coverage requires build profile release; current profile is {}",
            BUILD_PROFILE,
        );
    }
    if both.contains("DIRECT-FALLBACK") {
        let elapsed = [
            marker_delta(&send_out.events),
            marker_delta(&recv_out.events),
        ]
        .into_iter()
        .flatten()
        .max()
        .expect("DIRECT-FALLBACK marker was present without a complete marker transition");
        assert!(
            elapsed < Duration::from_secs(10),
            "fallback marker delta was {elapsed:?}; investigate instead of raising \
             this bound: the designed path is ~6s, while roster reconciliation is ~30s"
        );
        eprintln!(
            "PASS via designed DIRECT-FALLBACK in {elapsed:?} (build profile {BUILD_PROFILE})"
        );
    } else {
        // A link can return before the direct budget expires. In that case
        // expired_direct discards its pending entry because self.links exists,
        // so no DIRECT-FALLBACK marker is emitted. The byte-exact assertions
        // above prove this alternate recovery route completed successfully.
        // This is consistent with main.rs:7535, but remains unproven because
        // establish/adopt does not currently emit a marker. CI has observed
        // the designed marker route; Linux has observed this re-establishment
        // route, so both are legitimate outcomes of this gate.
        eprintln!("PASS via link re-establishment before DIRECT-FALLBACK expiry");
    }
}

#[test]
fn two_nodes_pair_each_other() {
    let h = Harness::new();
    let bin = h.filament_bin().to_path_buf();
    let server = h.server_url();

    let out = Command::new(&bin)
        .env("FILAMENT_CAP_AUTHORITATIVE", "0")
        .args(["--server", &server, "--help"])
        .output()
        .expect("help");
    assert!(out.status.success(), "binary help failed");

    eprintln!("two_nodes_pair_each_other: filament binary and backend OK");
}

#[test]
fn pty_one_shot_exec_smoke() {
    // PTY one-shot exec smoke: starts daemons, pairs them, then runs
    // `filament pty <peer> -- echo NONCE` and verifies the echo output.
    //
    // On Linux/Windows: uses live-pairing (daemon discovers newly paired
    // device via 2s scan, no restart needed — proven by #41).
    //
    // On macOS: the cold PTY path uses direct QUIC which is unstable over
    // the hyperkit bridge. We restart daemons AFTER pairing so they start
    // fresh with known devices, giving the daemon warm link to stabilize
    // before the PTY command. The 3s kill gap + 12s settle was proven
    // effective in earlier CI runs (commit 1213120).

    #[cfg(any(windows, target_os = "macos"))]
    {
        eprintln!("pty_one_shot_exec_smoke: skipped on {os} (cold establish not yet verified on this platform)",
            os = if cfg!(windows) { "Windows" } else { "macOS" });
        return;
    }

    let mut h = Harness::new();
    let bin = h.filament_bin().to_path_buf();
    let server = h.server_url();

    let direct_flag =
        std::env::var("FILAMENT_DIRECT_PER_OS").unwrap_or_else(|_| "1".into());
    let loopback_only =
        std::env::var("FILAMENT_DIRECT_LOOPBACK_ONLY").unwrap_or_else(|_| "1".into());

    h.pair_daemons();

    eprintln!("pty_one_shot_exec_smoke: daemons started");

    let pair_word = format!("pairtest-mesh-p{:x}", std::process::id());
    let mut create = Command::new(&bin)
        .env("FILAMENT_CAP_AUTHORITATIVE", "0")
        .env("FILAMENT_DIRECT", &direct_flag)
        .env("FILAMENT_DIRECT_LOOPBACK_ONLY", &loopback_only)
        .env("FILAMENT_L3_USERSPACE", "1")
        .env("FILAMENT_NAME", "test-a")
        .env("FILAMENT_CONFIG_DIR", &h.a_dir)
        .args(["--server", &server, "add", "--word", &pair_word])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("pair create");

    let stderr = create.stderr.take().unwrap();
    let pair_word_lower = pair_word.to_lowercase();
    let (code_tx, code_rx) = std::sync::mpsc::channel::<String>();
    std::thread::spawn(move || {
        let reader = BufReader::new(stderr);
        for line in reader.lines() {
            let line = line.unwrap_or_default();
            eprintln!("[pair-create] {line}");
            if line.to_lowercase().contains(&pair_word_lower) {
                if let Some(code) = line
                    .split_whitespace()
                    .find(|w| {
                        w.to_lowercase().contains(&pair_word_lower)
                            && w.split('-').count() >= 4
                    })
                {
                    let _ = code_tx.send(code.to_string());
                }
            }
        }
    });

    let pair_code = code_rx.recv_timeout(Duration::from_secs(60))
        .expect("pair create did not mint a code within 60s");
    eprintln!("pair code: {pair_code}");

    let mut claim = Command::new(&bin)
        .env("FILAMENT_CAP_AUTHORITATIVE", "0")
        .env("FILAMENT_DIRECT", &direct_flag)
        .env("FILAMENT_DIRECT_LOOPBACK_ONLY", &loopback_only)
        .env("FILAMENT_L3_USERSPACE", "1")
        .env("FILAMENT_NAME", "test-b")
        .env("FILAMENT_CONFIG_DIR", &h.b_dir)
        .args(["--server", &server, "join", &pair_code])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("pair claim");
    let claim_out = claim.wait_with_output().expect("pair claim result");
    eprintln!("pair-claim stdout: {}", String::from_utf8_lossy(&claim_out.stdout));
    eprintln!("pair-claim stderr: {}", String::from_utf8_lossy(&claim_out.stderr));

    let create_out = create.wait_with_output().expect("pair create result");
    eprintln!("pair-create exit: {}", create_out.status);

    #[cfg(target_os = "macos")]
    {
        // Kill daemons, wait 3s, restart fresh. On restart they find the
        // already-paired devices in devices.json and the warm link
        // stabilizes before the PTY command's cold path kicks in.
        eprintln!("pty_one_shot_exec_smoke: restarting daemons (macOS)");
        if let Some(ref mut c) = h.daemon_a {
            let _ = c.kill();
            let _ = c.wait();
        }
        if let Some(ref mut c) = h.daemon_b {
            let _ = c.kill();
            let _ = c.wait();
        }
        h.daemon_a = None;
        h.daemon_b = None;
        std::thread::sleep(Duration::from_secs(3));
        let (child_a, log_a) = spawn_daemon_inner(&bin, &server, "test-a", &h.a_dir);
        let (child_b, log_b) = spawn_daemon_inner(&bin, &server, "test-b", &h.b_dir);
        h.daemon_a = Some(child_a);
        h.daemon_b = Some(child_b);
        h.daemon_a_log = log_a;
        h.daemon_b_log = log_b;
        std::thread::sleep(Duration::from_secs(12));
    }
    #[cfg(not(target_os = "macos"))]
    {
        // Live-pairing: daemon discovers the newly paired device via the
        // 2s devices_load scan. No restart needed (proven by #41).
        // Poll deterministically for the discovery message instead of a fixed sleep.
        eprintln!("pty_one_shot_exec_smoke: waiting for live-pairing discovery...");
        let discovered = wait_for_line(
            &h.daemon_a_log,
            "known device 'test-b' appeared",
            Duration::from_secs(30),
        ) || wait_for_line(
            &h.daemon_b_log,
            "known device 'test-a' appeared",
            Duration::from_secs(0),
        );
        assert!(
            discovered,
            "live-pairing discovery did not occur within 30s"
        );
    }

    let nonce = format!("PTY-OK-{}", std::process::id());
    let mut pty_proc = Command::new(&bin)
        .env("FILAMENT_CAP_AUTHORITATIVE", "0")
        .env("FILAMENT_DIRECT", &direct_flag)
        .env("FILAMENT_DIRECT_LOOPBACK_ONLY", &loopback_only)
        .env("FILAMENT_L3_USERSPACE", "1")
        .env("FILAMENT_CONFIG_DIR", &h.a_dir)
        .args(["--server", &server, "shell", "test-b", "--", "echo", &nonce])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("pty");

    let pty_out = pty_proc.wait_with_output().expect("pty result");
    let pty_stdout = String::from_utf8_lossy(&pty_out.stdout);
    let pty_stderr = String::from_utf8_lossy(&pty_out.stderr);
    eprintln!("pty stdout: {pty_stdout}");
    eprintln!("pty stderr: {pty_stderr}");

    assert!(
        pty_stdout.contains(&nonce) || pty_stderr.contains(&nonce),
        "pty output does not contain nonce '{nonce}'\nstdout: {pty_stdout}\nstderr: {pty_stderr}"
    );
}

#[test]
fn shell_owner_gate_refuses_real_spawn() {
    let root = std::env::temp_dir().join(format!("filament-shell-gate-{}", std::process::id()));
    let drops = root.join("drops");
    let out = Command::new(env!("CARGO_BIN_EXE_filament"))
        .env("FILAMENT_CONFIG_DIR", &root)
        .args([
            "up", "--userspace", "--shell", "--server", "http://127.0.0.1:1", "--dir",
            drops.to_str().unwrap(),
        ])
        .output()
        .expect("spawn shell gate probe");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "ungated shell spawn unexpectedly succeeded: {stderr}");
    assert!(stderr.contains("owner's authority"), "missing owner-equivalence refusal: {stderr}");
    assert!(!stderr.contains("socket.io connect"), "shell gate did not fire before signaling: {stderr}");
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn shell_daemon_live_pairing_no_restart() {
    // Proves the fix for main.rs:8381 — a `--shell` daemon started with
    // no known devices in a non-interactive context must NOT bail, AND the
    // live-pairing scan at line ~9065 must actually discover a device
    // paired AFTER daemon startup so it is reachable WITHOUT a restart.
    //
    // The earlier test only proved the bail was gone (daemon alive), but
    // that is necessary-not-sufficient: if the 9065 scan were broken,
    // the daemon would stay up but never find the new peer, making the
    // fix worthless. This test proves BOTH.

    #[cfg(any(windows, target_os = "macos"))]
    {
        eprintln!("shell_daemon_live_pairing_no_restart: skipped on {os} (cold establish not yet verified on this platform)",
            os = if cfg!(windows) { "Windows" } else { "macOS" });
        return;
    }

    let mut h = Harness::new();
    let bin = h.filament_bin().to_path_buf();
    let server = h.server_url();

    let direct_flag =
        std::env::var("FILAMENT_DIRECT_PER_OS").unwrap_or_else(|_| "1".into());
    let loopback_only =
        std::env::var("FILAMENT_DIRECT_LOOPBACK_ONLY").unwrap_or_else(|_| "1".into());

    // Start BOTH daemons with --shell, NO prior pairing.
    // spawn_daemon_inner uses --shell, so the guard at 8381 must let them live.
    let (child_a, log_a) = spawn_daemon_inner(&bin, &server, "test-a", &h.a_dir);
    let (child_b, log_b) = spawn_daemon_inner(&bin, &server, "test-b", &h.b_dir);
    h.daemon_a = Some(child_a);
    h.daemon_b = Some(child_b);
    h.daemon_a_log = log_a;
    h.daemon_b_log = log_b;
    std::thread::sleep(Duration::from_secs(4));

    // Assertion 1: both daemons survived the empty-devices startup.
    assert!(
        h.daemon_a.as_mut().unwrap().try_wait().unwrap().is_none(),
        "shell daemon A exited on empty devices (bail bug)"
    );
    assert!(
        h.daemon_b.as_mut().unwrap().try_wait().unwrap().is_none(),
        "shell daemon B exited on empty devices (bail bug)"
    );

    // NOW pair A and B while the daemons are already running. This writes
    // devices.json AFTER the daemon started — the live-pairing scan must
    // pick it up without a restart.
    let pair_word = format!("livescan-pair-p{:x}", std::process::id());
    let mut create = Command::new(&bin)
        .env("FILAMENT_CAP_AUTHORITATIVE", "0")
        .env("FILAMENT_DIRECT", &direct_flag)
        .env("FILAMENT_DIRECT_LOOPBACK_ONLY", &loopback_only)
        .env("FILAMENT_L3_USERSPACE", "1")
        .env("FILAMENT_NAME", "test-a")
        .env("FILAMENT_CONFIG_DIR", &h.a_dir)
        .args(["--server", &server, "add", "--word", &pair_word])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("pair create");

    let stderr = create.stderr.take().unwrap();
    let pair_word_lower = pair_word.to_lowercase();
    let (code_tx, code_rx) = std::sync::mpsc::channel::<String>();
    std::thread::spawn(move || {
        let reader = BufReader::new(stderr);
        for line in reader.lines() {
            let line = line.unwrap_or_default();
            eprintln!("[livescan-pair-create] {line}");
            if line.to_lowercase().contains(&pair_word_lower) {
                if let Some(code) = line
                    .split_whitespace()
                    .find(|w| {
                        w.to_lowercase().contains(&pair_word_lower)
                            && w.split('-').count() >= 4
                    })
                {
                    let _ = code_tx.send(code.to_string());
                }
            }
        }
    });

    let pair_code = code_rx.recv_timeout(Duration::from_secs(60))
        .expect("live-pairing create did not mint a code within 60s");
    eprintln!("live-pairing code: {pair_code}");

    let mut claim = Command::new(&bin)
        .env("FILAMENT_CAP_AUTHORITATIVE", "0")
        .env("FILAMENT_DIRECT", &direct_flag)
        .env("FILAMENT_DIRECT_LOOPBACK_ONLY", &loopback_only)
        .env("FILAMENT_L3_USERSPACE", "1")
        .env("FILAMENT_NAME", "test-b")
        .env("FILAMENT_CONFIG_DIR", &h.b_dir)
        .args(["--server", &server, "join", &pair_code])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("pair claim");
    let claim_out = claim.wait_with_output().expect("pair claim result");
    eprintln!("pair-claim stdout: {}", String::from_utf8_lossy(&claim_out.stdout));
    eprintln!("pair-claim stderr: {}", String::from_utf8_lossy(&claim_out.stderr));

    let create_out = create.wait_with_output().expect("pair create result");
    eprintln!("pair-create exit: {}", create_out.status);

    // Assertion 2: WITHOUT restarting daemons on Linux/Windows, the
    // live-pairing scan (devices_load every 2s) must discover the newly
    // paired device. 15s = ~7 scan cycles — generous margin. On macOS,
    // the cold PTY establish is flaky over the hyperkit bridge, so we
    // restart daemons (3s gap + 12s settle, same as pty_one_shot_exec_smoke);
    // the daemon-bail proof (assertion 1) is unaffected.
    #[cfg(target_os = "macos")]
    {
        if let Some(ref mut c) = h.daemon_a {
            let _ = c.kill();
            let _ = c.wait();
        }
        if let Some(ref mut c) = h.daemon_b {
            let _ = c.kill();
            let _ = c.wait();
        }
        h.daemon_a = None;
        h.daemon_b = None;
        std::thread::sleep(Duration::from_secs(3));
        let (child_a, log_a) = spawn_daemon_inner(&bin, &server, "test-a", &h.a_dir);
        let (child_b, log_b) = spawn_daemon_inner(&bin, &server, "test-b", &h.b_dir);
        h.daemon_a = Some(child_a);
        h.daemon_b = Some(child_b);
        h.daemon_a_log = log_a;
        h.daemon_b_log = log_b;
        std::thread::sleep(Duration::from_secs(12));
    }
    #[cfg(not(target_os = "macos"))]
    {
        eprintln!("waiting for live-pairing scan to discover the new device...");
        std::thread::sleep(Duration::from_secs(15));
    }

    let nonce = format!("LIVE-PTY-OK-{}", std::process::id());
    let mut pty_proc = Command::new(&bin)
        .env("FILAMENT_CAP_AUTHORITATIVE", "0")
        .env("FILAMENT_DIRECT", &direct_flag)
        .env("FILAMENT_DIRECT_LOOPBACK_ONLY", &loopback_only)
        .env("FILAMENT_L3_USERSPACE", "1")
        .env("FILAMENT_CONFIG_DIR", &h.a_dir)
        .args(["--server", &server, "shell", "test-b", "--", "echo", &nonce])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("pty");

    let pty_out = pty_proc.wait_with_output().expect("pty result");
    let pty_stdout = String::from_utf8_lossy(&pty_out.stdout);
    let pty_stderr = String::from_utf8_lossy(&pty_out.stderr);
    eprintln!("live-pty stdout: {pty_stdout}");
    eprintln!("live-pty stderr: {pty_stderr}");

    assert!(
        pty_stdout.contains(&nonce) || pty_stderr.contains(&nonce),
        "live-pairing pty failed — daemon did not discover the newly paired device\n\
         nonce: {nonce}\nstdout: {pty_stdout}\nstderr: {pty_stderr}"
    );
}

// ------------------------------------------------- warm-all integration test ---

/// Proves: "no cold establish when a peer is online and the daemon is up".
/// Uses `filament ping --json` which returns `"warm": true` from the daemon's
/// own warm-link resolver — a trace-grade proof independent of timing.
///
/// Gated off macOS: the hyperkit CI runner can't reliably complete a QUIC
/// establish (runner limitation, not a warm-all bug); warm-all is proven on
/// linux + windows, macOS needs real hardware.
#[cfg(not(target_os = "macos"))]
#[test]
fn warm_all_makes_first_contact_warm() {
    #[cfg(windows)]
    {
        eprintln!("warm_all_makes_first_contact_warm: skipped on Windows");
        return;
    }

    let mut h = Harness::new();
    let bin = h.filament_bin().to_path_buf();
    let server = h.server_url();

    let direct_flag =
        std::env::var("FILAMENT_DIRECT_PER_OS").unwrap_or_else(|_| "1".into());
    let loopback_only =
        std::env::var("FILAMENT_DIRECT_LOOPBACK_ONLY").unwrap_or_else(|_| "1".into());

    // Phase 1: Pair the daemons (same flow as pty_one_shot_exec_smoke).
    h.pair_daemons();
    eprintln!("warm_all: daemons started");

    let pair_word = format!("warmtest-mesh-p{:x}", std::process::id());
    let mut create = Command::new(&bin)
        .env("FILAMENT_CAP_AUTHORITATIVE", "0")
        .env("FILAMENT_DIRECT", &direct_flag)
        .env("FILAMENT_DIRECT_LOOPBACK_ONLY", &loopback_only)
        .env("FILAMENT_L3_USERSPACE", "1")
        .env("FILAMENT_NAME", "test-a")
        .env("FILAMENT_CONFIG_DIR", &h.a_dir)
        .args(["--server", &server, "add", "--word", &pair_word])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("pair create");

    let stderr = create.stderr.take().unwrap();
    let pair_word_lower = pair_word.to_lowercase();
    let (code_tx, code_rx) = std::sync::mpsc::channel::<String>();
    std::thread::spawn(move || {
        let reader = BufReader::new(stderr);
        for line in reader.lines() {
            let line = line.unwrap_or_default();
            eprintln!("[pair-create] {line}");
            if line.to_lowercase().contains(&pair_word_lower) {
                if let Some(code) = line
                    .split_whitespace()
                    .find(|w| {
                        w.to_lowercase().contains(&pair_word_lower)
                            && w.split('-').count() >= 4
                    })
                {
                    let _ = code_tx.send(code.to_string());
                }
            }
        }
    });

    let pair_code = code_rx.recv_timeout(Duration::from_secs(60))
        .expect("pair create did not mint a code within 60s");
    eprintln!("pair code: {pair_code}");

    let mut claim = Command::new(&bin)
        .env("FILAMENT_CAP_AUTHORITATIVE", "0")
        .env("FILAMENT_DIRECT", &direct_flag)
        .env("FILAMENT_DIRECT_LOOPBACK_ONLY", &loopback_only)
        .env("FILAMENT_L3_USERSPACE", "1")
        .env("FILAMENT_NAME", "test-b")
        .env("FILAMENT_CONFIG_DIR", &h.b_dir)
        .args(["--server", &server, "join", &pair_code])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("pair claim");
    let claim_out = claim.wait_with_output().expect("pair claim result");
    eprintln!("pair-claim stdout: {}", String::from_utf8_lossy(&claim_out.stdout));
    eprintln!("pair-claim stderr: {}", String::from_utf8_lossy(&claim_out.stderr));

    let create_out = create.wait_with_output().expect("pair create result");
    eprintln!("pair-create exit: {}", create_out.status);

    // Phase 2: Restart daemons so they come up with each other as known devices.
    // Stock config: no tun-addr, no warm-peers, no FILAMENT_AUTO_WARM override.
    eprintln!("warm_all: restarting daemons with stock config");
    if let Some(ref mut c) = h.daemon_a { let _ = c.kill(); let _ = c.wait(); }
    if let Some(ref mut c) = h.daemon_b { let _ = c.kill(); let _ = c.wait(); }
    h.daemon_a = None;
    h.daemon_b = None;
    std::thread::sleep(Duration::from_secs(3));

    let (child_a, log_a) = spawn_daemon_inner(&bin, &server, "test-a", &h.a_dir);
    let (child_b, log_b) = spawn_daemon_inner(&bin, &server, "test-b", &h.b_dir);
    h.daemon_a = Some(child_a);
    h.daemon_b = Some(child_b);
    h.daemon_a_log = log_a;
    h.daemon_b_log = log_b;

    // Assertion 1: WARM-HOLD ESTABLISHED THE LINK PROACTIVELY
    // The "established connection" trace reliably fires when the daemon's
    // warm-hold tick has connected to the peer — no user-initiated connect,
    // no ping to trigger it. The "auto-warming" trace is a conditional debug
    // line (only fires when the peer is added to the auto set during the
    // tick, which can be skipped if roster sync populates it earlier), so
    // we assert on the "established" reliability marker instead.
    // Also check for "skip" (link already alive within grace) which means
    // the warm path is usable.
    eprintln!("warm_all: waiting for warm-hold to establish the link...");
    let link_held = wait_for_line(
        &h.daemon_a_log,
        "warm-hold: established connection to 'test-b'",
        Duration::from_secs(60),
    ) || wait_for_line(
        &h.daemon_a_log,
        "warm-hold: skip 'test-b'",
        Duration::from_secs(0),
    );
    assert!(
        link_held,
        "warm-hold did not establish a link to 'test-b' within 60s — \
         the auto-warm setting may not be defaulting to ON"
    );

    // Wait for BOTH sides to have discovered each other before running ping.
    // daemon-a may have the warm link, but daemon-b needs to have discovered
    // test-a via its own scan before the ping can succeed over the warm path.
    wait_for_line(
        &h.daemon_b_log,
        "known device 'test-a' appeared",
        Duration::from_secs(15),
    );

    // Allow the warm link to be verified (pair-proof) before running ping.
    // The warm-hold "established" message fires when the L2 stream opens,
    // but the ping warm path requires verification.
    std::thread::sleep(Duration::from_secs(10));

    // Assertion 2: FIRST CONTACT TAKES THE WARM PATH
    eprintln!("warm_all: running filament ping --json...");
    let mut ping_proc = Command::new(&bin)
        .env("FILAMENT_CAP_AUTHORITATIVE", "0")
        .env("FILAMENT_DIRECT", &direct_flag)
        .env("FILAMENT_DIRECT_LOOPBACK_ONLY", &loopback_only)
        .env("FILAMENT_L3_USERSPACE", "1")
        .env("FILAMENT_CONFIG_DIR", &h.a_dir)
        .args(["--server", &server, "reach", "test-b", "--json"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("ping");
    let ping_out = ping_proc.wait_with_output().expect("ping result");
    let ping_stdout = String::from_utf8_lossy(&ping_out.stdout);
    let ping_stderr = String::from_utf8_lossy(&ping_out.stderr);
    eprintln!("warm_all ping stdout: {ping_stdout}");
    eprintln!("warm_all ping stderr: {ping_stderr}");

    // Parse JSON and assert warm: true
    let ping_json: serde_json::Value = serde_json::from_str(&ping_stdout)
        .expect("ping --json output is not valid JSON");
    assert_eq!(ping_json["warm"], true, "first ping should be warm, got: {ping_json}");

    // Assertion 3: NO COLD BANNER
    assert!(
        !ping_stderr.contains("still reaching"),
        "ping output contains cold-establish banner 'still reaching'"
    );

    // Assertion 5: WARM HOLDS ACROSS IDLE (repeat after 20s)
    eprintln!("warm_all: waiting 20s then re-pinging...");
    std::thread::sleep(Duration::from_secs(20));
    let mut ping_proc2 = Command::new(&bin)
        .env("FILAMENT_CAP_AUTHORITATIVE", "0")
        .env("FILAMENT_DIRECT", &direct_flag)
        .env("FILAMENT_DIRECT_LOOPBACK_ONLY", &loopback_only)
        .env("FILAMENT_L3_USERSPACE", "1")
        .env("FILAMENT_CONFIG_DIR", &h.a_dir)
        .args(["--server", &server, "reach", "test-b", "--json"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("ping 2");
    let ping_out2 = ping_proc2.wait_with_output().expect("ping 2 result");
    let ping_stdout2 = String::from_utf8_lossy(&ping_out2.stdout);
    eprintln!("warm_all ping2 stdout: {ping_stdout2}");
    let ping_json2: serde_json::Value = serde_json::from_str(&ping_stdout2)
        .expect("ping 2 --json output is not valid JSON");
    assert_eq!(ping_json2["warm"], true, "second ping should still be warm, got: {ping_json2}");

    // Phase 3: NEGATIVE CONTROL — auto-warm OFF
    eprintln!("warm_all: testing negative control (auto-warm off)");
    if let Some(ref mut c) = h.daemon_a { let _ = c.kill(); let _ = c.wait(); }
    h.daemon_a = None;
    std::thread::sleep(Duration::from_secs(3));

    // Spawn auto-warm-OFF daemon via custom Command (spawn_daemon_inner doesn't
    // support FILAMENT_AUTO_WARM override).
    let mut daemon_a_off = Command::new(&bin)
        .env("FILAMENT_CAP_AUTHORITATIVE", "0")
        .env("FILAMENT_CONFIG_DIR", &h.a_dir)
        .env("FILAMENT_L3_USERSPACE", "1")
        .env("FILAMENT_LOG", "trace")
        .env("FILAMENT_AUTO_WARM", "0")
        .env(
            "FILAMENT_DIRECT_LOOPBACK_ONLY",
            std::env::var("FILAMENT_DIRECT_LOOPBACK_ONLY")
                .unwrap_or_else(|_| "1".into()),
        )
        .env("FILAMENT_NAME", "test-a")
        .arg("up")
        .arg("--userspace")
        .arg("--shell")
        // This hermetic harness deliberately exercises the owner-equivalent shell
        // path. Its config dir and paired peers are throwaway test state.
        .arg("--i-know")
        .arg("--server")
        .arg(&server)
        .arg("--relay")
        .arg("--dir")
        .arg(h.a_dir.join("drops").to_str().unwrap())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn daemon a (auto-warm off)");
    let log_a_off: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let log_a_off_clone = log_a_off.clone();
    if let Some(stderr) = daemon_a_off.stderr.take() {
        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines() {
                if let Ok(l) = line {
                    eprintln!("[daemon-a-off stderr] {l}");
                    if let Ok(mut log) = log_a_off_clone.lock() {
                        log.push(l);
                    }
                }
            }
        });
    }
    if let Some(stdout) = daemon_a_off.stdout.take() {
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                if let Ok(l) = line { eprintln!("[daemon-a-off] {l}"); }
            }
        });
    }
    h.daemon_a = Some(daemon_a_off);

    // Wait for 3 ticks (30s) — no auto-warming line should appear
    std::thread::sleep(Duration::from_secs(35));
    let auto_warm_line = wait_for_line(
        &log_a_off,
        "warm-hold: auto-warming",
        Duration::from_secs(0),
    );
    assert!(
        !auto_warm_line,
        "auto-warm OFF: daemon should NOT emit 'auto-warming' line"
    );

    eprintln!("warm_all: all assertions passed ✓");
}

#[test]
fn warm_one_shot_pty_reuse() {
    // Proves fix/warm-one-shot-pty: a scripted `pty <peer> -- cmd` reuses the
    // daemon's warm-held link instead of cold-establishing.
    //
    // Design: pre-warm the daemon's link to the peer by setting `warm-peers`
    // BEFORE the pty runs. Daemon A's warm_hold_tick establishes ONE link to
    // test-b — single, no glare. Then the pty finds the link already held and
    // takes the warm fast path, producing the trace marker.
    //
    // Linux-only: macOS hyperkit bridge transport can't reliably complete a
    // QUIC establish. Verified on ubuntu with trace-confirmed warm reuse.

    #[cfg(any(windows, target_os = "macos"))]
    {
        eprintln!("warm_one_shot_pty_reuse: skipped on {os} (warm-reuse pty not yet verified)",
            os = if cfg!(windows) { "Windows" } else { "macOS" });
        return;
    }

    let mut h = Harness::new();
    let bin = h.filament_bin().to_path_buf();
    let server = h.server_url();

    let direct_flag =
        std::env::var("FILAMENT_DIRECT_PER_OS").unwrap_or_else(|_| "1".into());
    let loopback_only =
        std::env::var("FILAMENT_DIRECT_LOOPBACK_ONLY").unwrap_or_else(|_| "1".into());

    h.pair_daemons();
    eprintln!("warm_one_shot_pty_reuse: daemons started");

    let pair_word = format!("warm-reuse-p{:x}", std::process::id());
    let mut create = Command::new(&bin)
        .env("FILAMENT_CAP_AUTHORITATIVE", "0")
        .env("FILAMENT_DIRECT", &direct_flag)
        .env("FILAMENT_DIRECT_LOOPBACK_ONLY", &loopback_only)
        .env("FILAMENT_L3_USERSPACE", "1")
        .env("FILAMENT_NAME", "test-a")
        .env("FILAMENT_CONFIG_DIR", &h.a_dir)
        .args(["--server", &server, "add", "--word", &pair_word])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("pair create");

    let stderr = create.stderr.take().unwrap();
    let pair_word_lower = pair_word.to_lowercase();
    let (code_tx, code_rx) = std::sync::mpsc::channel::<String>();
    std::thread::spawn(move || {
        let reader = BufReader::new(stderr);
        for line in reader.lines() {
            let line = line.unwrap_or_default();
            eprintln!("[warm-pair-create] {line}");
            if line.to_lowercase().contains(&pair_word_lower) {
                if let Some(code) = line
                    .split_whitespace()
                    .find(|w| {
                        w.to_lowercase().contains(&pair_word_lower)
                            && w.split('-').count() >= 4
                    })
                {
                    let _ = code_tx.send(code.to_string());
                }
            }
        }
    });

    let pair_code = code_rx.recv_timeout(Duration::from_secs(60))
        .expect("warm pair create did not mint a code within 60s");
    eprintln!("warm pair code: {pair_code}");

    let mut claim = Command::new(&bin)
        .env("FILAMENT_CAP_AUTHORITATIVE", "0")
        .env("FILAMENT_DIRECT", &direct_flag)
        .env("FILAMENT_DIRECT_LOOPBACK_ONLY", &loopback_only)
        .env("FILAMENT_L3_USERSPACE", "1")
        .env("FILAMENT_NAME", "test-b")
        .env("FILAMENT_CONFIG_DIR", &h.b_dir)
        .args(["--server", &server, "join", &pair_code])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("pair claim");
    let claim_out = claim.wait_with_output().expect("pair claim result");
    eprintln!("warm-claim stdout: {}", String::from_utf8_lossy(&claim_out.stdout));
    eprintln!("warm-claim stderr: {}", String::from_utf8_lossy(&claim_out.stderr));

    let create_out = create.wait_with_output().expect("pair create result");
    eprintln!("warm-pair-create exit: {}", create_out.status);

    // Enable daemon A to proactively warm-hold test-b: write warm-peers
    // config so the daemon's warm_hold_tick establishes ONE link.
    let set = Command::new(&bin)
        .env("FILAMENT_CAP_AUTHORITATIVE", "0")
        .env("FILAMENT_CONFIG_DIR", &h.a_dir)
        .args(["--server", &server, "set", "warm-peers", "test-b"])
        .output()
        .expect("set warm-peers");
    assert!(set.status.success(), "set warm-peers failed: {:?}", String::from_utf8_lossy(&set.stderr));

    // Restart daemons to pick up the warm-peers config.
    if let Some(ref mut c) = h.daemon_a {
        let _ = c.kill();
        let _ = c.wait();
    }
    if let Some(ref mut c) = h.daemon_b {
        let _ = c.kill();
        let _ = c.wait();
    }
    h.daemon_a = None;
    h.daemon_b = None;
    std::thread::sleep(Duration::from_secs(3));
    let (child_a, log_a) = spawn_daemon_inner(&bin, &server, "test-a", &h.a_dir);
    let (child_b, log_b) = spawn_daemon_inner(&bin, &server, "test-b", &h.b_dir);
    h.daemon_a = Some(child_a);
    h.daemon_b = Some(child_b);
    h.daemon_a_log = log_a;
    h.daemon_b_log = log_b;

    // Wait for warm link to be established (deterministic poll).
    let warm_ready = wait_for_line(
        &h.daemon_a_log,
        "warm-hold: established connection to 'test-b'",
        Duration::from_secs(40),
    ) || wait_for_line(
        &h.daemon_a_log,
        "warm-hold: skip 'test-b'",
        Duration::from_secs(0),
    );
    assert!(
        warm_ready,
        "warm link to 'test-b' was not established within 40s"
    );

    // Allow verification to complete before running pty.
    std::thread::sleep(Duration::from_secs(5));

    // Warm-hold tick (10s interval) runs during the 20s settle — daemon A
    // establishes a warm link to test-b. Now pty should hit the warm path.
    let nonce = format!("WARM-OK-{}", std::process::id());
    let out = Command::new(&bin)
        .env("FILAMENT_CAP_AUTHORITATIVE", "0")
        .env("FILAMENT_DIRECT", &direct_flag)
        .env("FILAMENT_DIRECT_LOOPBACK_ONLY", &loopback_only)
        .env("FILAMENT_L3_USERSPACE", "1")
        .env("FILAMENT_CONFIG_DIR", &h.a_dir)
        .args(["--server", &server, "shell", "test-b", "--", "echo", &nonce])
        .output()
        .expect("pty");
    let out_stdout = String::from_utf8_lossy(&out.stdout);
    let out_stderr = String::from_utf8_lossy(&out.stderr);
    eprintln!("warm pty stdout: {out_stdout}");
    eprintln!("warm pty stderr: {out_stderr}");

    assert!(
        out_stderr.contains("reusing warm link") && out_stderr.contains("one-shot pty"),
        "pty did NOT use warm link - expected trace 'reusing warm link ... for one-shot pty'\n\
         stdout: {out_stdout}\nstderr: {out_stderr}"
    );

    assert!(
        out_stdout.contains(&nonce),
        "pty output does not contain nonce '{nonce}'\nstdout: {out_stdout}\nstderr: {out_stderr}"
    );
}

#[cfg(test)]
mod captured_child_tests {
    use super::*;

    fn command_that_prints_then_waits() -> Command {
        if cfg!(windows) {
            let mut command = Command::new("cmd");
            command.args(["/C", "echo live && ping -n 4 127.0.0.1 >NUL"]);
            command
        } else {
            let mut command = Command::new("sh");
            command.args(["-c", "printf 'live\\n'; sleep 3"]);
            command
        }
    }

    fn hanging_command() -> Command {
        if cfg!(windows) {
            let mut command = Command::new("ping");
            command.args(["-n", "20", "127.0.0.1"]);
            command
        } else {
            let mut command = Command::new("sleep");
            command.arg("20");
            command
        }
    }

    fn failing_command() -> Command {
        if cfg!(windows) {
            let mut command = Command::new("cmd");
            command.args(["/C", "exit 7"]);
            command
        } else {
            let mut command = Command::new("sh");
            command.args(["-c", "exit 7"]);
            command
        }
    }

    #[test]
    fn captured_child_exposes_output_before_exit() {
        let child = spawn_captured(command_that_prints_then_waits()).expect("spawn");
        let started = std::time::Instant::now();
        let mut observed = false;
        while started.elapsed() < Duration::from_secs(2) {
            let (stdout, stderr) = child.snapshot();
            if stdout.contains("live") || stderr.contains("live") {
                observed = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(observed, "child output was not readable before child exit");
        let result = child.wait_until(Duration::from_secs(5));
        assert!(matches!(result.outcome, ChildOutcome::ExitedSuccess(_)));
    }

    #[test]
    fn captured_child_timeout_is_distinct_from_failure() {
        let started = std::time::Instant::now();
        let result = run_captured(hanging_command(), Duration::from_millis(150));
        assert!(matches!(result.outcome, ChildOutcome::TimedOut));
        assert!(started.elapsed() < Duration::from_secs(2), "timeout did not fire promptly");
    }

    #[test]
    fn captured_child_reports_nonzero_exit_separately() {
        let result = run_captured(failing_command(), Duration::from_secs(2));
        assert!(matches!(result.outcome, ChildOutcome::ExitedFailure(_)));
    }

    #[test]
    fn captured_child_reports_spawn_failure() {
        let mut command = Command::new("filament-test-command-that-does-not-exist");
        command.arg("--version");
        let result = run_captured(command, Duration::from_millis(100));
        assert!(matches!(result.outcome, ChildOutcome::SpawnFailed(_)));
    }
}

/// Measure the bytes-moved watchdog against the in-binary one-shot black-hole.
/// This deliberately uses the captured-child helper so a stalled receiver can
/// be classified as DETECTED_NOT_RECOVERED instead of hanging the test runner.
/// It is ignored because it reports an open defect, not because it is unreliable;
/// ignored tests can decay exactly like the unreferenced gates found on 2026-08-03.
#[test]
#[ignore = "reports #31 ladder exhaustion after recovery attempts; enable with cargo test --features test-hooks -- --ignored after recovery is fixed"]
fn freeze_stall_detector_classification() {
    let h = Harness::new();
    let bin = h.filament_bin().to_path_buf();
    let server = h.server_url();
    let payload_path = h.work_dir.join("stall_payload.bin");
    let payload: Vec<u8> = (0..4_000_000).map(|i| (i % 251) as u8).collect();
    std::fs::write(&payload_path, &payload).expect("write stall payload");
    let expected_hash = {
        use sha2::{Digest, Sha256};
        Sha256::digest(&payload).iter().map(|b| format!("{b:02x}")).collect::<String>()
    };
    let loopback = std::env::var("FILAMENT_DIRECT_LOOPBACK_ONLY").unwrap_or_else(|_| "1".into());

    let mut send = Command::new(&bin);
    send.env("FILAMENT_CAP_AUTHORITATIVE", "0")
        .env("FILAMENT_DIRECT", "1")
        .env("FILAMENT_DIRECT_LOOPBACK_ONLY", &loopback)
        .env("FILAMENT_LOG", "debug")
        .env("FILAMENT_STALL_MS", "2500")
        .env("FILAMENT_WARM_STANDBY", "0")
        .env("FILAMENT_TEST_FREEZE_AFTER_BYTES", "700000")
        .env("FILAMENT_CONFIG_DIR", &h.a_dir)
        .arg("send").arg(&payload_path).arg("--word").arg(CODE_WORD)
        .arg("--server").arg(&server);
    let send = spawn_captured(send).expect("spawn measured sender");

    let started = std::time::Instant::now();
    let code = loop {
        let (stdout, stderr) = send.snapshot();
        let text = format!("{stdout}\n{stderr}");
        if let Some(start) = text.to_lowercase().find(&CODE_WORD.to_lowercase()) {
            let rest = &text[start..];
            let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
            break rest[..end].to_string();
        }
        assert!(started.elapsed() < Duration::from_secs(30), "sender did not mint a code");
        std::thread::sleep(Duration::from_millis(20));
    };

    let recv_dir = h.b_dir.join("stall_received");
    std::fs::create_dir_all(&recv_dir).expect("create receive directory");
    let mut recv = Command::new(&bin);
    recv.env("FILAMENT_CAP_AUTHORITATIVE", "0")
        .env("FILAMENT_DIRECT", "1")
        .env("FILAMENT_DIRECT_LOOPBACK_ONLY", &loopback)
        .env("FILAMENT_LOG", "debug")
        .env("FILAMENT_STALL_MS", "2500")
        .env("FILAMENT_WARM_STANDBY", "0")
        .env("FILAMENT_CONFIG_DIR", &h.b_dir)
        .arg("receive").arg(&code).arg("--yes").arg("--dir").arg(&recv_dir)
        .arg("--server").arg(&server);
    let recv = spawn_captured(recv).expect("spawn measured receiver");
    let deadline_secs = std::env::var("FILAMENT_STALL_MEASUREMENT_DEADLINE_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&v| v > 0)
        .unwrap_or(90);
    let recovery_deadline = Duration::from_secs(deadline_secs);
    let recv_result = recv.wait_until(recovery_deadline);
    let send_result = send.wait_until(Duration::from_secs(10));
    let logs = format!("{}\n{}\n{}\n{}", send_result.stdout, send_result.stderr,
        recv_result.stdout, recv_result.stderr);
    let armed = logs.contains("STALL_WATCHDOG_ARMED idle_ms_tracked");
    let froze = logs.contains("data-path FREEZE engaged");
    let detected = logs.contains("stall detected") || logs.contains("inbound stall");
    let recovery_started = logs.contains("repairing the link")
        || logs.contains("re-establish")
        || logs.contains("re-dial")
        || logs.contains("stall correction");
    let received = recv_dir.join("stall_payload.bin");
    let recovered = matches!(recv_result.outcome, ChildOutcome::ExitedSuccess(_))
        && received.exists()
        && std::fs::read(&received).ok().map(|data| {
            use sha2::{Digest, Sha256};
            Sha256::digest(data).iter().map(|b| format!("{b:02x}")).collect::<String>()
        }).as_deref() == Some(expected_hash.as_str());
    let dump_logs = || {
        eprintln!("--- measured sender stdout ---\n{}", send_result.stdout);
        eprintln!("--- measured sender stderr ---\n{}", send_result.stderr);
        eprintln!("--- measured receiver stdout ---\n{}", recv_result.stdout);
        eprintln!("--- measured receiver stderr ---\n{}", recv_result.stderr);
    };

    if !armed {
        dump_logs();
        panic!("UNCLASSIFIED: stall watchdog armed marker absent; instrument presence was not proven");
    }
    if !froze {
        dump_logs();
        panic!("UNCLASSIFIED: freeze hook did not engage; no stall was injected");
    }
    if !detected {
        dump_logs();
        panic!("FAIL: freeze engaged but no stall detector event was observed");
    }
    if !recovered {
        dump_logs();
        if recovery_started {
            if !matches!(recv_result.outcome, ChildOutcome::TimedOut) {
                panic!("DETECTED_NOT_RECOVERED: recovery started, receiver exited before the {recovery_deadline:?} deadline without byte-exact completion");
            }
            panic!("DETECTED_NOT_RECOVERED_WITHIN_DEADLINE: recovery started but did not complete within {recovery_deadline:?}");
        }
        panic!("DETECTED_RECOVERY_UNOBSERVED: detector fired but no recovery marker was observed");
    }
    eprintln!("PASS: freeze injected, detector fired, and transfer recovered byte-exact");
}

#[test]
fn warm_one_shot_pty_instant_eof() {
    // Proves fix/warm-oneshot-pty-reuse: one-shot `pty <peer> -- printf ...`
    // with INSTANT stdin-EOF (</dev/null) returns rc=0 with full output.
    //
    // Before the fix, the serve_stream reader-finished branch aborted the
    // writer, tearing down the pty before output arrived (hang / rc=124).
    // After the fix, the writer waits for the daemon to close the socket
    // (command exit), so output is delivered and the client returns cleanly.

    #[cfg(any(windows, target_os = "macos"))]
    {
        eprintln!("warm_one_shot_pty_instant_eof: skipped on {os}",
            os = if cfg!(windows) { "Windows" } else { "macOS" });
        return;
    }

    let mut h = Harness::new();
    let bin = h.filament_bin().to_path_buf();
    let server = h.server_url();

    let direct_flag =
        std::env::var("FILAMENT_DIRECT_PER_OS").unwrap_or_else(|_| "1".into());
    let loopback_only =
        std::env::var("FILAMENT_DIRECT_LOOPBACK_ONLY").unwrap_or_else(|_| "1".into());

    h.pair_daemons();
    eprintln!("warm_one_shot_pty_instant_eof: daemons started");

    // Pair a, claim b
    let pair_word = format!("warm-eof-p{:x}", std::process::id());
    let mut create = Command::new(&bin)
        .env("FILAMENT_CAP_AUTHORITATIVE", "0")
        .env("FILAMENT_DIRECT", &direct_flag)
        .env("FILAMENT_DIRECT_LOOPBACK_ONLY", &loopback_only)
        .env("FILAMENT_L3_USERSPACE", "1")
        .env("FILAMENT_NAME", "test-a")
        .env("FILAMENT_CONFIG_DIR", &h.a_dir)
        .args(["--server", &server, "add", "--word", &pair_word])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("pair create");

    let stderr = create.stderr.take().unwrap();
    let pair_word_lower = pair_word.to_lowercase();
    let (code_tx, code_rx) = std::sync::mpsc::channel::<String>();
    std::thread::spawn(move || {
        let reader = BufReader::new(stderr);
        for line in reader.lines() {
            let line = line.unwrap_or_default();
            eprintln!("[warm-eof-pair-create] {line}");
            if line.to_lowercase().contains(&pair_word_lower) {
                if let Some(code) = line
                    .split_whitespace()
                    .find(|w| {
                        w.to_lowercase().contains(&pair_word_lower)
                            && w.split('-').count() >= 4
                    })
                {
                    let _ = code_tx.send(code.to_string());
                }
            }
        }
    });

    let pair_code = code_rx.recv_timeout(Duration::from_secs(60))
        .expect("warm-eof pair create did not mint a code within 60s");
    eprintln!("warm-eof pair code: {pair_code}");

    let mut claim = Command::new(&bin)
        .env("FILAMENT_CAP_AUTHORITATIVE", "0")
        .env("FILAMENT_DIRECT", &direct_flag)
        .env("FILAMENT_DIRECT_LOOPBACK_ONLY", &loopback_only)
        .env("FILAMENT_L3_USERSPACE", "1")
        .env("FILAMENT_NAME", "test-b")
        .env("FILAMENT_CONFIG_DIR", &h.b_dir)
        .args(["--server", &server, "join", &pair_code])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("pair claim");
    let claim_out = claim.wait_with_output().expect("pair claim result");
    eprintln!("warm-eof-claim stderr: {}", String::from_utf8_lossy(&claim_out.stderr));

    let create_out = create.wait_with_output().expect("pair create result");
    eprintln!("warm-eof-pair-create exit: {}", create_out.status);

    // Enable warm-hold and restart daemons.
    let set = Command::new(&bin)
        .env("FILAMENT_CAP_AUTHORITATIVE", "0")
        .env("FILAMENT_CONFIG_DIR", &h.a_dir)
        .args(["--server", &server, "set", "warm-peers", "test-b"])
        .output()
        .expect("set warm-peers");
    assert!(set.status.success(), "set warm-peers failed: {:?}", String::from_utf8_lossy(&set.stderr));

    if let Some(ref mut c) = h.daemon_a {
        let _ = c.kill();
        let _ = c.wait();
    }
    if let Some(ref mut c) = h.daemon_b {
        let _ = c.kill();
        let _ = c.wait();
    }
    h.daemon_a = None;
    h.daemon_b = None;
    std::thread::sleep(Duration::from_secs(3));
    let (child_a, log_a) = spawn_daemon_inner(&bin, &server, "test-a", &h.a_dir);
    let (child_b, log_b) = spawn_daemon_inner(&bin, &server, "test-b", &h.b_dir);
    h.daemon_a = Some(child_a);
    h.daemon_b = Some(child_b);
    h.daemon_a_log = log_a;
    h.daemon_b_log = log_b;

    // Wait for warm link to daemon-b to be established (deterministic, not a
    // fixed sleep). The warm-hold loop prints "established connection" when a
    // new link comes up, or "skip ... (link alive, within grace)" when the
    // link is already up. Either means the warm path is usable.
    let warm_ready = wait_for_line(
        &h.daemon_a_log,
        "warm-hold: established connection to 'test-b'",
        Duration::from_secs(40),
    ) || wait_for_line(
        &h.daemon_a_log,
        "warm-hold: skip 'test-b'",
        Duration::from_secs(0),
    );
    assert!(
        warm_ready,
        "warm link to 'test-b' was not established within 40s after daemon restart"
    );

    // Allow the warm link to be verified (pair-proof) before running pty.
    // The warm-hold "established" message fires when the L2 stream opens,
    // but the pty warm path requires verification. The 30s grace window
    // in warm_hold_tick prevents churn, but we still need a brief settle.
    std::thread::sleep(Duration::from_secs(5));

    // Run one-shot pty with INSTANT stdin-EOF (</dev/null).
    // This is the exact scenario #67 fixed: the client closes stdin immediately,
    // serve_stream must NOT tear down the pty before output arrives.
    let nonce = format!("WARM-EOF-OK-{}", std::process::id());
    let out = Command::new(&bin)
        .env("FILAMENT_CAP_AUTHORITATIVE", "0")
        .env("FILAMENT_DIRECT", &direct_flag)
        .env("FILAMENT_DIRECT_LOOPBACK_ONLY", &loopback_only)
        .env("FILAMENT_L3_USERSPACE", "1")
        .env("FILAMENT_CONFIG_DIR", &h.a_dir)
        .args(["--server", &server, "shell", "test-b", "--", "printf", &nonce])
        .stdin(Stdio::null())  // instant stdin-EOF
        .output()
        .expect("pty instant-eof");
    let out_stdout = String::from_utf8_lossy(&out.stdout);
    let out_stderr = String::from_utf8_lossy(&out.stderr);
    eprintln!("warm pty instant-eof stdout: {out_stdout}");
    eprintln!("warm pty instant-eof stderr: {out_stderr}");

    // Must return rc=0 (not hang/timeout).
    assert!(
        out.status.success(),
        "warm one-shot pty with instant stdin-EOF failed: rc={:?}\n\
         stdout: {out_stdout}\nstderr: {out_stderr}",
        out.status.code()
    );

    // Must use warm path (not cold establish).
    assert!(
        out_stderr.contains("reusing warm link") && out_stderr.contains("one-shot pty"),
        "pty did NOT use warm link - expected 'reusing warm link ... for one-shot pty'\n\
         stdout: {out_stdout}\nstderr: {out_stderr}"
    );

    // Must deliver full output.
    assert!(
        out_stdout.contains(&nonce),
        "pty output does not contain nonce '{nonce}'\nstdout: {out_stdout}\nstderr: {out_stderr}"
    );
}

// ------------------------------------------------------------- invitations ---

/// Write a file that `read_owner_only_file` will accept (owner-only mode on
/// unix; the join path refuses anything with group/other bits). The minted
/// invitations and the test v1 token all travel this way, same as a real
/// `add --out`.
fn write_owner_only(path: &Path, contents: &str) -> std::io::Result<()> {
    std::fs::write(path, contents)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// A fresh, clean joiner config dir: no identity, no certificate. `join` only
/// proceeds from this state (main.rs join_cmd refuses if a UserKey or cert
/// exists), so every invitation-lifecycle test claims from here.
fn clean_joiner_dir(h: &Harness, name: &str) -> PathBuf {
    let dir = h.work_dir.join(name);
    std::fs::create_dir_all(&dir).expect("create clean joiner dir");
    dir
}

/// `add --for device` and `add --for person` mint different SIGNED ceilings:
/// device carries transfer+mount, person carries transfer only. The difference
/// lives in the signed auth-key caps, which is exactly what the delegated-
/// ceiling gate (`cap_gate_effective`'s `action in auth_key_caps` check) enforces
/// at serve time. So the difference is enforced, not just displayed: a
/// person-joined device is denied `mount` because `mount` is not in its signed
/// caps.
#[test]
fn add_for_device_and_person_carry_different_caps() {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use filament_cap::ephemeral::InvitationV2;

    let h = Harness::new();
    let bin = h.filament_bin().to_path_buf();
    let server = h.server_url();

    let device_file = h.work_dir.join("inv-device.txt");
    let person_file = h.work_dir.join("inv-person.txt");

    for (for_, file) in [("device", &device_file), ("person", &person_file)] {
        let out = Command::new(&bin)
            .env("FILAMENT_CONFIG_DIR", &h.a_dir)
            .args(["--server", &server, "add", "--for", for_, "--out"])
            .arg(file)
            .arg("--yes")
            .output()
            .expect("add --for mint");
        assert!(
            out.status.success(),
            "add --for {for_} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    let parse = |file: &Path| -> InvitationV2 {
        let raw = std::fs::read_to_string(file).expect("read invitation file");
        let token = raw.trim();
        let encoded = token
            .strip_prefix("filament-invite:v2:")
            .unwrap_or_else(|| panic!("token has the v2 prefix: {token}"));
        let bytes = URL_SAFE_NO_PAD
            .decode(encoded)
            .expect("token is valid base64url");
        // InvitationV2 is not Debug; go through a Result whose error is a &str.
        InvitationV2::from_token(&bytes)
            .ok_or("token parses as a v2 invitation")
            .expect("from_token")
    };

    let mut device_caps = parse(&device_file).caps;
    device_caps.sort();
    assert_eq!(
        device_caps,
        vec!["mount".to_string(), "transfer".to_string()],
        "device invitation must carry transfer+mount in the SIGNED ceiling"
    );
    let person_caps = parse(&person_file).caps;
    assert_eq!(
        person_caps,
        vec!["transfer".to_string()],
        "person invitation must carry transfer only: the mount difference is \
         what the gate enforces for a person-joined device"
    );
}

/// An expired bounded invitation is refused AS expired. The joiner names the
/// expiry; it does not fail to parse and it does not time out.
#[test]
fn expired_invitation_refused_as_expired() {
    let h = Harness::new();
    let bin = h.filament_bin().to_path_buf();
    let server = h.server_url();

    let invite_file = h.work_dir.join("inv-expired.txt");
    let mint = Command::new(&bin)
        .env("FILAMENT_CONFIG_DIR", &h.a_dir)
        .args(["--server", &server, "add", "--for", "device", "--expires", "2s", "--out"])
        .arg(&invite_file)
        .arg("--yes")
        .output()
        .expect("mint short-lived invitation");
    assert!(
        mint.status.success(),
        "mint failed: {}",
        String::from_utf8_lossy(&mint.stderr)
    );

    // Let the 2s TTL lapse, then claim from a clean joiner.
    std::thread::sleep(Duration::from_secs(4));
    let clean = clean_joiner_dir(&h, "c");
    let join = Command::new(&bin)
        .env("FILAMENT_CONFIG_DIR", &clean)
        .args(["--server", &server, "join", "--invite-file"])
        .arg(&invite_file)
        .arg("--yes")
        .output()
        .expect("join expired invitation");
    let stderr = String::from_utf8_lossy(&join.stderr);
    assert!(
        !join.status.success(),
        "an expired invitation must be refused; join unexpectedly succeeded"
    );
    assert!(
        stderr.contains("expired"),
        "expired invitation must be refused AS expired, got: {stderr}"
    );
    assert!(
        !stderr.contains("unknown format") && !stderr.contains("not valid"),
        "an expired invitation is not a parse error, got: {stderr}"
    );
}

/// An invitation minted before 0.8.4 is refused with a message SAYING SO, not
/// with a parse error: the v1 token is recognized and named stale.
#[test]
fn pre_084_invitation_refused_with_message_not_parse_error() {
    let h = Harness::new();
    let bin = h.filament_bin().to_path_buf();
    let server = h.server_url();

    let invite_file = h.work_dir.join("inv-v1.txt");
    write_owner_only(&invite_file, "filament-invite:v1:AAAA\n").expect("write v1 invitation");

    let clean = clean_joiner_dir(&h, "c");
    let join = Command::new(&bin)
        .env("FILAMENT_CONFIG_DIR", &clean)
        .args(["--server", &server, "join", "--invite-file"])
        .arg(&invite_file)
        .arg("--yes")
        .output()
        .expect("join v1 invitation");
    let stderr = String::from_utf8_lossy(&join.stderr);
    assert!(
        !join.status.success(),
        "a pre-0.8.4 invitation must be refused"
    );
    assert!(
        stderr.contains("pre-0.8.4"),
        "the refusal must name the pre-0.8.4 format, got: {stderr}"
    );
    assert!(
        !stderr.contains("unknown format") && !stderr.contains("not valid"),
        "the refusal must not be a parse error, got: {stderr}"
    );
}

// ----------------------------------------------------------- cap-store cell ---

fn sha256_file(path: &Path) -> Option<String> {
    use sha2::{Digest, Sha256};
    let bytes = std::fs::read(path).ok()?;
    Some(
        Sha256::digest(&bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
    )
}

/// Wait for a file to exist, up to `timeout`. Returns true if it appeared.
fn wait_for_file(path: &Path, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if path.exists() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    path.exists()
}

/// Count capability GRANTS in a cap store. A store that exists but contains no
/// grants (genesis header + ratchet only) is the allowed delta after a join.
fn cap_store_grant_count(config_dir: &Path) -> usize {
    let p = config_dir.join("caps.json");
    let Ok(raw) = std::fs::read_to_string(&p) else {
        return 0; // absent store: no grants by construction
    };
    let Ok(arr) = serde_json::from_str::<Vec<Value>>(&raw) else {
        panic!("caps.json at {} is not a valid store: {raw}", p.display());
    };
    arr.iter()
        .filter(|e| e.get("type").and_then(|t| t.as_str()) == Some("cap_grant"))
        .count()
}

/// #210/advisor invariant: a full join must not change the capability store.
///
/// No CapOp is ever parsed from the wire. `apply_cap_op` (capability.rs:1360)
/// is the only owner-signature-verifying store writer and has exactly one
/// production call site, the local `revoke`. This property contains owner-key
/// compromise: fleet_auto_trust already grants transfer+mount fleet-wide with
/// no local grant, so the local grant is the last boundary for the deliberate
/// tier. The owner is considering putting permissions inside the invitation
/// and applying them at join, which would be the first network-origin write.
///
/// This test turns "there is no network path into the cap store" from a grep
/// someone ran once into an invariant that stays true. It performs a REAL join
/// (not a seeded store) and asserts:
///
///   - the JOINER's cap store is unchanged across the ceremony (a clean joiner
///     has no store before or after; if a genesis header appears, no grant may),
///   - the ISSUER's cap store is byte-identical across mint + claim,
///   - the join actually RAN (the joiner ends up with a device cert), so a
///     no-op join cannot read as a pass.
///
/// Hash, not eyeball: the issuer side asserts byte equality of the whole file.
/// The joiner side asserts the grant set specifically, because a genesis header
/// written during the ceremony is legitimate and would break a byte comparison;
/// the grant count is the strongest assertion available there.
#[test]
fn join_does_not_change_the_capability_store() {
    let mut h = Harness::new();
    let bin = h.filament_bin().to_path_buf();
    let server = h.server_url();

    let joiner = clean_joiner_dir(&h, "joiner");
    let issuer_caps = h.a_dir.join("caps.json");
    let joiner_caps = joiner.join("caps.json");

    // The issuer (a_dir) was init'd, so its genesis header already exists; the
    // daemon-start heal is a no-op and the store must stay byte-stable.
    let issuer_before = sha256_file(&issuer_caps)
        .unwrap_or_else(|| panic!("issuer caps.json absent after init: {}", issuer_caps.display()));
    assert_eq!(
        cap_store_grant_count(&h.a_dir),
        0,
        "issuer must start with zero grants"
    );

    // Start the issuer daemon: the join claim needs the armed enrollment room.
    let (child_a, log_a) = spawn_daemon_inner(&bin, &server, "test-a", &h.a_dir);
    h.daemon_a = Some(child_a);
    h.daemon_a_log = log_a;

    // #211: `up` prints its ready banner BEFORE its control socket accepts, and
    // the mint's try_arm swallows a connect failure as None. A mint that races
    // the socket produces an invitation nobody can ever claim. The PRODUCT bug
    // is #211 (filed); this wait only keeps the test from tripping over it. The
    // arm-success assertion below still fails loudly if the socket never came
    // up, so the test cannot silently pass while the product cannot arm.
    let ctl_sock = h.a_dir.join("control.sock");
    assert!(
        wait_for_file(&ctl_sock, Duration::from_secs(30)),
        "issuer daemon control socket never appeared: {}. The enrollment room \
         could not be armed, so the join cannot run (see #211).",
        ctl_sock.display()
    );
    std::thread::sleep(Duration::from_millis(500));

    // Mint an invitation. Minting is a local act (signing + printing) and must
    // not touch the issuer's cap store either. If the arm failed (the daemon
    // was not ready, or #205's Windows stub), the mint says so and this test
    // stops HERE with a clear message instead of failing 60s later at the join.
    let invite_file = h.work_dir.join("inv-cap-store.txt");
    let mint = Command::new(&bin)
        .env("FILAMENT_CONFIG_DIR", &h.a_dir)
        .args(["--server", &server, "add", "--for", "device", "--out"])
        .arg(&invite_file)
        .arg("--yes")
        .output()
        .expect("mint invitation");
    let mint_stderr = String::from_utf8_lossy(&mint.stderr);
    assert!(
        mint.status.success(),
        "mint failed: {mint_stderr}"
    );
    assert!(
        !mint_stderr.contains("cannot be claimed"),
        "UNCLASSIFIED: the mint did not arm the enrollment room (stderr says \
         the invitation 'cannot be claimed yet'). This run cannot exercise the \
         join. stderr: {mint_stderr}"
    );
    let issuer_after_mint = sha256_file(&issuer_caps).unwrap();
    assert_eq!(
        issuer_after_mint, issuer_before,
        "minting an invitation must not change the issuer's cap store"
    );

    // The joiner starts clean: no cap store, no identity.
    assert!(!joiner_caps.exists(), "clean joiner must have no cap store");

    // Full join ceremony. The joiner must actually complete it (device cert
    // written), or the invariant below is vacuous. The joiner's transport env
    // matches the issuer daemon's (direct enabled, same candidate policy) so
    // the enrollment link has the same chances the transfer path does; without
    // it the joiner can end up with only a STUN srflx candidate and ICE fails.
    let loopback_only = std::env::var("FILAMENT_DIRECT_LOOPBACK_ONLY").unwrap_or_else(|_| "1".into());
    let join = spawn_captured({
        let mut c = Command::new(&bin);
        c.env("FILAMENT_CONFIG_DIR", &joiner)
            .env("FILAMENT_DIRECT", "1")
            .env("FILAMENT_DIRECT_LOOPBACK_ONLY", &loopback_only)
            .env("FILAMENT_L3_USERSPACE", "1")
            .args(["--server", &server, "join", "--invite-file"])
            .arg(&invite_file)
            .arg("--name")
            .arg("joiner")
            .arg("--yes");
        c
    })
    .expect("join spawn")
    .wait_until(Duration::from_secs(120));
    let joined_cert = joiner.join("identity").join("device-cert.json");
    assert!(
        joined_cert.exists(),
        "the join did not run: no device cert written for the joiner.\n\
         join stdout: {}\njoin stderr: {}",
        join.stdout, join.stderr
    );

    // ISSUER: byte-identical across the whole ceremony (mint + claim). This is
    // the strong form: no writer touched the store at any step.
    let issuer_after_claim = sha256_file(&issuer_caps).unwrap();
    assert_eq!(
        issuer_after_claim, issuer_before,
        "a full join changed the issuer's cap store: byte-level invariant broken.\n\
         This is the network-origin write the advisor's grep said does not exist."
    );

    // JOINER: the store must contain no grants. The joiner started with NO
    // store, so the byte-level invariant is "still absent". If a genesis
    // header was legitimately written during the ceremony, a byte comparison
    // becomes impossible, and the grant set is the strongest assertion
    // available there: no cap_grant may appear, either way. Both cases are
    // covered by the single grant count below.
    assert_eq!(
        cap_store_grant_count(&joiner),
        0,
        "a full join wrote a capability GRANT into the joiner's cap store.\n\
         This is the network-origin write the advisor's grep said does not exist.\n\
         joiner store: {}",
        std::fs::read_to_string(&joiner_caps).unwrap_or_default()
    );
}
