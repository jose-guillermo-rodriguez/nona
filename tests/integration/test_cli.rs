// ============================================================================
// ============================================================================

#![cfg(feature = "std")]

use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Once;
use std::thread;
use std::time::Duration;

use nona_core::enclave_server::run_unix_server;

const TEST_SOCKET_PATH: &str = "/tmp/nona_cli_test.sock";
const TEST_SOCKET_PATH_BYTES: &[u8] = b"/tmp/nona_cli_test.sock\0";
static SERVER_INIT: Once = Once::new();

fn binary_path() -> PathBuf {
    if let Ok(path) = std::env::var("CARGO_BIN_EXE_nona") {
        return PathBuf::from(path);
    }
    let mut path = std::env::current_exe().unwrap();
    path.pop();
    if path.ends_with("deps") {
        path.pop();
    }
    path.push("nona");
    path
}

fn ensure_mock_enclave_server() {
    SERVER_INIT.call_once(|| {
        let _ = fs::remove_file(TEST_SOCKET_PATH);
        thread::spawn(|| unsafe {
            run_unix_server(TEST_SOCKET_PATH_BYTES);
        });
        for _ in 0..50 {
            if std::path::Path::new(TEST_SOCKET_PATH).exists() {
                return;
            }
            thread::sleep(Duration::from_millis(20));
        }
    });
}

#[test]
fn test_cli_exit_code_on_missing_or_bad_arguments() {
    let bin = binary_path();

    // 1. Missing target on match command -> Exit code 2
    let output = Command::new(&bin)
        .env("NONA_DEV_SIMULATION", "1")
        .arg("match")
        .output()
        .expect("Failed to execute binary");
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Missing required argument: --target"));

    // 2. Unknown flag -> Exit code 2
    let output = Command::new(&bin)
        .env("NONA_DEV_SIMULATION", "1")
        .args(["match", "--invalid-unknown-flag"])
        .output()
        .expect("Failed to execute binary");
    assert_eq!(output.status.code(), Some(2));

    // 3. Nonexistent input file -> Exit code 2
    let output = Command::new(&bin)
        .env("NONA_DEV_SIMULATION", "1")
        .args([
            "match",
            "--target",
            "nonexistent.bin",
            "nonexistent_input.txt",
        ])
        .output()
        .expect("Failed to execute binary");
    assert_eq!(output.status.code(), Some(2));
}

#[test]
fn test_cli_exit_code_on_connection_failure() {
    let bin = binary_path();

    // Attempting to ping an unreachable socket -> Exit code 1
    let output = Command::new(&bin)
        .env("NONA_DEV_SIMULATION", "1")
        .args([
            "ping",
            "--socket",
            "/tmp/nonexistent_socket_nona_test_9999.sock",
        ])
        .output()
        .expect("Failed to execute binary");
    assert_eq!(output.status.code(), Some(1));
}

#[test]
fn test_cli_ping_and_attestation() {
    ensure_mock_enclave_server();
    let bin = binary_path();

    // Ping enclave server -> Exit code 0
    let output = Command::new(&bin)
        .args(["ping", "--socket", TEST_SOCKET_PATH])
        .output()
        .expect("Failed to execute binary");
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("PONG"));

    // 1. Strict mode outside AWS Nitro Enclaves -> Fail closed (Exit code 1)
    let output_strict = Command::new(&bin)
        .args([
            "attest",
            "--socket",
            TEST_SOCKET_PATH,
            "--manifest",
            "manifests/enclave_manifest.json",
        ])
        .output()
        .expect("Failed to execute binary");
    assert_eq!(output_strict.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output_strict.stderr);
    assert!(stderr.contains("HardwareAttestationUnavailable"));

    // 2. Dev simulation mode -> Exit code 0
    let output_sim = Command::new(&bin)
        .args([
            "attest",
            "--dev-simulation",
            "--socket",
            TEST_SOCKET_PATH,
            "--manifest",
            "manifests/enclave_manifest.json",
        ])
        .output()
        .expect("Failed to execute binary");
    assert_eq!(output_sim.status.code(), Some(0));
    let stdout_sim = String::from_utf8_lossy(&output_sim.stdout);
    assert!(stdout_sim.contains("verified successfully"));
}

#[test]
fn test_cli_blind_and_e2e_match_pipeline() {
    ensure_mock_enclave_server();
    let bin = binary_path();

    let target_bin_path = "/tmp/nona_remote_target.bin";
    let input_txt_path = "/tmp/nona_local_records.txt";

    // Prepare remote target set: generate blinded tokens for 3 elements:
    // "alice@example.com", "bob@example.com", "charlie@example.com"
    let remote_records = "alice@example.com\nbob@example.com\ncharlie@example.com\n";
    fs::write("/tmp/nona_remote_records.txt", remote_records).unwrap();

    let blind_output = Command::new(&bin)
        .env("NONA_DEV_SIMULATION", "1")
        .args([
            "blind",
            "--socket",
            TEST_SOCKET_PATH,
            "-o",
            target_bin_path,
            "/tmp/nona_remote_records.txt",
        ])
        .output()
        .expect("Failed to execute blind");
    assert_eq!(blind_output.status.code(), Some(0));

    let target_data = fs::read(target_bin_path).expect("Failed to read generated target binary");
    assert_eq!(target_data.len(), 3 * 32);

    // 1. Line-delimited matching via file argument
    // Local set: "alice@example.com" (match), "david@example.com" (no match), "charlie@example.com" (match)
    let local_records = "alice@example.com\ndavid@example.com\ncharlie@example.com\n";
    fs::write(input_txt_path, local_records).unwrap();

    let match_output = Command::new(&bin)
        .env("NONA_DEV_SIMULATION", "1")
        .args([
            "match",
            "--target",
            target_bin_path,
            "--socket",
            TEST_SOCKET_PATH,
            "--format",
            "text",
            input_txt_path,
        ])
        .output()
        .expect("Failed to execute match");
    assert_eq!(match_output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&match_output.stdout);
    assert!(stdout.contains("alice@example.com"));
    assert!(stdout.contains("charlie@example.com"));
    assert!(!stdout.contains("david@example.com"));

    // 2. POSIX stdin Unix piping with JSON format output
    let mut child = Command::new(&bin)
        .env("NONA_DEV_SIMULATION", "1")
        .args([
            "match",
            "--target",
            target_bin_path,
            "--socket",
            TEST_SOCKET_PATH,
            "--format",
            "json",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("Failed to spawn process");

    {
        let stdin = child.stdin.as_mut().expect("Failed to open stdin");
        stdin.write_all(local_records.as_bytes()).unwrap();
    }
    let pipe_output = child.wait_with_output().unwrap();
    assert_eq!(pipe_output.status.code(), Some(0));
    let json_str = String::from_utf8_lossy(&pipe_output.stdout);
    assert!(json_str.contains("\"cardinality\":2"));
    assert!(json_str.contains("\"matches\":[\"alice@example.com\",\"charlie@example.com\"]"));
    assert!(json_str.contains("\"indices\":[0,2]"));

    // 3. CSV format output
    let mut child_csv = Command::new(&bin)
        .env("NONA_DEV_SIMULATION", "1")
        .args([
            "match",
            "--target",
            target_bin_path,
            "--socket",
            TEST_SOCKET_PATH,
            "--format",
            "csv",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("Failed to spawn process");

    {
        let stdin = child_csv.stdin.as_mut().expect("Failed to open stdin");
        stdin.write_all(local_records.as_bytes()).unwrap();
    }
    let csv_output = child_csv.wait_with_output().unwrap();
    assert_eq!(csv_output.status.code(), Some(0));
    let csv_str = String::from_utf8_lossy(&csv_output.stdout);
    assert!(csv_str.contains("index,record"));
    assert!(csv_str.contains("0,alice@example.com"));
    assert!(csv_str.contains("2,charlie@example.com"));

    // 4. Cardinality-only flag
    let mut child_card = Command::new(&bin)
        .env("NONA_DEV_SIMULATION", "1")
        .args([
            "match",
            "--target",
            target_bin_path,
            "--socket",
            TEST_SOCKET_PATH,
            "--cardinality-only",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("Failed to spawn process");

    {
        let stdin = child_card.stdin.as_mut().expect("Failed to open stdin");
        stdin.write_all(local_records.as_bytes()).unwrap();
    }
    let card_output = child_card.wait_with_output().unwrap();
    assert_eq!(card_output.status.code(), Some(0));
    let card_str = String::from_utf8_lossy(&card_output.stdout)
        .trim()
        .to_string();
    let card_val: Result<u64, _> = card_str.parse();
    assert!(card_val.is_ok());

    // Clean up test files
    let _ = fs::remove_file(target_bin_path);
    let _ = fs::remove_file(input_txt_path);
    let _ = fs::remove_file("/tmp/nona_remote_records.txt");
}

#[test]
fn test_cli_csv_and_json_ingestion() {
    ensure_mock_enclave_server();
    let bin = binary_path();

    let target_bin_path = "/tmp/nona_remote_target_multi.bin";
    let remote_records = "bob@example.com\n";
    fs::write("/tmp/nona_remote_records_multi.txt", remote_records).unwrap();

    let blind_output = Command::new(&bin)
        .env("NONA_DEV_SIMULATION", "1")
        .args([
            "blind",
            "--socket",
            TEST_SOCKET_PATH,
            "-o",
            target_bin_path,
            "/tmp/nona_remote_records_multi.txt",
        ])
        .output()
        .expect("Failed to execute blind");
    assert_eq!(blind_output.status.code(), Some(0));

    // 1. Structured CSV with header and column selection
    let csv_input =
        "user_id,email_address,role\n101,alice@example.com,admin\n102,bob@example.com,user\n";
    let mut child = Command::new(&bin)
        .env("NONA_DEV_SIMULATION", "1")
        .args([
            "match",
            "--target",
            target_bin_path,
            "--socket",
            TEST_SOCKET_PATH,
            "--column",
            "email_address",
            "--format",
            "json",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();

    {
        let stdin = child.stdin.as_mut().unwrap();
        stdin.write_all(csv_input.as_bytes()).unwrap();
    }
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(0));
    let res = String::from_utf8_lossy(&output.stdout);
    assert!(res.contains("\"cardinality\":1"));
    assert!(res.contains("bob@example.com"));

    // 2. JSON array input: ["alice@example.com", "bob@example.com"]
    let json_array_input = "[\"alice@example.com\", \"bob@example.com\"]";
    let mut child_ja = Command::new(&bin)
        .env("NONA_DEV_SIMULATION", "1")
        .args([
            "match",
            "--target",
            target_bin_path,
            "--socket",
            TEST_SOCKET_PATH,
            "--format",
            "json",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();

    {
        let stdin = child_ja.stdin.as_mut().unwrap();
        stdin.write_all(json_array_input.as_bytes()).unwrap();
    }
    let output_ja = child_ja.wait_with_output().unwrap();
    assert_eq!(output_ja.status.code(), Some(0));
    let res_ja = String::from_utf8_lossy(&output_ja.stdout);
    assert!(res_ja.contains("\"cardinality\":1"));
    assert!(res_ja.contains("bob@example.com"));

    // 3. NDJSON (JSON-Lines) input
    let ndjson_input = "{\"email\": \"alice@example.com\"}\n{\"email\": \"bob@example.com\"}\n";
    let mut child_nd = Command::new(&bin)
        .env("NONA_DEV_SIMULATION", "1")
        .args([
            "match",
            "--target",
            target_bin_path,
            "--socket",
            TEST_SOCKET_PATH,
            "--format",
            "json",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();

    {
        let stdin = child_nd.stdin.as_mut().unwrap();
        stdin.write_all(ndjson_input.as_bytes()).unwrap();
    }
    let output_nd = child_nd.wait_with_output().unwrap();
    assert_eq!(output_nd.status.code(), Some(0));
    let res_nd = String::from_utf8_lossy(&output_nd.stdout);
    assert!(res_nd.contains("\"cardinality\":1"));
    assert!(res_nd.contains("bob@example.com"));

    let _ = fs::remove_file(target_bin_path);
    let _ = fs::remove_file("/tmp/nona_remote_records_multi.txt");
}
