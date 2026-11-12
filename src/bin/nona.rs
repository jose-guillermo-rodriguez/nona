//! Developer CLI and POSIX streaming interlock entrypoint.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "std")]
use std::collections::BTreeSet;
#[cfg(feature = "std")]
use std::env;
#[cfg(feature = "std")]
use std::fs;
#[cfg(feature = "std")]
use std::io::{self, Read, Write};
#[cfg(feature = "std")]
use std::process;

#[cfg(feature = "std")]
use nona_core::client::{NonaClient, DEFAULT_UNIX_SOCKET_PATH};
#[cfg(feature = "std")]
use nona_core::normalization::normalize_to_buffer;
#[cfg(feature = "std")]
use nona_core::psi::{nona_phase2_intersect, NONA_FLAG_FULL_PSI, NONA_FLAG_PSI_CA};

#[cfg(not(feature = "std"))]
fn main() {}

#[cfg(feature = "std")]
const USAGE: &str = "\
nona 0.1.0 - High-Assurance Private Set Intersection (PSI) CLI

USAGE:
    nona <SUBCOMMAND> [OPTIONS] [INPUT]
    cat records.txt | nona match --target <REMOTE_SET> [OPTIONS]

SUBCOMMANDS:
    match       Intersect local records against target remote blinded set (Phase 2)
    blind       Pre-blind local records against enclave session key (Phase 1)
    attest      Verify enclave hardware attestation and PCR measurements
    ping        Verify heartbeat connection to confidential enclave server
    help        Print this help message

OPTIONS:
    -t, --target <FILE>         Path to remote blinded set binary file (required for match)
    -s, --socket <PATH>         Path to Unix domain socket (default: /tmp/nona.sock)
    -v, --vsock <PORT>          Connect via AF_VSOCK port (e.g. 5005) instead of Unix socket
    --dev-simulation            Allow developer simulation fallback when outside AWS Nitro Enclave
    -m, --manifest <FILE>       Path to enclave_manifest.json for PCR verification
    -f, --format <FORMAT>       Output format: text, json, csv (default: text)
    -c, --cardinality-only      Output intersection cardinality only (DP noise injected in CA mode)
        --column <NAME_OR_IDX>  Column name or 0-based index for CSV/JSON ingestion
    -h, --help                  Print help information
    -V, --version               Print version information

EXIT CODES:
    0    Success / clean intersection
    1    Protocol, attestation, or cryptographic boundary failure
    2    Invalid command line arguments or I/O failure
";

#[cfg(feature = "std")]
#[derive(Debug, Clone, PartialEq, Eq)]
enum OutputFormat {
    Text,
    Json,
    Csv,
}

#[cfg(feature = "std")]
#[derive(Debug, Clone)]
struct CliConfig {
    subcommand: String,
    target_path: Option<String>,
    socket_path: String,
    vsock_port: Option<u32>,
    manifest_path: Option<String>,
    format: OutputFormat,
    cardinality_only: bool,
    column: Option<String>,
    input_file: Option<String>,
    output_file: Option<String>,
    dev_simulation: bool,
}

#[cfg(feature = "std")]
impl Default for CliConfig {
    fn default() -> Self {
        Self {
            subcommand: "match".to_string(),
            target_path: None,
            socket_path: DEFAULT_UNIX_SOCKET_PATH.to_string(),
            vsock_port: None,
            manifest_path: None,
            format: OutputFormat::Text,
            cardinality_only: false,
            column: None,
            input_file: None,
            output_file: None,
            dev_simulation: std::env::var("NONA_DEV_SIMULATION").is_ok(),
        }
    }
}

#[cfg(feature = "std")]
#[repr(C, align(64))]
struct AlignedBuffer4096 {
    data: [u8; 4096],
}

use zeroize::Zeroize;

impl Drop for AlignedBuffer4096 {
    #[inline]
    fn drop(&mut self) {
        self.data.zeroize();
    }
}

impl AlignedBuffer4096 {
    #[inline]
    #[allow(clippy::cast_ptr_alignment)]
    fn new_boxed_zeroed() -> Box<Self> {
        // SAFETY: `alloc_zeroed` guarantees alignment matching `layout.align()` (64 bytes).
        // The pointer cast to `*mut Self` is dynamically aligned and satisfies C-ABI layout.
        let layout = std::alloc::Layout::new::<Self>();
        let ptr = unsafe { std::alloc::alloc_zeroed(layout).cast::<Self>() };
        if ptr.is_null() {
            std::alloc::handle_alloc_error(layout);
        }
        unsafe { Box::from_raw(ptr) }
    }
}

#[cfg(feature = "std")]
#[repr(C, align(64))]
struct AlignedU64(u64);

#[cfg(feature = "std")]
#[inline(never)]
fn parse_single_arg(
    args: &[String],
    idx: &mut usize,
    config: &mut CliConfig,
) -> Result<(), (String, i32)> {
    let arg = &args[*idx];
    match arg.as_str() {
        "-t" | "--target" => {
            *idx += 1;
            if *idx >= args.len() {
                return Err(("Missing argument for --target".to_string(), 2));
            }
            config.target_path = Some(args[*idx].clone());
        }
        "-s" | "--socket" => {
            *idx += 1;
            if *idx >= args.len() {
                return Err(("Missing argument for --socket".to_string(), 2));
            }
            config.socket_path.clone_from(&args[*idx]);
        }
        "-v" | "--vsock" => {
            *idx += 1;
            if *idx >= args.len() {
                return Err(("Missing argument for --vsock".to_string(), 2));
            }
            let port: u32 = args[*idx]
                .parse()
                .map_err(|_| ("Invalid VSOCK port number".to_string(), 2))?;
            config.vsock_port = Some(port);
        }
        "-m" | "--manifest" => {
            *idx += 1;
            if *idx >= args.len() {
                return Err(("Missing argument for --manifest".to_string(), 2));
            }
            config.manifest_path = Some(args[*idx].clone());
        }
        "-f" | "--format" => {
            *idx += 1;
            if *idx >= args.len() {
                return Err(("Missing argument for --format".to_string(), 2));
            }
            match args[*idx].to_lowercase().as_str() {
                "text" | "txt" => config.format = OutputFormat::Text,
                "json" => config.format = OutputFormat::Json,
                "csv" => config.format = OutputFormat::Csv,
                other => {
                    return Err((
                        format!("Unsupported output format '{other}' (supported: text, json, csv)"),
                        2,
                    ));
                }
            }
        }
        "-c" | "--cardinality-only" => {
            config.cardinality_only = true;
        }
        "--dev-simulation" | "--allow-simulation" => {
            config.dev_simulation = true;
        }
        "--column" => {
            *idx += 1;
            if *idx >= args.len() {
                return Err(("Missing argument for --column".to_string(), 2));
            }
            config.column = Some(args[*idx].clone());
        }
        "-o" | "--output" => {
            *idx += 1;
            if *idx >= args.len() {
                return Err(("Missing argument for --output".to_string(), 2));
            }
            config.output_file = Some(args[*idx].clone());
        }
        "-h" | "--help" => {
            print!("{USAGE}");
            process::exit(0);
        }
        "-V" | "--version" => {
            println!("nona 0.1.0");
            process::exit(0);
        }
        val if val.starts_with('-') => {
            return Err((format!("Unknown option '{val}'"), 2));
        }
        val => {
            if config.input_file.is_none() {
                config.input_file = Some(val.to_string());
            } else {
                return Err((format!("Unexpected positional argument '{val}'"), 2));
            }
        }
    }
    Ok(())
}

fn parse_args() -> Result<CliConfig, (String, i32)> {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() {
        return Ok(CliConfig::default());
    }

    let mut config = CliConfig::default();
    let mut idx = 0;

    let first = &args[0];
    if first == "-h" || first == "--help" || first == "help" {
        print!("{USAGE}");
        process::exit(0);
    }
    if first == "-V" || first == "--version" {
        println!("nona 0.1.0");
        process::exit(0);
    }

    if !first.starts_with('-') {
        match first.as_str() {
            "match" | "blind" | "attest" | "ping" => {
                config.subcommand.clone_from(first);
                idx = 1;
            }
            _ => {
                config.subcommand = "match".to_string();
            }
        }
    }

    while idx < args.len() {
        parse_single_arg(&args, &mut idx, &mut config)?;
        idx += 1;
    }

    Ok(config)
}

#[cfg(feature = "std")]
fn read_input_data(input_file: Option<&str>) -> Result<String, (String, i32)> {
    match input_file {
        Some("-") | None => {
            let mut buf = String::new();
            io::stdin()
                .read_to_string(&mut buf)
                .map_err(|e| (format!("Failed to read from stdin: {e}"), 2))?;
            Ok(buf)
        }
        Some(path) => fs::read_to_string(path)
            .map_err(|e| (format!("Failed to read input file '{path}': {e}"), 2)),
    }
}

#[cfg(feature = "std")]
fn parse_csv_line(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut chars = line.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '"' {
            if in_quotes && chars.peek() == Some(&'"') {
                current.push('"');
                chars.next();
            } else {
                in_quotes = !in_quotes;
            }
        } else if c == ',' && !in_quotes {
            fields.push(current.trim().to_string());
            current.clear();
        } else {
            current.push(c);
        }
    }
    fields.push(current.trim().to_string());
    fields
}

#[cfg(feature = "std")]
fn extract_records(content: &str, col_hint: Option<&str>) -> Vec<String> {
    let trimmed = content.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }

    if trimmed.starts_with('[') && trimmed.ends_with(']') {
        return parse_json_array(trimmed, col_hint);
    }

    let raw_lines: Vec<&str> = content.lines().collect();
    if raw_lines.is_empty() {
        return Vec::new();
    }

    let mut ndjson_records = Vec::new();
    let mut all_ndjson = true;
    for line in &raw_lines {
        let l = line.trim();
        if l.is_empty() {
            continue;
        }
        if l.starts_with('{') && l.ends_with('}') {
            if let Some(val) = extract_json_object_field(l, col_hint) {
                ndjson_records.push(val);
            } else {
                all_ndjson = false;
                break;
            }
        } else {
            all_ndjson = false;
            break;
        }
    }
    if all_ndjson && !ndjson_records.is_empty() {
        return ndjson_records;
    }

    let non_empty_lines: Vec<&str> = raw_lines
        .into_iter()
        .filter(|l| !l.trim().is_empty())
        .collect();
    if !non_empty_lines.is_empty() && non_empty_lines[0].contains(',') {
        let parsed_rows: Vec<Vec<String>> =
            non_empty_lines.iter().map(|l| parse_csv_line(l)).collect();
        if !parsed_rows.is_empty() {
            let mut target_col = 0usize;
            let mut skip_header = false;
            let header = &parsed_rows[0];

            if let Some(hint) = col_hint {
                if let Ok(idx) = hint.parse::<usize>() {
                    target_col = idx;
                } else {
                    for (i, h) in header.iter().enumerate() {
                        if h.eq_ignore_ascii_case(hint) {
                            target_col = i;
                            skip_header = true;
                            break;
                        }
                    }
                }
            } else {
                let first_val = header[0].to_lowercase();
                if [
                    "record",
                    "email",
                    "id",
                    "identifier",
                    "key",
                    "element",
                    "val",
                ]
                .contains(&first_val.as_str())
                {
                    skip_header = true;
                }
            }

            let start = if skip_header { 1 } else { 0 };
            let mut records = Vec::new();
            for row in &parsed_rows[start..] {
                if target_col < row.len() {
                    let val = row[target_col].trim();
                    if !val.is_empty() {
                        records.push(val.to_string());
                    }
                }
            }
            return records;
        }
    }

    non_empty_lines
        .into_iter()
        .map(std::string::ToString::to_string)
        .collect()
}

#[cfg(feature = "std")]
fn extract_json_object_field(json_obj: &str, col_hint: Option<&str>) -> Option<String> {
    let s = json_obj
        .trim()
        .trim_start_matches('{')
        .trim_end_matches('}')
        .trim();
    let default_keys = [
        "record",
        "email",
        "id",
        "identifier",
        "key",
        "element",
        "val",
        "value",
    ];

    for pair in s.split(',') {
        let mut kv = pair.splitn(2, ':');
        let k = kv.next()?.trim().trim_matches('"').trim();
        let v = kv.next()?.trim().trim_matches('"').trim();

        if let Some(hint) = col_hint {
            if k.eq_ignore_ascii_case(hint) {
                return Some(v.to_string());
            }
        } else {
            for dk in &default_keys {
                if k.eq_ignore_ascii_case(dk) {
                    return Some(v.to_string());
                }
            }
        }
    }

    if let Some(first_pair) = s.split(',').next() {
        let mut kv = first_pair.splitn(2, ':');
        if kv.next().is_some() {
            if let Some(v) = kv.next() {
                return Some(v.trim().trim_matches('"').trim().to_string());
            }
        }
    }
    None
}

#[cfg(feature = "std")]
fn parse_json_array(json_arr: &str, col_hint: Option<&str>) -> Vec<String> {
    let inner = json_arr
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim();
    if inner.is_empty() {
        return Vec::new();
    }

    let mut results = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut brace_depth = 0;

    for c in inner.chars() {
        match c {
            '"' => {
                in_quotes = !in_quotes;
                current.push(c);
            }
            '{' if !in_quotes => {
                brace_depth += 1;
                current.push(c);
            }
            '}' if !in_quotes => {
                brace_depth -= 1;
                current.push(c);
            }
            ',' if !in_quotes && brace_depth == 0 => {
                let token = current.trim();
                if !token.is_empty() {
                    if token.starts_with('{') {
                        if let Some(val) = extract_json_object_field(token, col_hint) {
                            results.push(val);
                        }
                    } else {
                        results.push(token.trim_matches('"').to_string());
                    }
                }
                current.clear();
            }
            _ => current.push(c),
        }
    }

    let token = current.trim();
    if !token.is_empty() {
        if token.starts_with('{') {
            if let Some(val) = extract_json_object_field(token, col_hint) {
                results.push(val);
            }
        } else {
            results.push(token.trim_matches('"').to_string());
        }
    }

    results
}

#[cfg(feature = "std")]
fn normalize_records(raw_records: &[String]) -> (Vec<[u8; 32]>, Vec<usize>) {
    let mut elements = Vec::with_capacity(raw_records.len());
    let mut valid_indices = Vec::with_capacity(raw_records.len());

    for (idx, record) in raw_records.iter().enumerate() {
        let mut slot = [0u8; 64];
        let bytes = record.as_bytes();
        let copy_len = bytes.len().min(64);
        slot[..copy_len].copy_from_slice(&bytes[..copy_len]);

        let mut sanitized = [0u8; 64];
        let status = normalize_to_buffer(&slot, &mut sanitized);
        if status == 1 {
            let mut elem = [0u8; 32];
            elem.copy_from_slice(&sanitized[..32]);
            elements.push(elem);
            valid_indices.push(idx);
        }
    }
    (elements, valid_indices)
}

#[cfg(feature = "std")]
fn connect_raw(config: &CliConfig) -> Result<NonaClient, (String, i32)> {
    let mut client = if let Some(port) = config.vsock_port {
        NonaClient::connect_vsock(port)
            .map_err(|e| (format!("Failed to connect to VSOCK port {port}: {e:?}"), 1))?
    } else {
        NonaClient::connect_unix(&config.socket_path).map_err(|e| {
            (
                format!(
                    "Failed to connect to Unix socket '{}': {:?}",
                    config.socket_path, e
                ),
                1,
            )
        })?
    };
    client.allow_simulation_fallback = config.dev_simulation;
    Ok(client)
}

#[cfg(feature = "std")]
fn connect_client(config: &CliConfig) -> Result<NonaClient, (String, i32)> {
    let mut client = connect_raw(config)?;
    let manifest = config
        .manifest_path
        .as_deref()
        .unwrap_or("manifests/enclave_manifest.json");

    client.attest_and_bind(manifest).map_err(|e| {
        (
            format!("Enclave hardware attestation or PCR check failed: {e:?}"),
            1,
        )
    })?;

    Ok(client)
}

#[cfg(feature = "std")]
#[inline(never)]
fn execute_psi_intersection_chunks(
    blinded_local: &[u8],
    target_bytes: &[u8],
    total_a: usize,
    total_b: usize,
    flags: u32,
) -> Result<(Vec<usize>, u64), (String, i32)> {
    let mut matched_local_indices = Vec::new();
    let mut total_cardinality: u64 = 0;

    let chunk_size = 128;
    let mut a_offset = 0;

    let mut aligned_a = AlignedBuffer4096::new_boxed_zeroed();
    let mut aligned_b = AlignedBuffer4096::new_boxed_zeroed();
    let mut aligned_out = AlignedBuffer4096::new_boxed_zeroed();

    while a_offset < total_a {
        let a_chunk_count = std::cmp::min(chunk_size, total_a - a_offset);
        let a_chunk_bytes = &blinded_local[a_offset * 32..(a_offset + a_chunk_count) * 32];

        let mut b_offset = 0;
        let mut chunk_matched = BTreeSet::new();

        while b_offset < total_b {
            let b_chunk_count = std::cmp::min(chunk_size, total_b - b_offset);
            let b_chunk_bytes = &target_bytes[b_offset * 32..(b_offset + b_chunk_count) * 32];

            aligned_a.data.fill(0);
            aligned_b.data.fill(0);
            aligned_out.data.fill(0);
            let mut card_out = AlignedU64(0);

            aligned_a.data[..a_chunk_bytes.len()].copy_from_slice(a_chunk_bytes);
            aligned_b.data[..b_chunk_bytes.len()].copy_from_slice(b_chunk_bytes);

            let rc = unsafe {
                nona_phase2_intersect(
                    aligned_a.data.as_ptr(),
                    a_chunk_bytes.len(),
                    aligned_b.data.as_ptr(),
                    b_chunk_bytes.len(),
                    a_chunk_count,
                    aligned_out.data.as_mut_ptr(),
                    aligned_out.data.len(),
                    flags,
                    &raw mut card_out.0,
                )
            };

            if rc != 0 {
                return Err((format!("Phase 2 intersection failed with code {rc}"), 1));
            }

            if flags == NONA_FLAG_FULL_PSI {
                let card = usize::try_from(card_out.0).unwrap_or(0);
                for i in 0..card {
                    let off = i * 4;
                    if off + 4 <= aligned_out.data.len() {
                        let idx = u32::from_le_bytes([
                            aligned_out.data[off],
                            aligned_out.data[off + 1],
                            aligned_out.data[off + 2],
                            aligned_out.data[off + 3],
                        ]) as usize;
                        chunk_matched.insert(a_offset + idx);
                    }
                }
            } else {
                total_cardinality = total_cardinality.saturating_add(card_out.0);
            }

            b_offset += b_chunk_count;
        }

        if flags == NONA_FLAG_FULL_PSI {
            for idx in chunk_matched {
                matched_local_indices.push(idx);
            }
        }

        a_offset += a_chunk_count;
    }

    Ok((matched_local_indices, total_cardinality))
}

fn run_match(config: &CliConfig) -> Result<(), (String, i32)> {
    let target_path = config
        .target_path
        .as_ref()
        .ok_or_else(|| ("Missing required argument: --target <FILE>".to_string(), 2))?;

    let target_bytes = fs::read(target_path).map_err(|e| {
        (
            format!("Failed to read target file '{target_path}': {e}"),
            2,
        )
    })?;

    if target_bytes.is_empty() || (target_bytes.len() % 32) != 0 {
        return Err((
            format!("Target file '{}' must contain a non-empty multiple of 32-byte blinded tokens (got {} bytes)", target_path, target_bytes.len()),
            2,
        ));
    }

    let input_raw = read_input_data(config.input_file.as_deref())?;
    let raw_records = extract_records(&input_raw, config.column.as_deref());

    if raw_records.is_empty() {
        emit_results(config, &[], &[], 0);
        return Ok(());
    }

    let (elements, valid_orig_indices) = normalize_records(&raw_records);
    if elements.is_empty() {
        emit_results(config, &[], &[], 0);
        return Ok(());
    }

    let mut stream_payload = Vec::with_capacity(elements.len() * 32);
    for elem in &elements {
        stream_payload.extend_from_slice(elem);
    }

    let mut client = connect_client(config)?;
    let blinded_local = if config.dev_simulation {
        let sim_key = [0x42u8; 32];
        client.blind_stream_chunked_with_key(&sim_key, &stream_payload)
    } else {
        client.blind_stream_chunked(&stream_payload)
    }
    .map_err(|e| (format!("Phase 1 blinding stream failed: {e:?}"), 1))?;

    let flags = if config.cardinality_only {
        NONA_FLAG_PSI_CA
    } else {
        NONA_FLAG_FULL_PSI
    };

    let total_a = elements.len();
    let total_b = target_bytes.len() / 32;

    let (matched_local_indices, mut total_cardinality) =
        execute_psi_intersection_chunks(&blinded_local, &target_bytes, total_a, total_b, flags)?;

    if flags == NONA_FLAG_FULL_PSI {
        total_cardinality = matched_local_indices.len() as u64;
    }

    let mut matched_records = Vec::new();
    let mut original_indices = Vec::new();

    for &local_idx in &matched_local_indices {
        if local_idx < valid_orig_indices.len() {
            let orig_idx = valid_orig_indices[local_idx];
            original_indices.push(orig_idx);
            matched_records.push(raw_records[orig_idx].clone());
        }
    }

    emit_results(
        config,
        &original_indices,
        &matched_records,
        total_cardinality,
    );
    Ok(())
}

#[cfg(feature = "std")]
fn emit_results(config: &CliConfig, indices: &[usize], records: &[String], cardinality: u64) {
    if config.cardinality_only {
        match config.format {
            OutputFormat::Json => {
                println!("{{\"cardinality\":{cardinality}}}");
            }
            OutputFormat::Csv => {
                println!("cardinality\n{cardinality}");
            }
            OutputFormat::Text => {
                println!("{cardinality}");
            }
        }
        return;
    }

    match config.format {
        OutputFormat::Text => {
            for record in records {
                println!("{record}");
            }
        }
        OutputFormat::Csv => {
            println!("index,record");
            for (idx, record) in indices.iter().zip(records.iter()) {
                if record.contains(',') || record.contains('"') || record.contains('\n') {
                    let escaped = record.replace('"', "\"\"");
                    println!("{idx},\"{escaped}\"");
                } else {
                    println!("{idx},{record}");
                }
            }
        }
        OutputFormat::Json => {
            print!("{{\"cardinality\":{cardinality},\"indices\":[");
            for (i, idx) in indices.iter().enumerate() {
                if i > 0 {
                    print!(",");
                }
                print!("{idx}");
            }
            print!("],\"matches\":[");
            for (i, rec) in records.iter().enumerate() {
                if i > 0 {
                    print!(",");
                }
                print!("\"{}\"", escape_json_str(rec));
            }
            println!("]}}");
        }
    }
}

#[cfg(feature = "std")]
fn escape_json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            other => out.push(other),
        }
    }
    out
}

#[cfg(feature = "std")]
fn run_blind(config: &CliConfig) -> Result<(), (String, i32)> {
    let input_raw = read_input_data(config.input_file.as_deref())?;
    let raw_records = extract_records(&input_raw, config.column.as_deref());

    if raw_records.is_empty() {
        return Ok(());
    }

    let (elements, _) = normalize_records(&raw_records);
    if elements.is_empty() {
        return Ok(());
    }

    let mut stream_payload = Vec::with_capacity(elements.len() * 32);
    for elem in &elements {
        stream_payload.extend_from_slice(elem);
    }

    let mut client = connect_client(config)?;
    let blinded = if config.dev_simulation {
        let sim_key = [0x42u8; 32];
        client.blind_stream_chunked_with_key(&sim_key, &stream_payload)
    } else {
        client.blind_stream_chunked(&stream_payload)
    }
    .map_err(|e| (format!("Phase 1 blinding failed: {e:?}"), 1))?;

    if let Some(ref out_path) = config.output_file {
        fs::write(out_path, &blinded)
            .map_err(|e| (format!("Failed to write output file '{out_path}': {e}"), 2))?;
    } else {
        io::stdout()
            .write_all(&blinded)
            .map_err(|e| (format!("Failed to write to stdout: {e}"), 2))?;
    }

    Ok(())
}

#[cfg(feature = "std")]
fn run_ping(config: &CliConfig) -> Result<(), (String, i32)> {
    let mut client = connect_raw(config)?;
    let echo = client
        .ping(b"NONA_PING_CLI_2026")
        .map_err(|e| (format!("Ping failed: {e:?}"), 1))?;
    println!("PONG: {}", String::from_utf8_lossy(&echo));
    Ok(())
}

#[cfg(feature = "std")]
fn run_attest(config: &CliConfig) -> Result<(), (String, i32)> {
    let manifest_path = config.manifest_path.as_ref().ok_or_else(|| {
        (
            "Missing required argument: --manifest <FILE>".to_string(),
            2,
        )
    })?;

    let mut client = connect_raw(config)?;
    client
        .attest_and_bind(manifest_path)
        .map_err(|e| (format!("Attestation failed: {e:?}"), 1))?;

    println!("Attestation and PCR measurements verified successfully against {manifest_path}");
    Ok(())
}

#[cfg(feature = "std")]
fn main() {
    let config = match parse_args() {
        Ok(cfg) => cfg,
        Err((err, code)) => {
            eprintln!("Error: {err}");
            process::exit(code);
        }
    };

    let result = match config.subcommand.as_str() {
        "match" => run_match(&config),
        "blind" => run_blind(&config),
        "ping" => run_ping(&config),
        "attest" => run_attest(&config),
        other => {
            eprintln!("Error: Unknown subcommand '{other}'");
            process::exit(2);
        }
    };

    if let Err((err, code)) = result {
        eprintln!("Error: {err}");
        process::exit(code);
    }
}
