// ============================================================================
// BENCHMARK: engine_benchmarks.rs - High-Precision Zero-Allocation Microbenchmarks
// ============================================================================

use std::hint::black_box;
use std::time::{Duration, Instant};

use nona_core::attestation::{derive_compressed_public_key, SECP256K1_PUBKEY_COMPRESSED_SIZE};
use nona_core::crypto::ct_zeroize;
use nona_core::enclave_server::{
    dispatch_frame, EnclaveFrameBuffer, EnclaveRequestHeader, CMD_BLIND_PHASE1, CMD_INGEST,
    CMD_PING, NONA_VSOCK_MAGIC, NONA_VSOCK_VERSION,
};
use nona_core::normalization::{normalize_to_buffer, SanitizedCode};
use nona_core::obfuscation::IndexPermutationCircuit;
use nona_core::psi::{FieldElement, JacobianPoint, Scalar};

#[repr(C, align(64))]
struct AlignedBuffer<const N: usize> {
    data: [u8; N],
}

impl<const N: usize> AlignedBuffer<N> {
    const fn new(val: u8) -> Self {
        Self { data: [val; N] }
    }
}

struct BenchResult {
    name: &'static str,
    iterations: u64,
    elapsed: Duration,
    unit_str: &'static str,
    units_per_op: f64,
}

impl BenchResult {
    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss
    )]
    fn print(&self) {
        let nanos = self.elapsed.as_nanos() as f64;
        let ns_per_op = nanos / self.iterations as f64;
        let ops_per_sec = (self.iterations as f64 / self.elapsed.as_secs_f64()) as u64;

        if self.units_per_op > 1.0 {
            let total_units = (self.iterations as f64 * self.units_per_op) / (1024.0 * 1024.0);
            let mb_per_sec = total_units / self.elapsed.as_secs_f64();
            println!(
                "  {:<42} {:>10.2} ns/op | {:>10} ops/s | {:>9.2} MB/s",
                self.name, ns_per_op, ops_per_sec, mb_per_sec
            );
        } else if ns_per_op >= 1_000_000.0 {
            let ms_per_op = ns_per_op / 1_000_000.0;
            println!(
                "  {:<42} {:>10.2} ms/op | {:>10} ops/s",
                self.name, ms_per_op, ops_per_sec
            );
        } else if ns_per_op >= 1_000.0 {
            let us_per_op = ns_per_op / 1_000.0;
            println!(
                "  {:<42} {:>10.2} µs/op | {:>10} ops/s",
                self.name, us_per_op, ops_per_sec
            );
        } else {
            println!(
                "  {:<42} {:>10.2} ns/op | {:>10} ops/s",
                self.name, ns_per_op, ops_per_sec
            );
        }
    }
}

fn run_bench<F>(name: &'static str, min_duration: Duration, mut f: F) -> BenchResult
where
    F: FnMut(),
{
    // Warm-up
    let warmup_end = Instant::now() + Duration::from_millis(15);
    while Instant::now() < warmup_end {
        f();
    }

    // Benchmark loop
    let mut iterations: u64 = 0;
    let start = Instant::now();
    let target_end = start + min_duration;

    while Instant::now() < target_end || iterations < 10 {
        for _ in 0..10 {
            f();
        }
        iterations += 10;
    }
    let elapsed = start.elapsed();

    BenchResult {
        name,
        iterations,
        elapsed,
        unit_str: "ops",
        units_per_op: 1.0,
    }
}

fn run_throughput_bench<F>(
    name: &'static str,
    bytes_per_op: usize,
    min_duration: Duration,
    mut f: F,
) -> BenchResult
where
    F: FnMut(),
{
    let mut res = run_bench(name, min_duration, &mut f);
    #[allow(clippy::cast_precision_loss)]
    {
        res.units_per_op = bytes_per_op as f64;
    }
    res.unit_str = "bytes";
    res
}

#[inline(never)]
fn bench_sec1_ct_zeroize(bench_dur: Duration) {
    println!("\n[1/6] Constant-Time Volatile Zeroization (ct_zeroize):");
    let mut buf_64 = AlignedBuffer::<64>::new(0xFF);
    run_throughput_bench("ct_zeroize (64 bytes)", 64, bench_dur, || {
        ct_zeroize(black_box(&mut buf_64.data));
    })
    .print();

    let mut buf_512 = AlignedBuffer::<512>::new(0xFF);
    run_throughput_bench("ct_zeroize (512 bytes)", 512, bench_dur, || {
        ct_zeroize(black_box(&mut buf_512.data));
    })
    .print();

    // Isolate 4096-byte buffer in static cell to respect Architectural Invariant §1
    struct StaticBuf4096(core::cell::UnsafeCell<AlignedBuffer<4096>>);
    unsafe impl Sync for StaticBuf4096 {}
    static BUF_4096: StaticBuf4096 =
        StaticBuf4096(core::cell::UnsafeCell::new(AlignedBuffer::new(0xFF)));

    let buf_4096 = unsafe { &mut *BUF_4096.0.get() };
    run_throughput_bench("ct_zeroize (4096 bytes)", 4096, bench_dur, || {
        ct_zeroize(black_box(&mut buf_4096.data));
    })
    .print();
}

#[inline(never)]
fn bench_sec2_normalization(bench_dur: Duration) {
    println!("\n[2/6] Monomorphic Normalization & Feistel Obfuscation:");
    let mut raw_phone_64 = [0u8; 64];
    let phone_seed = b"+1 (415) 555-2671";
    raw_phone_64[..phone_seed.len()].copy_from_slice(phone_seed);

    let mut norm_out = [0u8; 64];
    run_bench("normalize_to_buffer (64-byte window)", bench_dur, || {
        let status = normalize_to_buffer(black_box(&raw_phone_64), black_box(&mut norm_out));
        assert_eq!(status, 1);
    })
    .print();

    let circuit = IndexPermutationCircuit::new(0x0123456789ABCDEF, 0xFEDCBA9876543210);
    run_throughput_bench("Feistel permute (64-bit block)", 8, bench_dur, || {
        let _ = circuit.permute(black_box(0xCAFEBABEDEADBEEF));
    })
    .print();

    #[repr(C, align(64))]
    struct AlignedCode(SanitizedCode);
    let mut aligned_code = AlignedCode(SanitizedCode { data: [0u8; 64] });
    let mut out_idx = 0u64;
    run_bench("nona_normalize_and_obfuscate (C-ABI)", bench_dur, || {
        let status = unsafe {
            nona_core::nona_normalize_and_obfuscate(
                black_box(raw_phone_64.as_ptr()),
                black_box(raw_phone_64.len()),
                black_box(0x0123456789ABCDEF),
                black_box(0xFEDCBA9876543210),
                black_box(&raw mut aligned_code.0),
                black_box(&raw mut out_idx),
            )
        };
        assert_eq!(status, 0);
    })
    .print();
}

#[inline(never)]
fn bench_sec3_field_arithmetic(bench_dur: Duration) {
    println!("\n[3/6] SECP256K1 Field Arithmetic (256-bit Limbs):");
    let fe_a = FieldElement {
        limbs: [
            0x59F2815B16F81798,
            0x029BFCDB2DCE28D9,
            0x55A06295CE870B07,
            0x79BE667EF9DCBBAC,
        ],
    };
    let fe_b = FieldElement {
        limbs: [
            0xABAC09B95C709EE5,
            0x8CEF3CA7ABAC09B9,
            0x3045406E95C07CD8,
            0xC6047F9441ED7D6D,
        ],
    };

    run_bench("FieldElement::mul", bench_dur, || {
        let _ = black_box(&fe_a).mul(black_box(&fe_b));
    })
    .print();

    run_bench("FieldElement::square", bench_dur, || {
        let _ = black_box(&fe_a).square();
    })
    .print();

    run_bench("FieldElement::invert (Fermat Chain)", bench_dur, || {
        let _ = black_box(&fe_a).invert();
    })
    .print();
}

#[inline(never)]
fn bench_sec4_jacobian_points(bench_dur: Duration) {
    println!("\n[4/6] SECP256K1 Homogeneous Projective P^2 Operations (RCB 2016 Alg 4):");
    let g = JacobianPoint::generator();
    let two_g = g.double();

    run_bench("ProjectivePoint::double (Alg 4 unified)", bench_dur, || {
        let _ = black_box(&g).double();
    })
    .print();

    run_bench("ProjectivePoint::add (RCB 2016 Alg 4)", bench_dur, || {
        let _ = black_box(&two_g).add(black_box(&g));
    })
    .print();

    let scalar = Scalar::from_limbs([0x123456789ABCDEF0, 0, 0, 0]);
    run_bench(
        "ProjectivePoint::scalar_mul (256-bit Ladder)",
        bench_dur,
        || {
            let _ = black_box(&g).scalar_mul(black_box(&scalar));
        },
    )
    .print();
}

#[inline(never)]
fn bench_sec5_psi_pipeline(bench_dur: Duration) {
    println!("\n[5/6] High-Throughput PSI Blinding & Key Derivation:");
    let privkey = [0x5Au8; 32];
    let mut pubkey = [0u8; SECP256K1_PUBKEY_COMPRESSED_SIZE];
    run_bench("derive_compressed_public_key (SEC 1)", bench_dur, || {
        let status = derive_compressed_public_key(black_box(&privkey), black_box(&mut pubkey));
        assert_eq!(status, 0);
    })
    .print();

    let align_key = AlignedBuffer::<32>::new(0x42);
    let raw_elements_16 = AlignedBuffer::<{ 16 * 32 }>::new(0x11);
    let mut blinded_out_16 = AlignedBuffer::<{ 16 * 32 }>::new(0x00);
    run_throughput_bench(
        "nona_phase1_blind (16 elements)",
        16 * 32,
        bench_dur,
        || {
            let status = unsafe {
                nona_core::psi::nona_phase1_blind_impl(
                    black_box(raw_elements_16.data.as_ptr()),
                    black_box(raw_elements_16.data.len()),
                    black_box(16),
                    black_box(align_key.data.as_ptr()),
                    black_box(blinded_out_16.data.as_mut_ptr()),
                    black_box(blinded_out_16.data.len()),
                )
            };
            assert_eq!(status, 0);
        },
    )
    .print();

    // Isolate 4096-byte buffers in static storage to strictly comply with < 4 KiB stack ceiling
    struct StaticElements128(core::cell::UnsafeCell<AlignedBuffer<{ 128 * 32 }>>);
    unsafe impl Sync for StaticElements128 {}
    static RAW_128: StaticElements128 =
        StaticElements128(core::cell::UnsafeCell::new(AlignedBuffer::new(0x11)));
    static BLINDED_128: StaticElements128 =
        StaticElements128(core::cell::UnsafeCell::new(AlignedBuffer::new(0x00)));

    let raw_elements_128 = unsafe { &*RAW_128.0.get() };
    let blinded_out_128 = unsafe { &mut *BLINDED_128.0.get() };

    run_throughput_bench(
        "nona_phase1_blind (128 elements)",
        128 * 32,
        bench_dur,
        || {
            let status = unsafe {
                nona_core::psi::nona_phase1_blind_impl(
                    black_box(raw_elements_128.data.as_ptr()),
                    black_box(raw_elements_128.data.len()),
                    black_box(128),
                    black_box(align_key.data.as_ptr()),
                    black_box(blinded_out_128.data.as_mut_ptr()),
                    black_box(blinded_out_128.data.len()),
                )
            };
            assert_eq!(status, 0);
        },
    )
    .print();
}

#[inline(never)]
fn bench_sec6_enclave_dispatch(bench_dur: Duration) {
    println!("\n[6/6] Confidential Enclave Wire Dispatch (dispatch_frame):");
    // EnclaveFrameBuffer is 16 KiB - isolate in static cell to respect Architectural Invariant §1
    struct StaticEnclaveResp(core::cell::UnsafeCell<EnclaveFrameBuffer>);
    unsafe impl Sync for StaticEnclaveResp {}
    static ENCLAVE_RESP: StaticEnclaveResp =
        StaticEnclaveResp(core::cell::UnsafeCell::new(EnclaveFrameBuffer::INIT));

    let enclave_resp = unsafe { &mut *ENCLAVE_RESP.0.get() };
    enclave_resp.purge();

    let ping_payload = b"PING_MICROBENCHMARK_2026";
    let ping_hdr = EnclaveRequestHeader {
        magic: NONA_VSOCK_MAGIC,
        version: NONA_VSOCK_VERSION,
        command: CMD_PING,
        payload_len: u32::try_from(ping_payload.len()).unwrap_or(0),
        flags: 0,
        reserved: [0u8; 16],
    };
    run_bench("dispatch_frame: CMD_PING (echo)", bench_dur, || {
        let (status, _) = dispatch_frame(
            black_box(&ping_hdr),
            black_box(ping_payload),
            black_box(&mut enclave_resp.data),
        );
        assert_eq!(status, 0);
    })
    .print();

    let ingest_payload = AlignedBuffer::<128>::new(0xAA);
    let ingest_hdr = EnclaveRequestHeader {
        magic: NONA_VSOCK_MAGIC,
        version: NONA_VSOCK_VERSION,
        command: CMD_INGEST,
        payload_len: 128,
        flags: 0,
        reserved: [0u8; 16],
    };

    let mut pop_scratch = [0u8; 128];
    while nona_core::ingest::ingest_pop(&mut pop_scratch).is_ok() {}

    run_throughput_bench(
        "dispatch_frame: CMD_INGEST (128 bytes)",
        128,
        bench_dur,
        || {
            let (status, _) = dispatch_frame(
                black_box(&ingest_hdr),
                black_box(&ingest_payload.data),
                black_box(&mut enclave_resp.data),
            );
            assert_eq!(status, 0);
            let _ = nona_core::ingest::ingest_pop(&mut pop_scratch);
        },
    )
    .print();

    let align_key = AlignedBuffer::<32>::new(0x42);
    let mut blind_wire_payload = AlignedBuffer::<{ 32 + 32 * 4 }>::new(0x77);
    blind_wire_payload.data[0..32].copy_from_slice(&align_key.data);

    let blind_hdr = EnclaveRequestHeader {
        magic: NONA_VSOCK_MAGIC,
        version: NONA_VSOCK_VERSION,
        command: CMD_BLIND_PHASE1,
        payload_len: u32::try_from(blind_wire_payload.data.len()).unwrap_or(0),
        flags: 0,
        reserved: [0u8; 16],
    };
    run_bench(
        "dispatch_frame: CMD_BLIND_PHASE1 (4 elements)",
        bench_dur,
        || {
            let (status, _) = dispatch_frame(
                black_box(&blind_hdr),
                black_box(&blind_wire_payload.data),
                black_box(&mut enclave_resp.data),
            );
            assert_eq!(status, 0);
        },
    )
    .print();
}

fn main() {
    println!(
        "========================================================================================="
    );
    println!("NONA CORE ENGINE: PERFORMANCE MICROBENCHMARK SUITE");
    println!(
        "========================================================================================="
    );

    let bench_dur = Duration::from_millis(150);

    bench_sec1_ct_zeroize(bench_dur);
    bench_sec2_normalization(bench_dur);
    bench_sec3_field_arithmetic(bench_dur);
    bench_sec4_jacobian_points(bench_dur);
    bench_sec5_psi_pipeline(bench_dur);
    bench_sec6_enclave_dispatch(bench_dur);

    println!("=========================================================================================\n");
}
