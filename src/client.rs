//! Host-side client driver establishing dual transport (AF_VSOCK / AF_UNIX) with the
//! Nona Enclave wire daemon, enforcing hardware attestation, PCR integrity, and chunked streaming.

#![cfg(feature = "std")]

use std::fs::File;
use std::io::{Read, Write};
use std::ops::{Deref, DerefMut};
use std::os::unix::net::UnixStream;
use zeroize::Zeroize;

#[repr(C, align(64))]
struct ChunkBuffer {
    data: [u8; CHUNK_BYTES],
}

impl ChunkBuffer {
    #[allow(clippy::cast_ptr_alignment)]
    fn new_boxed() -> Box<Self> {
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

impl Drop for ChunkBuffer {
    #[inline]
    fn drop(&mut self) {
        self.data.zeroize();
    }
}

impl Deref for ChunkBuffer {
    type Target = [u8; CHUNK_BYTES];
    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl DerefMut for ChunkBuffer {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data
    }
}

use crate::crypto::{ecdsa_p384_verify, sha512_digest};
use crate::enclave_server::{
    EnclaveRequestHeader, EnclaveResponseHeader, CMD_ATTEST, CMD_BLIND_PHASE1, CMD_INGEST,
    CMD_PING, FLAG_USE_SESSION_KEY, NONA_VSOCK_MAGIC, NONA_VSOCK_VERSION,
};

pub const DEFAULT_UNIX_SOCKET_PATH: &str = "/tmp/nona.sock";
pub const DEFAULT_VSOCK_PORT: u32 = 5005;
pub const DEFAULT_VSOCK_CID: u32 = 16;
pub const STREAM_CHUNK_ELEMENTS: usize = 128;
pub const ELEMENT_BYTES: usize = 32;
pub const CHUNK_BYTES: usize = STREAM_CHUNK_ELEMENTS * ELEMENT_BYTES; // 4096 bytes

#[derive(Debug)]
pub enum ClientError {
    IoError(std::io::Error),
    ConnectionFailed,
    InvalidHeader,
    ServerStatusError(i32),
    HardwareAttestationUnavailable,
    AttestationValidationFailed(&'static str),
    PcrMismatch(&'static str),
    KeyBindingMismatch,
    CborParseError,
}

impl From<std::io::Error> for ClientError {
    fn from(err: std::io::Error) -> Self {
        ClientError::IoError(err)
    }
}

pub struct VsockStream {
    fd: std::os::unix::io::RawFd,
}

impl Drop for VsockStream {
    fn drop(&mut self) {
        if self.fd >= 0 {
            unsafe {
                libc::close(self.fd);
            }
        }
    }
}

impl Read for VsockStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let ret = unsafe { libc::read(self.fd, buf.as_mut_ptr().cast(), buf.len()) };
        if ret < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            usize::try_from(ret).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
        }
    }
}

impl Write for VsockStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let ret = unsafe { libc::write(self.fd, buf.as_ptr().cast(), buf.len()) };
        if ret < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            usize::try_from(ret).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub enum TransportStream {
    Unix(UnixStream),
    Vsock(VsockStream),
}

impl Read for TransportStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Unix(s) => s.read(buf),
            Self::Vsock(s) => s.read(buf),
        }
    }
}

impl Write for TransportStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Unix(s) => s.write(buf),
            Self::Vsock(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Unix(s) => s.flush(),
            Self::Vsock(s) => s.flush(),
        }
    }
}

pub struct NonaClient {
    stream: TransportStream,
    pub session_pubkey: [u8; 33],
    pub attested: bool,
    pub allow_simulation_fallback: bool,
    pub last_verified_attest_secs: u64,
    pub challenge_rtt_ns: u64,
}

struct ExtractedPcrTriple<'a> {
    pcr0: Option<&'a [u8]>,
    pcr1: Option<&'a [u8]>,
    pcr2: Option<&'a [u8]>,
}

struct ExtractedAttestationClaims<'a> {
    user_data: Option<&'a [u8]>,
    nonce: Option<&'a [u8]>,
    timestamp_ms: Option<u64>,
    pcr0: Option<&'a [u8]>,
    pcr1: Option<&'a [u8]>,
    pcr2: Option<&'a [u8]>,
    leaf_cert: Option<&'a [u8]>,
    cabundle: Option<Vec<&'a [u8]>>,
}

impl NonaClient {
    pub fn connect_unix(path: &str) -> Result<Self, ClientError> {
        let stream = UnixStream::connect(path).map_err(|_| ClientError::ConnectionFailed)?;
        Ok(Self {
            stream: TransportStream::Unix(stream),
            session_pubkey: [0u8; 33],
            attested: false,
            allow_simulation_fallback: false,
            last_verified_attest_secs: 0,
            challenge_rtt_ns: 0,
        })
    }

    pub fn connect_vsock(port: u32) -> Result<Self, ClientError> {
        let cid = std::env::var("NONA_VSOCK_CID")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(DEFAULT_VSOCK_CID);
        Self::connect_vsock_cid(cid, port)
    }

    pub fn connect_vsock_cid(cid: u32, port: u32) -> Result<Self, ClientError> {
        #[cfg(target_os = "linux")]
        {
            use crate::enclave_server::{sockaddr_vm, AF_VSOCK};
            use core::mem::size_of;

            let fd = unsafe { libc::socket(AF_VSOCK, libc::SOCK_STREAM, 0) };
            if fd < 0 {
                return Err(ClientError::ConnectionFailed);
            }

            let addr = sockaddr_vm::new(port, cid);
            let ret = unsafe {
                libc::connect(
                    fd,
                    (&raw const addr).cast::<libc::sockaddr>(),
                    size_of::<sockaddr_vm>() as libc::socklen_t,
                )
            };

            if ret < 0 {
                unsafe { libc::close(fd); }
                return Err(ClientError::ConnectionFailed);
            }

            Ok(Self {
                stream: TransportStream::Vsock(VsockStream { fd }),
                session_pubkey: [0u8; 33],
                attested: false,
                allow_simulation_fallback: false,
                last_verified_attest_secs: 0,
                challenge_rtt_ns: 0,
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (cid, port);
            Err(ClientError::ConnectionFailed)
        }
    }

    pub fn ping(&mut self, payload: &[u8]) -> Result<Vec<u8>, ClientError> {
        self.send_command(CMD_PING, 0, payload)
    }

    pub fn ingest_chunk(&mut self, chunk_128_bytes: &[u8]) -> Result<(), ClientError> {
        if !self.attested {
            return Err(ClientError::AttestationValidationFailed(
                "Channel unauthenticated: attestation required before ingest",
            ));
        }
        if chunk_128_bytes.len() != 128 && chunk_128_bytes.len() != 4096 {
            return Err(ClientError::InvalidHeader);
        }
        let _ = self.send_command(CMD_INGEST, 0, chunk_128_bytes)?;
        Ok(())
    }

    pub fn blind_phase1(&mut self, raw_elements: &[u8]) -> Result<Vec<u8>, ClientError> {
        if !self.attested {
            return Err(ClientError::AttestationValidationFailed(
                "Channel unauthenticated: attestation required before blinding",
            ));
        }
        self.send_command(CMD_BLIND_PHASE1, FLAG_USE_SESSION_KEY, raw_elements)
    }

    pub fn blind_phase1_with_key(
        &mut self,
        key: &[u8; 32],
        raw_elements: &[u8],
    ) -> Result<Vec<u8>, ClientError> {
        if !self.attested {
            return Err(ClientError::AttestationValidationFailed(
                "Channel unauthenticated: attestation required before blinding",
            ));
        }
        let mut framed = Vec::with_capacity(32 + raw_elements.len());
        framed.extend_from_slice(key);
        framed.extend_from_slice(raw_elements);
        let res = self.send_command(CMD_BLIND_PHASE1, 0, &framed);
        framed.zeroize();
        res
    }

    fn blind_stream_chunked_inner(
        &mut self,
        explicit_key: Option<&[u8; 32]>,
        stream_data: &[u8],
    ) -> Result<Vec<u8>, ClientError> {
        if !self.attested {
            return Err(ClientError::AttestationValidationFailed(
                "Channel unauthenticated: attestation required before blinding",
            ));
        }
        if stream_data.is_empty() || !stream_data.len().is_multiple_of(ELEMENT_BYTES) {
            return Err(ClientError::InvalidHeader);
        }

        let total_elements = stream_data.len() / ELEMENT_BYTES;
        let mut results = Vec::with_capacity(stream_data.len());
        let mut chunk_staging = ChunkBuffer::new_boxed();

        let mut offset = 0;
        while offset < stream_data.len() {
            let rem_bytes = stream_data.len() - offset;
            let current_chunk_bytes = std::cmp::min(rem_bytes, CHUNK_BYTES);
            let active_elements = current_chunk_bytes / ELEMENT_BYTES;

            chunk_staging[..current_chunk_bytes]
                .copy_from_slice(&stream_data[offset..offset + current_chunk_bytes]);

            // Task 1.4: Asymmetric Tail Padding & Masking out to 128 elements using dummy point
            if active_elements < STREAM_CHUNK_ELEMENTS {
                let dummy_elem = [0xFFu8; ELEMENT_BYTES];
                for i in active_elements..STREAM_CHUNK_ELEMENTS {
                    chunk_staging[i * ELEMENT_BYTES..(i + 1) * ELEMENT_BYTES]
                        .copy_from_slice(&dummy_elem);
                }
            }

            let blinded_chunk = match explicit_key {
                Some(key) => self.blind_phase1_with_key(key, &chunk_staging.data)?,
                None => self.blind_phase1(&chunk_staging.data)?,
            };
            results.extend_from_slice(&blinded_chunk[..active_elements * ELEMENT_BYTES]);
            offset += current_chunk_bytes;
        }

        chunk_staging.fill(0);
        if results.len() != total_elements * ELEMENT_BYTES {
            return Err(ClientError::InvalidHeader);
        }
        Ok(results)
    }

    pub fn blind_stream_chunked(&mut self, stream_data: &[u8]) -> Result<Vec<u8>, ClientError> {
        self.blind_stream_chunked_inner(None, stream_data)
    }

    pub fn blind_stream_chunked_with_key(
        &mut self,
        key: &[u8; 32],
        stream_data: &[u8],
    ) -> Result<Vec<u8>, ClientError> {
        self.blind_stream_chunked_inner(Some(key), stream_data)
    }

    pub fn verify_manifest_pcrs(
        manifest_path: &str,
        runtime_pcr0: &[u8],
        runtime_pcr1: &[u8],
        runtime_pcr2: &[u8],
    ) -> Result<(), ClientError> {
        if runtime_pcr0.len() != 48 {
            return Err(ClientError::PcrMismatch("Invalid runtime PCR0 byte length"));
        }
        if runtime_pcr1.len() != 48 {
            return Err(ClientError::PcrMismatch("Invalid runtime PCR1 byte length"));
        }
        if runtime_pcr2.len() != 48 {
            return Err(ClientError::PcrMismatch("Invalid runtime PCR2 byte length"));
        }

        let policy = ManifestPcrPolicy::from_manifest_file(manifest_path)?;

        if !ct_eq_48(&policy.pcr0, runtime_pcr0) {
            return Err(ClientError::PcrMismatch("PCR0 integrity violation"));
        }
        if !ct_eq_48(&policy.pcr1, runtime_pcr1) {
            return Err(ClientError::PcrMismatch("PCR1 integrity violation"));
        }
        if !ct_eq_48(&policy.pcr2, runtime_pcr2) {
            return Err(ClientError::PcrMismatch("PCR2 integrity violation"));
        }
        Ok(())
    }

    pub fn verify_simulation_manifest(manifest_path: &str) -> Result<(), ClientError> {
        let _policy = ManifestPcrPolicy::from_manifest_file(manifest_path)?;
        Ok(())
    }

    /// Generates a 256-bit cryptographic challenge nonce bound to OS CSPRNG entropy,
    /// a strictly monotonic atomic sequence counter, and monotonic `Instant` ticks.
    /// Completely isolated from untrusted host/hypervisor wall-clock (`SystemTime`) (FR-36-TIMEWARP).
    pub fn generate_client_challenge_nonce() -> Result<[u8; 32], ClientError> {
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::sync::OnceLock;
        use std::time::Instant;

        static NONCE_SEQ: AtomicU64 = AtomicU64::new(1);
        static NONCE_EPOCH: OnceLock<Instant> = OnceLock::new();

        let mut os_rand = [0u8; 32];
        let dev_path = b"/dev/urandom\0";
        let fd = unsafe { libc::open(dev_path.as_ptr().cast::<libc::c_char>(), libc::O_RDONLY) };
        if fd < 0 {
            return Err(ClientError::AttestationValidationFailed(
                "OS CSPRNG unavailable for challenge nonce",
            ));
        }
        let mut total_read = 0usize;
        while total_read < os_rand.len() {
            let n = unsafe {
                libc::read(
                    fd,
                    os_rand[total_read..].as_mut_ptr().cast(),
                    os_rand.len() - total_read,
                )
            };
            if n <= 0 {
                unsafe {
                    libc::close(fd);
                }
                os_rand.zeroize();
                return Err(ClientError::AttestationValidationFailed(
                    "Short read from OS CSPRNG for challenge nonce",
                ));
            }
            let Ok(chunk) = usize::try_from(n) else {
                unsafe {
                    libc::close(fd);
                }
                os_rand.zeroize();
                return Err(ClientError::AttestationValidationFailed(
                    "Invalid OS CSPRNG read count",
                ));
            };
            total_read += chunk;
        }
        unsafe {
            libc::close(fd);
        }

        let mut acc = 0u8;
        for &b in &os_rand {
            acc |= b;
        }
        if acc == 0 {
            return Err(ClientError::AttestationValidationFailed(
                "Degenerate all-zero OS CSPRNG output",
            ));
        }

        let origin = NONCE_EPOCH.get_or_init(Instant::now);
        let mono_nanos = u64::try_from(origin.elapsed().as_nanos()).unwrap_or(u64::MAX);
        let seq = NONCE_SEQ.fetch_add(1, Ordering::SeqCst);

        let mut seed = [0u8; 48];
        seed[0..32].copy_from_slice(&os_rand);
        seed[32..40].copy_from_slice(&mono_nanos.to_le_bytes());
        seed[40..48].copy_from_slice(&seq.to_le_bytes());
        os_rand.zeroize();

        let digest = sha512_digest(&seed);
        seed.zeroize();
        let mut nonce = [0u8; 32];
        nonce.copy_from_slice(&digest[..32]);
        Ok(nonce)
    }

    /// Advances a monotonic reference clock anchored at initial observation plus `Instant::elapsed()`.
    /// Prevents backward hypervisor/host wall-clock warps from regressing reference timestamps
    /// to resurrect expired attestation documents or certificates (FR-36-TIMEWARP).
    pub fn advance_monotonic_reference_secs(observed_wall_secs: u64) -> u64 {
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::sync::OnceLock;
        use std::time::Instant;

        static MONO_ANCHOR: OnceLock<(u64, Instant)> = OnceLock::new();
        static REF_HWM_SECS: AtomicU64 = AtomicU64::new(0);

        let (anchor_secs, anchor_inst) =
            *MONO_ANCHOR.get_or_init(|| (observed_wall_secs, Instant::now()));
        let mono_floor = anchor_secs.saturating_add(anchor_inst.elapsed().as_secs());
        let candidate = observed_wall_secs.max(mono_floor);

        let mut prev = REF_HWM_SECS.load(Ordering::SeqCst);
        loop {
            let next = prev.max(candidate);
            match REF_HWM_SECS.compare_exchange_weak(
                prev,
                next,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => return next,
                Err(actual) => prev = actual,
            }
        }
    }

    fn current_monotonic_reference_secs() -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        let wall_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        Self::advance_monotonic_reference_secs(wall_secs)
    }

    /// Enforces monotonic progression of hardware-signed attestation timestamps across sessions.
    /// Rejects backward time-warped attestation documents while advancing the high-water mark.
    fn enforce_monotonic_attest_hwm(attest_secs: u64) -> Result<(), ClientError> {
        use std::sync::atomic::{AtomicU64, Ordering};

        static ATTEST_HWM_SECS: AtomicU64 = AtomicU64::new(0);

        let mut prev = ATTEST_HWM_SECS.load(Ordering::SeqCst);
        loop {
            if prev > 0 && attest_secs.saturating_add(MAX_ATTESTATION_CLOCK_SKEW_SECS) < prev {
                return Err(ClientError::AttestationValidationFailed(
                    "Attestation timestamp regressed below monotonic high-water mark",
                ));
            }
            let next = prev.max(attest_secs);
            match ATTEST_HWM_SECS.compare_exchange_weak(
                prev,
                next,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => return Ok(()),
                Err(actual) => prev = actual,
            }
        }
    }

    /// Validates that a live cryptographic challenge-response round-trip completed within
    /// the strict monotonic interval ceiling (`MAX_CHALLENGE_RESPONSE_INTERVAL_NS`).
    pub fn validate_challenge_response_interval(rtt_ns: u64) -> Result<(), ClientError> {
        if rtt_ns > MAX_CHALLENGE_RESPONSE_INTERVAL_NS {
            return Err(ClientError::AttestationValidationFailed(
                "Challenge-response interval exceeded monotonic bound",
            ));
        }
        Ok(())
    }

    pub fn attest_and_bind(&mut self, manifest_path: &str) -> Result<(), ClientError> {
        use std::time::Instant;

        if manifest_path.trim().is_empty() {
            return Err(ClientError::PcrMismatch(
                "Manifest path required for PCR policy pinning",
            ));
        }
        let challenge_nonce = Self::generate_client_challenge_nonce()?;
        let challenge_start = Instant::now();
        let resp = match self.send_command(CMD_ATTEST, 0, &challenge_nonce) {
            Ok(r) => r,
            Err(ClientError::ServerStatusError(-110)) => {
                if self.allow_simulation_fallback {
                    Self::verify_simulation_manifest(manifest_path)?;
                    self.attested = true;
                    return Ok(());
                }
                return Err(ClientError::HardwareAttestationUnavailable);
            }
            Err(ClientError::ServerStatusError(-112)) => {
                return Err(ClientError::AttestationValidationFailed(
                    "Attestation frame buffer overflow",
                ));
            }
            Err(e) => return Err(e),
        };
        let rtt_ns = u64::try_from(challenge_start.elapsed().as_nanos()).unwrap_or(u64::MAX);
        Self::validate_challenge_response_interval(rtt_ns)?;

        if resp.len() <= 33 {
            return Err(ClientError::AttestationValidationFailed(
                "Truncated attestation",
            ));
        }

        self.session_pubkey.copy_from_slice(&resp[..33]);
        if self.session_pubkey[0] != 0x02 && self.session_pubkey[0] != 0x03 {
            return Err(ClientError::KeyBindingMismatch);
        }
        let doc_bytes = &resp[33..];

        let expected_user_data = sha512_digest(&self.session_pubkey);
        let verified_attest_secs = Self::verify_live_challenge_attestation_with_root(
            doc_bytes,
            &expected_user_data,
            &challenge_nonce,
            rtt_ns,
            manifest_path,
            &crate::aws_root_ca::AWS_NITRO_ROOT_CA_DER,
        )?;

        self.last_verified_attest_secs = verified_attest_secs;
        self.challenge_rtt_ns = rtt_ns;
        self.attested = true;
        Ok(())
    }

    #[inline(never)]
    fn peel_outer_attestation_doc<'a>(
        root: &'a CborValue<'a>,
    ) -> Result<Option<CborValue<'a>>, ClientError> {
        if let CborValue::Map(entries) = root {
            let mut inner_doc_bytes: Option<&[u8]> = None;
            for (k, v) in entries {
                if let CborValue::Text("Attestation") = k {
                    if let CborValue::Map(inner_entries) = v {
                        for (ik, iv) in inner_entries {
                            if let CborValue::Text("document") = ik {
                                if let CborValue::Bytes(b) = iv {
                                    inner_doc_bytes = Some(b);
                                    break;
                                }
                            }
                        }
                    } else if let CborValue::Bytes(b) = v {
                        inner_doc_bytes = Some(b);
                        break;
                    }
                } else if let CborValue::Text("document") = k {
                    if let CborValue::Bytes(b) = v {
                        inner_doc_bytes = Some(b);
                        break;
                    }
                }
            }
            if let Some(doc_slice) = inner_doc_bytes {
                let mut unpeeled_parser = CborParser::new(doc_slice);
                let val = unpeeled_parser.parse_value()?;
                if !unpeeled_parser.is_eof() {
                    return Err(ClientError::CborParseError);
                }
                return Ok(Some(val));
            }
        }
        Ok(None)
    }

    fn verify_cose_protected_headers(protected_bytes: &[u8]) -> Result<(), ClientError> {
        if protected_bytes.is_empty() {
            return Err(ClientError::AttestationValidationFailed(
                "Empty COSE protected header",
            ));
        }
        let mut hdr_parser = CborParser::new(protected_bytes);
        let hdr_val = hdr_parser.parse_value()?;
        if !hdr_parser.is_eof() {
            return Err(ClientError::CborParseError);
        }
        let CborValue::Map(entries) = hdr_val else {
            return Err(ClientError::CborParseError);
        };

        let mut seen_alg = false;
        let mut seen_keys: Vec<&CborValue<'_>> = Vec::with_capacity(entries.len());
        for (k, v) in &entries {
            if seen_keys.contains(&k) {
                return Err(ClientError::CborParseError);
            }
            seen_keys.push(k);

            // RFC 8152 Table 1: header parameter 1 = alg, -35 (Negative(34)) = ES384
            if let CborValue::Unsigned(1) = k {
                match v {
                    CborValue::Negative(34) => {
                        seen_alg = true;
                    }
                    _ => {
                        return Err(ClientError::AttestationValidationFailed(
                            "Unsupported COSE signature algorithm (expected ES384)",
                        ));
                    }
                }
            }
        }

        if !seen_alg {
            return Err(ClientError::AttestationValidationFailed(
                "Missing alg=ES384 in COSE protected header",
            ));
        }
        Ok(())
    }

    fn build_cose_sig_structure(protected_bytes: &[u8], payload_bytes: &[u8]) -> Vec<u8> {
        // RFC 8152 §4.4: Sig_structure = ["Signature1", body_protected, external_aad, payload]
        let mut out = Vec::with_capacity(24 + protected_bytes.len() + payload_bytes.len());
        // Array of 4 items (0x84)
        out.push(0x84);
        // Item 0: text(10) "Signature1"
        out.push(0x6a);
        out.extend_from_slice(b"Signature1");
        // Item 1: body_protected bstr
        encode_cbor_bstr_header(&mut out, protected_bytes.len());
        out.extend_from_slice(protected_bytes);
        // Item 2: external_aad empty bstr (0x40)
        out.push(0x40);
        // Item 3: payload bstr
        encode_cbor_bstr_header(&mut out, payload_bytes.len());
        out.extend_from_slice(payload_bytes);
        out
    }

    pub fn parse_and_verify_cose_attestation(
        doc_bytes: &[u8],
        expected_user_data: &[u8; 64],
        manifest_path: &str,
    ) -> Result<(), ClientError> {
        Self::parse_and_verify_cose_attestation_with_nonce(
            doc_bytes,
            expected_user_data,
            None,
            manifest_path,
        )
    }

    /// Verifies a COSE_Sign1 attestation document against an explicit verified external timestamp
    /// (`verified_unix_secs`), completely isolated from untrusted local wall-clock time (FR-36-TIMEWARP).
    pub fn parse_and_verify_cose_attestation_at(
        doc_bytes: &[u8],
        expected_user_data: &[u8; 64],
        expected_nonce: Option<&[u8]>,
        manifest_path: &str,
        verified_unix_secs: u64,
    ) -> Result<(), ClientError> {
        Self::parse_and_verify_cose_attestation_full(
            doc_bytes,
            expected_user_data,
            expected_nonce,
            manifest_path,
            &crate::aws_root_ca::AWS_NITRO_ROOT_CA_DER,
            verified_unix_secs,
        )
    }

    pub fn parse_and_verify_cose_attestation_with_nonce(
        doc_bytes: &[u8],
        expected_user_data: &[u8; 64],
        expected_nonce: Option<&[u8]>,
        manifest_path: &str,
    ) -> Result<(), ClientError> {
        Self::parse_and_verify_cose_attestation_full(
            doc_bytes,
            expected_user_data,
            expected_nonce,
            manifest_path,
            &crate::aws_root_ca::AWS_NITRO_ROOT_CA_DER,
            Self::current_monotonic_reference_secs(),
        )
    }

    /// Verifies a live challenge-response COSE_Sign1 attestation document using:
    /// 1) Monotonic round-trip interval bound (`rtt_ns <= MAX_CHALLENGE_RESPONSE_INTERVAL_NS`),
    /// 2) Constant-time cryptographic nonce & user_data key binding,
    /// 3) Hardware-signed NSM timestamp (`attest_secs`) checked against a monotonic high-water mark,
    /// 4) Full P-384 X.509 certificate chain validation at `attest_secs` and PCR pinning.
    ///
    /// Zero dependency on untrusted host/hypervisor `SystemTime` (FR-36-TIMEWARP).
    pub fn verify_live_challenge_attestation_with_root(
        doc_bytes: &[u8],
        expected_user_data: &[u8; 64],
        challenge_nonce: &[u8; 32],
        rtt_ns: u64,
        manifest_path: &str,
        trusted_root_der: &[u8],
    ) -> Result<u64, ClientError> {
        Self::validate_challenge_response_interval(rtt_ns)?;
        let attest_secs = Self::extract_and_verify_attestation_core(
            doc_bytes,
            expected_user_data,
            Some(challenge_nonce),
            manifest_path,
            trusted_root_der,
            None,
        )?;
        Self::enforce_monotonic_attest_hwm(attest_secs)?;
        Ok(attest_secs)
    }

    #[inline(never)]
    fn verify_cose_chain_and_signature(
        protected_bytes: &[u8],
        payload_bytes: &[u8],
        sig_bytes: &[u8],
        leaf_cert_der: &[u8],
        cabundle: &[&[u8]],
        trusted_root_der: &[u8],
        attest_secs: u64,
    ) -> Result<(), ClientError> {
        let leaf_pubkey = crate::aws_root_ca::verify_x509_chain(
            leaf_cert_der,
            cabundle,
            trusted_root_der,
            attest_secs,
        )
        .map_err(|_| {
            ClientError::AttestationValidationFailed(
                "X.509 certificate chain validation to trusted Root CA failed",
            )
        })?;

        let sig_structure = Self::build_cose_sig_structure(protected_bytes, payload_bytes);
        let mut sig_r = [0u8; 48];
        let mut sig_s = [0u8; 48];
        sig_r.copy_from_slice(&sig_bytes[..48]);
        sig_s.copy_from_slice(&sig_bytes[48..96]);
        if !ecdsa_p384_verify(&leaf_pubkey, &sig_structure, &sig_r, &sig_s) {
            return Err(ClientError::AttestationValidationFailed(
                "COSE_Sign1 ECDSA-P384 signature verification failed",
            ));
        }
        Ok(())
    }

    #[inline(never)]
    fn parse_pcr_map_entries<'a>(
        pcr_map: &[(CborValue<'a>, CborValue<'a>)],
    ) -> Result<ExtractedPcrTriple<'a>, ClientError> {
        let mut pcrs = ExtractedPcrTriple {
            pcr0: None,
            pcr1: None,
            pcr2: None,
        };
        for (pk, pv) in pcr_map {
            match pk {
                CborValue::Unsigned(0) => {
                    let CborValue::Bytes(pcr_bytes) = pv else {
                        return Err(ClientError::CborParseError);
                    };
                    if pcrs.pcr0.is_some() {
                        return Err(ClientError::CborParseError);
                    }
                    pcrs.pcr0 = Some(*pcr_bytes);
                }
                CborValue::Unsigned(1) => {
                    let CborValue::Bytes(pcr_bytes) = pv else {
                        return Err(ClientError::CborParseError);
                    };
                    if pcrs.pcr1.is_some() {
                        return Err(ClientError::CborParseError);
                    }
                    pcrs.pcr1 = Some(*pcr_bytes);
                }
                CborValue::Unsigned(2) => {
                    let CborValue::Bytes(pcr_bytes) = pv else {
                        return Err(ClientError::CborParseError);
                    };
                    if pcrs.pcr2.is_some() {
                        return Err(ClientError::CborParseError);
                    }
                    pcrs.pcr2 = Some(*pcr_bytes);
                }
                _ => {}
            }
        }
        Ok(pcrs)
    }

    #[inline(never)]
    fn extract_attestation_payload_claims<'a>(
        payload_bytes: &'a [u8],
    ) -> Result<ExtractedAttestationClaims<'a>, ClientError> {
        let mut payload_parser = CborParser::new(payload_bytes);
        let payload_val = payload_parser.parse_value()?;
        if !payload_parser.is_eof() {
            return Err(ClientError::CborParseError);
        }
        let CborValue::Map(entries) = &payload_val else {
            return Err(ClientError::CborParseError);
        };

        let mut claims = ExtractedAttestationClaims {
            user_data: None,
            nonce: None,
            timestamp_ms: None,
            pcr0: None,
            pcr1: None,
            pcr2: None,
            leaf_cert: None,
            cabundle: None,
        };

        let mut seen_top_keys: Vec<&str> = Vec::with_capacity(entries.len());

        for (k, v) in entries {
            let CborValue::Text(key) = k else {
                return Err(ClientError::CborParseError);
            };
            if seen_top_keys.contains(key) {
                return Err(ClientError::CborParseError);
            }
            seen_top_keys.push(key);

            match *key {
                "user_data" => {
                    if let CborValue::Bytes(ud) = v {
                        claims.user_data = Some(*ud);
                    }
                }
                "nonce" => {
                    if let CborValue::Bytes(n) = v {
                        claims.nonce = Some(*n);
                    }
                }
                "timestamp" => {
                    let CborValue::Unsigned(ts_ms) = v else {
                        return Err(ClientError::CborParseError);
                    };
                    claims.timestamp_ms = Some(*ts_ms);
                }
                "pcrs" => {
                    let CborValue::Map(pcr_map) = v else {
                        return Err(ClientError::CborParseError);
                    };
                    let pcrs = Self::parse_pcr_map_entries(pcr_map)?;
                    claims.pcr0 = pcrs.pcr0;
                    claims.pcr1 = pcrs.pcr1;
                    claims.pcr2 = pcrs.pcr2;
                }
                "cabundle" => {
                    let CborValue::Array(certs) = v else {
                        return Err(ClientError::CborParseError);
                    };
                    let mut chain = Vec::with_capacity(certs.len());
                    for cert in certs {
                        let CborValue::Bytes(cert_der) = cert else {
                            return Err(ClientError::CborParseError);
                        };
                        chain.push(*cert_der);
                    }
                    claims.cabundle = Some(chain);
                }
                "certificate" => {
                    let CborValue::Bytes(cert_der) = v else {
                        return Err(ClientError::CborParseError);
                    };
                    claims.leaf_cert = Some(*cert_der);
                }
                _ => {}
            }
        }

        Ok(claims)
    }

    #[inline(never)]
    fn verify_extracted_attestation_claims(
        protected_bytes: &[u8],
        payload_bytes: &[u8],
        sig_bytes: &[u8],
        expected_user_data: &[u8; 64],
        expected_nonce: Option<&[u8]>,
        manifest_path: &str,
        trusted_root_der: &[u8],
        verified_unix_secs: Option<u64>,
    ) -> Result<u64, ClientError> {
        let claims = Self::extract_attestation_payload_claims(payload_bytes)?;

        // 1. Verify User Data Key Binding in Constant Time
        let ud = claims.user_data.ok_or(ClientError::KeyBindingMismatch)?;
        if ud.len() != 64 {
            return Err(ClientError::KeyBindingMismatch);
        }
        let mut diff = 0u8;
        for (a, b) in ud.iter().zip(expected_user_data.iter()) {
            diff |= a ^ b;
        }
        if diff != 0 {
            return Err(ClientError::KeyBindingMismatch);
        }

        // 2. Verify Cryptographic Challenge Nonce when Supplied
        if let Some(exp_nonce) = expected_nonce {
            let actual_nonce = claims.nonce.ok_or(ClientError::AttestationValidationFailed(
                "Missing required cryptographic nonce in attestation document",
            ))?;
            if !crate::aws_root_ca::ct_bytes_eq(actual_nonce, exp_nonce) {
                return Err(ClientError::AttestationValidationFailed(
                    "Attestation challenge nonce mismatch",
                ));
            }
        }

        // 3. Enforce Hardware-Signed Timestamp Presence & Optional External Reference Bounds
        let ts_ms = claims
            .timestamp_ms
            .ok_or(ClientError::AttestationValidationFailed(
                "Missing timestamp in attestation document",
            ))?;
        if ts_ms == 0 {
            return Err(ClientError::AttestationValidationFailed(
                "Zero timestamp in attestation document",
            ));
        }
        let attest_secs = ts_ms / 1000;
        if let Some(ref_secs) = verified_unix_secs {
            if attest_secs > ref_secs.saturating_add(MAX_ATTESTATION_CLOCK_SKEW_SECS) {
                return Err(ClientError::AttestationValidationFailed(
                    "Attestation document timestamp is future-dated",
                ));
            }
            if ref_secs > attest_secs.saturating_add(MAX_ATTESTATION_AGE_SECS) {
                return Err(ClientError::AttestationValidationFailed(
                    "Attestation document has expired",
                ));
            }
        }

        // 4 & 5. Validate X.509 Certificate Chain up to Pinned Root CA & Verify COSE ES384 Signature
        let leaf_cert_der = claims
            .leaf_cert
            .ok_or(ClientError::AttestationValidationFailed(
                "Missing leaf certificate in attestation document",
            ))?;
        let cabundle = claims
            .cabundle
            .ok_or(ClientError::AttestationValidationFailed(
                "Missing cabundle in attestation document",
            ))?;
        Self::verify_cose_chain_and_signature(
            protected_bytes,
            payload_bytes,
            sig_bytes,
            leaf_cert_der,
            &cabundle,
            trusted_root_der,
            attest_secs,
        )?;

        // 6. Verify Manifest PCR Measurements if Manifest Provided
        if !manifest_path.is_empty() {
            let p0 = claims.pcr0.ok_or(ClientError::PcrMismatch(
                "PCR0 missing from attestation document",
            ))?;
            let p1 = claims.pcr1.ok_or(ClientError::PcrMismatch(
                "PCR1 missing from attestation document",
            ))?;
            let p2 = claims.pcr2.ok_or(ClientError::PcrMismatch(
                "PCR2 missing from attestation document",
            ))?;
            Self::verify_manifest_pcrs(manifest_path, p0, p1, p2)?;
        }

        Ok(attest_secs)
    }

    #[inline(never)]
    fn extract_and_verify_attestation_core(
        doc_bytes: &[u8],
        expected_user_data: &[u8; 64],
        expected_nonce: Option<&[u8]>,
        manifest_path: &str,
        trusted_root_der: &[u8],
        verified_unix_secs: Option<u64>,
    ) -> Result<u64, ClientError> {
        if doc_bytes.len() < 32 {
            return Err(ClientError::CborParseError);
        }

        let mut parser = CborParser::new(doc_bytes);
        let root = parser.parse_value()?;
        if !parser.is_eof() {
            return Err(ClientError::CborParseError);
        }
        let unpeeled_holder = Self::peel_outer_attestation_doc(&root)?;
        let effective_root = unpeeled_holder.as_ref().unwrap_or(&root);

        let cose_array = match effective_root {
            CborValue::Tag(18, inner) => match inner.as_ref() {
                CborValue::Array(arr) if arr.len() == 4 => arr,
                _ => return Err(ClientError::CborParseError),
            },
            CborValue::Array(arr) if arr.len() == 4 => arr,
            _ => return Err(ClientError::CborParseError),
        };

        let protected_bytes = match &cose_array[0] {
            CborValue::Bytes(b) => *b,
            _ => return Err(ClientError::CborParseError),
        };
        Self::verify_cose_protected_headers(protected_bytes)?;

        let CborValue::Map(unprotected_entries) = &cose_array[1] else {
            return Err(ClientError::CborParseError);
        };
        for (uk, _) in unprotected_entries {
            if let CborValue::Unsigned(1) = uk {
                return Err(ClientError::AttestationValidationFailed(
                    "alg header forbidden in COSE unprotected bucket",
                ));
            }
        }

        let payload_bytes = match &cose_array[2] {
            CborValue::Bytes(b) => *b,
            _ => return Err(ClientError::CborParseError),
        };

        let sig_bytes = match &cose_array[3] {
            CborValue::Bytes(b) => *b,
            _ => return Err(ClientError::CborParseError),
        };
        if sig_bytes.len() != 96 {
            return Err(ClientError::AttestationValidationFailed(
                "Invalid COSE ES384 signature length (expected 96 bytes)",
            ));
        }

        Self::verify_extracted_attestation_claims(
            protected_bytes,
            payload_bytes,
            sig_bytes,
            expected_user_data,
            expected_nonce,
            manifest_path,
            trusted_root_der,
            verified_unix_secs,
        )
    }

    #[inline(never)]
    pub fn parse_and_verify_cose_attestation_full(
        doc_bytes: &[u8],
        expected_user_data: &[u8; 64],
        expected_nonce: Option<&[u8]>,
        manifest_path: &str,
        trusted_root_der: &[u8],
        current_unix_secs: u64,
    ) -> Result<(), ClientError> {
        let _ = Self::extract_and_verify_attestation_core(
            doc_bytes,
            expected_user_data,
            expected_nonce,
            manifest_path,
            trusted_root_der,
            Some(current_unix_secs),
        )?;
        Ok(())
    }

    fn send_command(
        &mut self,
        command: u16,
        flags: u32,
        payload: &[u8],
    ) -> Result<Vec<u8>, ClientError> {
        let req_header = EnclaveRequestHeader {
            magic: NONA_VSOCK_MAGIC,
            version: NONA_VSOCK_VERSION,
            command,
            #[allow(clippy::cast_possible_truncation)]
            payload_len: payload.len() as u32,
            flags,
            reserved: [0u8; 16],
        };

        let req_wire = req_header.to_wire_bytes();
        self.stream.write_all(&req_wire)?;
        if !payload.is_empty() {
            self.stream.write_all(payload)?;
        }
        self.stream.flush()?;

        let mut resp_wire = [0u8; EnclaveResponseHeader::WIRE_SIZE];
        self.stream.read_exact(&mut resp_wire)?;
        let resp_header = EnclaveResponseHeader::from_wire_bytes(&resp_wire);

        if resp_header.magic != NONA_VSOCK_MAGIC {
            return Err(ClientError::InvalidHeader);
        }
        if resp_header.status != 0 {
            return Err(ClientError::ServerStatusError(resp_header.status));
        }

        let mut resp_body = vec![0u8; resp_header.payload_len as usize];
        if resp_header.payload_len > 0 {
            self.stream.read_exact(&mut resp_body)?;
        }
        Ok(resp_body)
    }
}

pub mod hex {
    pub fn encode(data: &[u8]) -> String {
        let mut s = String::with_capacity(data.len() * 2);
        for &b in data {
            use std::fmt::Write;
            let _ = write!(s, "{b:02x}");
        }
        s
    }

    pub fn decode(s: &str) -> Option<Vec<u8>> {
        if !s.len().is_multiple_of(2) {
            return None;
        }
        let mut bytes = Vec::with_capacity(s.len() / 2);
        let s_bytes = s.as_bytes();
        let mut i = 0;
        while i < s_bytes.len() {
            let high = hex_val(s_bytes[i])?;
            let low = hex_val(s_bytes[i + 1])?;
            bytes.push((high << 4) | low);
            i += 2;
        }
        Some(bytes)
    }

    fn hex_val(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    }
}

// ============================================================================
// ZERO-DEPENDENCY CBOR / COSE_SIGN1 PROTOCOL DECODER & MOCK SYNTHESIZER
// ============================================================================

#[derive(Debug, PartialEq, Eq)]
pub enum CborValue<'a> {
    Unsigned(u64),
    Negative(u64),
    Bytes(&'a [u8]),
    Text(&'a str),
    Array(Vec<CborValue<'a>>),
    Map(Vec<(CborValue<'a>, CborValue<'a>)>),
    Tag(u64, Box<CborValue<'a>>),
    Other,
}

pub const MAX_CBOR_DEPTH: usize = 16;
pub const MAX_CBOR_COLLECTION_ITEMS: usize = 1024;
pub const MAX_ATTESTATION_AGE_SECS: u64 = 300;
pub const MAX_ATTESTATION_CLOCK_SKEW_SECS: u64 = 60;
pub const MAX_CHALLENGE_RESPONSE_INTERVAL_SECS: u64 = 30;
pub const MAX_CHALLENGE_RESPONSE_INTERVAL_NS: u64 =
    MAX_CHALLENGE_RESPONSE_INTERVAL_SECS * 1_000_000_000;

#[allow(clippy::cast_possible_truncation)]
fn encode_cbor_bstr_header(out: &mut Vec<u8>, len: usize) {
    if len <= 23 {
        out.push(0x40 | (len as u8));
    } else if len <= 255 {
        out.push(0x58);
        out.push(len as u8);
    } else {
        out.push(0x59);
        out.extend_from_slice(&u16::try_from(len).unwrap_or(0).to_be_bytes());
    }
}

pub struct CborParser<'a> {
    buf: &'a [u8],
    offset: usize,
    depth: usize,
}

impl<'a> CborParser<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, offset: 0, depth: 0 }
    }

    pub const fn is_eof(&self) -> bool {
        self.offset == self.buf.len()
    }

    fn read_byte(&mut self) -> Result<u8, ClientError> {
        if self.offset >= self.buf.len() {
            return Err(ClientError::CborParseError);
        }
        let b = self.buf[self.offset];
        self.offset += 1;
        Ok(b)
    }

    fn read_slice(&mut self, len: usize) -> Result<&'a [u8], ClientError> {
        if self
            .offset
            .checked_add(len)
            .is_none_or(|end| end > self.buf.len())
        {
            return Err(ClientError::CborParseError);
        }
        let s = &self.buf[self.offset..self.offset + len];
        self.offset += len;
        Ok(s)
    }

    fn read_header(&mut self) -> Result<(u8, u64), ClientError> {
        let b = self.read_byte()?;
        let major = b >> 5;
        let info = b & 0x1f;
        let val = match info {
            0..=23 => info as u64,
            24 => self.read_byte()? as u64,
            25 => {
                let sl = self.read_slice(2)?;
                u16::from_be_bytes([sl[0], sl[1]]) as u64
            }
            26 => {
                let sl = self.read_slice(4)?;
                u32::from_be_bytes([sl[0], sl[1], sl[2], sl[3]]) as u64
            }
            27 => {
                let sl = self.read_slice(8)?;
                u64::from_be_bytes([sl[0], sl[1], sl[2], sl[3], sl[4], sl[5], sl[6], sl[7]])
            }
            31 => u64::MAX,
            _ => return Err(ClientError::CborParseError),
        };
        Ok((major, val))
    }

    #[allow(clippy::cast_possible_truncation)]
    pub fn parse_value(&mut self) -> Result<CborValue<'a>, ClientError> {
        if self.depth >= MAX_CBOR_DEPTH {
            return Err(ClientError::CborParseError);
        }
        self.depth += 1;
        let res = self.parse_value_inner();
        self.depth -= 1;
        res
    }

    #[inline(never)]
    fn parse_cbor_array(&mut self, val: u64) -> Result<CborValue<'a>, ClientError> {
        if val == u64::MAX {
            let mut arr = Vec::new();
            while self.offset < self.buf.len() && self.buf[self.offset] != 0xff {
                if arr.len() >= MAX_CBOR_COLLECTION_ITEMS {
                    return Err(ClientError::CborParseError);
                }
                arr.push(self.parse_value()?);
            }
            if self.offset < self.buf.len() && self.buf[self.offset] == 0xff {
                self.offset += 1;
            }
            Ok(CborValue::Array(arr))
        } else {
            let count = usize::try_from(val).map_err(|_| ClientError::CborParseError)?;
            if count > MAX_CBOR_COLLECTION_ITEMS {
                return Err(ClientError::CborParseError);
            }
            let mut arr = Vec::with_capacity(count.min(1024));
            for _ in 0..count {
                arr.push(self.parse_value()?);
            }
            Ok(CborValue::Array(arr))
        }
    }

    #[inline(never)]
    fn parse_cbor_map(&mut self, val: u64) -> Result<CborValue<'a>, ClientError> {
        if val == u64::MAX {
            let mut map = Vec::new();
            while self.offset < self.buf.len() && self.buf[self.offset] != 0xff {
                if map.len() >= MAX_CBOR_COLLECTION_ITEMS {
                    return Err(ClientError::CborParseError);
                }
                let k = self.parse_value()?;
                let v = self.parse_value()?;
                map.push((k, v));
            }
            if self.offset < self.buf.len() && self.buf[self.offset] == 0xff {
                self.offset += 1;
            }
            Ok(CborValue::Map(map))
        } else {
            let count = usize::try_from(val).map_err(|_| ClientError::CborParseError)?;
            if count > MAX_CBOR_COLLECTION_ITEMS {
                return Err(ClientError::CborParseError);
            }
            let mut map = Vec::with_capacity(count.min(1024));
            for _ in 0..count {
                let k = self.parse_value()?;
                let v = self.parse_value()?;
                map.push((k, v));
            }
            Ok(CborValue::Map(map))
        }
    }

    fn parse_value_inner(&mut self) -> Result<CborValue<'a>, ClientError> {
        let (major, val) = self.read_header()?;
        match major {
            0 => Ok(CborValue::Unsigned(val)),
            1 => Ok(CborValue::Negative(val)),
            2 => {
                let len = usize::try_from(val).map_err(|_| ClientError::CborParseError)?;
                let b = self.read_slice(len)?;
                Ok(CborValue::Bytes(b))
            }
            3 => {
                let len = usize::try_from(val).map_err(|_| ClientError::CborParseError)?;
                let b = self.read_slice(len)?;
                let s = core::str::from_utf8(b).map_err(|_| ClientError::CborParseError)?;
                Ok(CborValue::Text(s))
            }
            4 => self.parse_cbor_array(val),
            5 => self.parse_cbor_map(val),
            6 => {
                let inner = self.parse_value()?;
                Ok(CborValue::Tag(val, Box::new(inner)))
            }
            _ => Ok(CborValue::Other),
        }
    }
}

/// Synthesizes a canonical CBOR COSE_Sign1 document for testing and local simulation.
pub fn synthesize_mock_cose_sign1_document(
    user_data: &[u8],
    pcr0: &[u8],
    pcr1: &[u8],
    pcr2: &[u8],
    include_aws_root_ca: bool,
) -> Vec<u8> {
    let mut payload = Vec::new();

    // Inner map of 4 entries (0xa4)
    payload.push(0xa4);

    // 1. "user_data" => bstr
    payload.push(0x69);
    payload.extend_from_slice(b"user_data");
    payload.push(0x58);
    payload.push(u8::try_from(user_data.len()).unwrap_or(0));
    payload.extend_from_slice(user_data);

    // 2. "pcrs" => map of 3 items (0xa3)
    payload.push(0x64);
    payload.extend_from_slice(b"pcrs");
    payload.push(0xa3);
    // Key 0 => pcr0
    payload.push(0x00);
    payload.push(0x58);
    payload.push(u8::try_from(pcr0.len()).unwrap_or(0));
    payload.extend_from_slice(pcr0);
    // Key 1 => pcr1
    payload.push(0x01);
    payload.push(0x58);
    payload.push(u8::try_from(pcr1.len()).unwrap_or(0));
    payload.extend_from_slice(pcr1);
    // Key 2 => pcr2
    payload.push(0x02);
    payload.push(0x58);
    payload.push(u8::try_from(pcr2.len()).unwrap_or(0));
    payload.extend_from_slice(pcr2);

    // 3. "cabundle" => array of 1 cert
    payload.push(0x68);
    payload.extend_from_slice(b"cabundle");
    payload.push(0x81);
    let cert_body: &[u8] = if include_aws_root_ca {
        &crate::aws_root_ca::AWS_NITRO_ROOT_CA_DER
    } else {
        b"\x30\x82\x01\x00Untrusted Root CA: CN=generic-self-signed Certificate Authority"
    };
    if cert_body.len() <= 23 {
        #[allow(clippy::cast_possible_truncation)]
        payload.push(0x40 | (cert_body.len() as u8));
    } else if cert_body.len() <= 255 {
        payload.push(0x58);
        #[allow(clippy::cast_possible_truncation)]
        payload.push(cert_body.len() as u8);
    } else {
        payload.push(0x59);
        payload.extend_from_slice(&u16::try_from(cert_body.len()).unwrap_or(0).to_be_bytes());
    }
    payload.extend_from_slice(cert_body);

    // 4. "module_id" => text
    payload.push(0x69);
    payload.extend_from_slice(b"module_id");
    payload.push(0x6b);
    payload.extend_from_slice(b"nona-enclave");

    // Outer COSE_Sign1: Tag 18 (0xd2) + Array of 4 (0x84)
    let mut cose = Vec::new();
    cose.push(0xd2);
    cose.push(0x84);

    // Item 0: Protected header: map of 1 {1: -35 (ES384)} => 0xa1, 0x01, 0x38, 0x22
    let protected = [0xa1, 0x01, 0x38, 0x22];
    cose.push(0x44);
    cose.extend_from_slice(&protected);

    // Item 1: Unprotected header: empty map (0xa0)
    cose.push(0xa0);

    // Item 2: Payload bytes (u16 length encoded)
    cose.push(0x59);
    cose.extend_from_slice(&u16::try_from(payload.len()).unwrap_or(0).to_be_bytes());
    cose.extend_from_slice(&payload);

    // Item 3: Signature: dummy 96 bytes (ES384 signature)
    let dummy_sig = [0x5au8; 96];
    cose.push(0x58);
    cose.push(96);
    cose.extend_from_slice(&dummy_sig);

    cose
}



/// Synthesizes a genuine, cryptographically signed X.509 v3 P-384 certificate chain
/// (Root CA + Leaf Certificate) and RFC 8152 COSE_Sign1 ES384 attestation document
/// for end-to-end cryptographic verification testing.
#[allow(clippy::cast_possible_truncation)]
pub fn synthesize_signed_cose_sign1_attestation(
    user_data: &[u8],
    nonce: Option<&[u8]>,
    timestamp_ms: u64,
    pcr0: &[u8],
    pcr1: &[u8],
    pcr2: &[u8],
) -> (Vec<u8>, Vec<u8>) {
    use crate::crypto::{ecdsa_p384_sign_deterministic, p384_public_key_from_private};

    fn der_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + content.len());
        out.push(tag);
        if content.len() < 128 {
            out.push(content.len() as u8);
        } else if content.len() <= 255 {
            out.push(0x81);
            out.push(content.len() as u8);
        } else {
            out.push(0x82);
            out.extend_from_slice(&u16::try_from(content.len()).unwrap_or(0).to_be_bytes());
        }
        out.extend_from_slice(content);
        out
    }

    fn der_int_be(bytes: &[u8]) -> Vec<u8> {
        let mut idx = 0;
        while idx + 1 < bytes.len() && bytes[idx] == 0 {
            idx += 1;
        }
        let slice = &bytes[idx..];
        let mut buf = Vec::with_capacity(slice.len() + 1);
        if (slice[0] & 0x80) != 0 {
            buf.push(0x00);
        }
        buf.extend_from_slice(slice);
        der_tlv(0x02, &buf)
    }

    fn build_x509_v3_cert(
        serial: u8,
        issuer_dn: &[u8],
        subject_dn: &[u8],
        not_before_utc: &[u8; 13],
        not_after_utc: &[u8; 13],
        subject_pubkey_uncompressed: &[u8; 97],
        is_ca: bool,
        signer_privkey: &[u8; 48],
    ) -> Vec<u8> {
        // Version [0] EXPLICIT INTEGER 2 (v3)
        let ver = der_tlv(0xa0, &der_tlv(0x02, &[0x02]));
        let ser = der_tlv(0x02, &[serial]);
        // AlgId ecdsa-with-SHA384: SEQUENCE { OID 1.2.840.10045.4.3.3 }
        let alg_id = der_tlv(0x30, &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03]);
        // Validity
        let mut val_body = Vec::new();
        val_body.extend_from_slice(&der_tlv(0x17, not_before_utc));
        val_body.extend_from_slice(&der_tlv(0x17, not_after_utc));
        let validity = der_tlv(0x30, &val_body);

        // SPKI: SEQUENCE { SEQUENCE { id-ecPublicKey, secp384r1 }, BIT STRING (0x00 || pubkey) }
        let mut spki_alg = Vec::new();
        spki_alg.extend_from_slice(&[0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]);
        spki_alg.extend_from_slice(&[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22]);
        let mut spki_bs = Vec::with_capacity(98);
        spki_bs.push(0x00);
        spki_bs.extend_from_slice(subject_pubkey_uncompressed);
        let mut spki_body = Vec::new();
        spki_body.extend_from_slice(&der_tlv(0x30, &spki_alg));
        spki_body.extend_from_slice(&der_tlv(0x03, &spki_bs));
        let spki = der_tlv(0x30, &spki_body);

        // Extensions [3] EXPLICIT SEQUENCE { BasicConstraints }
        let bc_inner = if is_ca {
            der_tlv(0x30, &[0x01, 0x01, 0xff])
        } else {
            der_tlv(0x30, &[])
        };
        let mut bc_ext_body = Vec::new();
        bc_ext_body.extend_from_slice(&[0x06, 0x03, 0x55, 0x1d, 0x13]);
        bc_ext_body.extend_from_slice(&[0x01, 0x01, 0xff]);
        bc_ext_body.extend_from_slice(&der_tlv(0x04, &bc_inner));
        let ext_seq = der_tlv(0x30, &der_tlv(0x30, &bc_ext_body));
        let exts = der_tlv(0xa3, &ext_seq);

        let mut tbs_body = Vec::new();
        tbs_body.extend_from_slice(&ver);
        tbs_body.extend_from_slice(&ser);
        tbs_body.extend_from_slice(&alg_id);
        tbs_body.extend_from_slice(issuer_dn);
        tbs_body.extend_from_slice(&validity);
        tbs_body.extend_from_slice(subject_dn);
        tbs_body.extend_from_slice(&spki);
        tbs_body.extend_from_slice(&exts);
        let tbs = der_tlv(0x30, &tbs_body);

        let raw_sig = ecdsa_p384_sign_deterministic(signer_privkey, &tbs)
            .unwrap_or([0u8; 96]);
        let mut der_sig_body = Vec::new();
        der_sig_body.extend_from_slice(&der_int_be(&raw_sig[..48]));
        der_sig_body.extend_from_slice(&der_int_be(&raw_sig[48..96]));
        let der_sig_seq = der_tlv(0x30, &der_sig_body);
        let mut sig_bs = Vec::with_capacity(1 + der_sig_seq.len());
        sig_bs.push(0x00);
        sig_bs.extend_from_slice(&der_sig_seq);

        let mut cert_body = Vec::new();
        cert_body.extend_from_slice(&tbs);
        cert_body.extend_from_slice(&alg_id);
        cert_body.extend_from_slice(&der_tlv(0x03, &sig_bs));
        der_tlv(0x30, &cert_body)
    }

    let mut root_priv = [0u8; 48];
    root_priv[47] = 0x11;
    root_priv[0] = 0x07;
    let root_pub = p384_public_key_from_private(&root_priv)
        .map_or([0u8; 97], |p| p.to_uncompressed_bytes());

    let mut leaf_priv = [0u8; 48];
    leaf_priv[47] = 0x22;
    leaf_priv[0] = 0x09;
    let leaf_pub = p384_public_key_from_private(&leaf_priv)
        .map_or([0u8; 97], |p| p.to_uncompressed_bytes());

    // RDN SEQUENCE { SET { SEQUENCE { CN, UTF8String } } }
    let root_cn = der_tlv(0x0c, b"nona-test-root-ca");
    let mut root_atv = Vec::from([0x06, 0x03, 0x55, 0x04, 0x03]);
    root_atv.extend_from_slice(&root_cn);
    let root_dn = der_tlv(0x30, &der_tlv(0x31, &der_tlv(0x30, &root_atv)));

    let leaf_cn = der_tlv(0x0c, b"nona-test-enclave-leaf");
    let mut leaf_atv = Vec::from([0x06, 0x03, 0x55, 0x04, 0x03]);
    leaf_atv.extend_from_slice(&leaf_cn);
    let leaf_dn = der_tlv(0x30, &der_tlv(0x31, &der_tlv(0x30, &leaf_atv)));

    let root_der = build_x509_v3_cert(
        1,
        &root_dn,
        &root_dn,
        b"200101000000Z",
        b"491231235959Z",
        &root_pub,
        true,
        &root_priv,
    );
    let leaf_der = build_x509_v3_cert(
        2,
        &root_dn,
        &leaf_dn,
        b"200101000000Z",
        b"491231235959Z",
        &leaf_pub,
        false,
        &root_priv,
    );

    let map_len: u8 = if nonce.is_some() { 0xa7 } else { 0xa6 };
    let mut payload = Vec::new();
    payload.push(map_len);

    // 1. "module_id"
    payload.push(0x69);
    payload.extend_from_slice(b"module_id");
    payload.push(0x6c);
    payload.extend_from_slice(b"nona-enclave");

    // 2. "timestamp" (uint64 ms)
    payload.push(0x69);
    payload.extend_from_slice(b"timestamp");
    payload.push(0x1b);
    payload.extend_from_slice(&timestamp_ms.to_be_bytes());

    // 3. "user_data"
    payload.push(0x69);
    payload.extend_from_slice(b"user_data");
    encode_cbor_bstr_header(&mut payload, user_data.len());
    payload.extend_from_slice(user_data);

    // 4. "pcrs"
    payload.push(0x64);
    payload.extend_from_slice(b"pcrs");
    payload.push(0xa3);
    payload.push(0x00);
    encode_cbor_bstr_header(&mut payload, pcr0.len());
    payload.extend_from_slice(pcr0);
    payload.push(0x01);
    encode_cbor_bstr_header(&mut payload, pcr1.len());
    payload.extend_from_slice(pcr1);
    payload.push(0x02);
    encode_cbor_bstr_header(&mut payload, pcr2.len());
    payload.extend_from_slice(pcr2);

    // 5. "certificate" (leaf DER)
    payload.push(0x6b);
    payload.extend_from_slice(b"certificate");
    encode_cbor_bstr_header(&mut payload, leaf_der.len());
    payload.extend_from_slice(&leaf_der);

    // 6. "cabundle" ([root_der])
    payload.push(0x68);
    payload.extend_from_slice(b"cabundle");
    payload.push(0x81);
    encode_cbor_bstr_header(&mut payload, root_der.len());
    payload.extend_from_slice(&root_der);

    // 7. optional "nonce"
    if let Some(n) = nonce {
        payload.push(0x65);
        payload.extend_from_slice(b"nonce");
        encode_cbor_bstr_header(&mut payload, n.len());
        payload.extend_from_slice(n);
    }

    let protected = [0xa1, 0x01, 0x38, 0x22]; // {1: -35 (ES384)}
    let sig_structure = NonaClient::build_cose_sig_structure(&protected, &payload);
    let cose_sig = ecdsa_p384_sign_deterministic(&leaf_priv, &sig_structure)
        .unwrap_or([0u8; 96]);

    let mut cose = Vec::new();
    cose.push(0xd2); // Tag(18)
    cose.push(0x84); // Array(4)
    cose.push(0x44);
    cose.extend_from_slice(&protected);
    cose.push(0xa0); // Unprotected empty map
    encode_cbor_bstr_header(&mut cose, payload.len());
    cose.extend_from_slice(&payload);
    cose.push(0x58);
    cose.push(96);
    cose.extend_from_slice(&cose_sig);

    (cose, root_der)
}

// ============================================================================
// STRICT STRUCTURAL JSON MANIFEST PCR POLICY PARSER & CONSTANT-TIME PINNING
// ============================================================================

const MAX_JSON_DEPTH: usize = 16;
const MAX_JSON_ITEMS: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
enum JsonValue {
    Null,
    Bool(bool),
    Number,
    String(String),
    Array(Vec<JsonValue>),
    Object(Vec<(String, JsonValue)>),
}

struct StrictJsonParser<'a> {
    bytes: &'a [u8],
    offset: usize,
    depth: usize,
}

impl<'a> StrictJsonParser<'a> {
    fn new(src: &'a str) -> Self {
        Self {
            bytes: src.as_bytes(),
            offset: 0,
            depth: 0,
        }
    }

    fn skip_whitespace(&mut self) {
        while self.offset < self.bytes.len() {
            match self.bytes[self.offset] {
                b' ' | b'\t' | b'\n' | b'\r' => self.offset += 1,
                _ => break,
            }
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.offset).copied()
    }

    fn next_byte(&mut self) -> Result<u8, ClientError> {
        let b = self
            .bytes
            .get(self.offset)
            .copied()
            .ok_or(ClientError::PcrMismatch("Unexpected EOF in JSON manifest"))?;
        self.offset += 1;
        Ok(b)
    }

    fn parse_root(mut self) -> Result<JsonValue, ClientError> {
        self.skip_whitespace();
        let val = self.parse_value()?;
        self.skip_whitespace();
        if self.offset != self.bytes.len() {
            return Err(ClientError::PcrMismatch(
                "Trailing data after JSON manifest root",
            ));
        }
        Ok(val)
    }

    fn parse_value(&mut self) -> Result<JsonValue, ClientError> {
        if self.depth >= MAX_JSON_DEPTH {
            return Err(ClientError::PcrMismatch("JSON manifest nesting overflow"));
        }
        self.skip_whitespace();
        let b = self
            .peek()
            .ok_or(ClientError::PcrMismatch("Empty JSON value in manifest"))?;
        self.depth += 1;
        let res = match b {
            b'{' => self.parse_object(),
            b'[' => self.parse_array(),
            b'"' => self.parse_string().map(JsonValue::String),
            b't' => self.parse_literal(b"true", JsonValue::Bool(true)),
            b'f' => self.parse_literal(b"false", JsonValue::Bool(false)),
            b'n' => self.parse_literal(b"null", JsonValue::Null),
            b'-' | b'0'..=b'9' => self.parse_number(),
            _ => Err(ClientError::PcrMismatch("Malformed JSON token in manifest")),
        };
        self.depth -= 1;
        res
    }

    fn parse_literal(&mut self, lit: &[u8], val: JsonValue) -> Result<JsonValue, ClientError> {
        let end = self
            .offset
            .checked_add(lit.len())
            .ok_or(ClientError::PcrMismatch("Malformed JSON literal"))?;
        if self.bytes.get(self.offset..end) != Some(lit) {
            return Err(ClientError::PcrMismatch("Invalid JSON literal in manifest"));
        }
        self.offset = end;
        Ok(val)
    }

    fn parse_number(&mut self) -> Result<JsonValue, ClientError> {
        if self.peek() == Some(b'-') {
            self.offset += 1;
        }
        match self.peek() {
            Some(b'0') => self.offset += 1,
            Some(b'1'..=b'9') => {
                self.offset += 1;
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.offset += 1;
                }
            }
            _ => return Err(ClientError::PcrMismatch("Invalid JSON number in manifest")),
        }
        if self.peek() == Some(b'.') {
            self.offset += 1;
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(ClientError::PcrMismatch("Invalid JSON fraction in manifest"));
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.offset += 1;
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.offset += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.offset += 1;
            }
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(ClientError::PcrMismatch("Invalid JSON exponent in manifest"));
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.offset += 1;
            }
        }
        Ok(JsonValue::Number)
    }

    fn parse_hex_u16(&mut self) -> Result<u16, ClientError> {
        let mut acc = 0u16;
        for _ in 0..4 {
            let b = self.next_byte()?;
            let digit = match b {
                b'0'..=b'9' => u16::from(b - b'0'),
                b'a'..=b'f' => u16::from(b - b'a' + 10),
                b'A'..=b'F' => u16::from(b - b'A' + 10),
                _ => {
                    return Err(ClientError::PcrMismatch(
                        "Invalid unicode escape in manifest",
                    ))
                }
            };
            acc = (acc << 4) | digit;
        }
        Ok(acc)
    }

    fn parse_string(&mut self) -> Result<String, ClientError> {
        if self.next_byte()? != b'"' {
            return Err(ClientError::PcrMismatch("Expected JSON string quote"));
        }
        let mut out = String::new();
        loop {
            let b = self.next_byte()?;
            match b {
                b'"' => return Ok(out),
                b'\\' => {
                    let esc = self.next_byte()?;
                    match esc {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{0008}'),
                        b'f' => out.push('\u{000C}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let code = self.parse_hex_u16()?;
                            let ch = char::from_u32(u32::from(code)).ok_or(
                                ClientError::PcrMismatch("Invalid unicode scalar in manifest"),
                            )?;
                            out.push(ch);
                        }
                        _ => {
                            return Err(ClientError::PcrMismatch(
                                "Invalid JSON escape sequence in manifest",
                            ))
                        }
                    }
                }
                0x00..=0x1F => {
                    return Err(ClientError::PcrMismatch(
                        "Unescaped control character in JSON manifest",
                    ))
                }
                _ => {
                    let start = self.offset - 1;
                    let remaining = core::str::from_utf8(&self.bytes[start..]).map_err(|_| {
                        ClientError::PcrMismatch("Invalid UTF-8 sequence in JSON manifest")
                    })?;
                    let ch = remaining
                        .chars()
                        .next()
                        .ok_or(ClientError::PcrMismatch("Empty UTF-8 char in manifest"))?;
                    out.push(ch);
                    self.offset = start + ch.len_utf8();
                }
            }
        }
    }

    fn parse_array(&mut self) -> Result<JsonValue, ClientError> {
        if self.next_byte()? != b'[' {
            return Err(ClientError::PcrMismatch("Expected JSON array opening"));
        }
        self.skip_whitespace();
        let mut items = Vec::new();
        if self.peek() == Some(b']') {
            self.offset += 1;
            return Ok(JsonValue::Array(items));
        }
        loop {
            if items.len() >= MAX_JSON_ITEMS {
                return Err(ClientError::PcrMismatch("JSON array exceeds item ceiling"));
            }
            items.push(self.parse_value()?);
            self.skip_whitespace();
            match self.next_byte()? {
                b',' => {}
                b']' => return Ok(JsonValue::Array(items)),
                _ => {
                    return Err(ClientError::PcrMismatch(
                        "Expected ',' or ']' in JSON array",
                    ))
                }
            }
        }
    }

    fn parse_object(&mut self) -> Result<JsonValue, ClientError> {
        if self.next_byte()? != b'{' {
            return Err(ClientError::PcrMismatch("Expected JSON object opening"));
        }
        self.skip_whitespace();
        let mut entries: Vec<(String, JsonValue)> = Vec::new();
        if self.peek() == Some(b'}') {
            self.offset += 1;
            return Ok(JsonValue::Object(entries));
        }
        loop {
            if entries.len() >= MAX_JSON_ITEMS {
                return Err(ClientError::PcrMismatch("JSON object exceeds key ceiling"));
            }
            self.skip_whitespace();
            let key = self.parse_string()?;
            if entries.iter().any(|(existing, _)| existing == &key) {
                return Err(ClientError::PcrMismatch("Duplicate JSON key in manifest"));
            }
            self.skip_whitespace();
            if self.next_byte()? != b':' {
                return Err(ClientError::PcrMismatch("Expected ':' after JSON key"));
            }
            let val = self.parse_value()?;
            entries.push((key, val));
            self.skip_whitespace();
            match self.next_byte()? {
                b',' => {}
                b'}' => return Ok(JsonValue::Object(entries)),
                _ => {
                    return Err(ClientError::PcrMismatch(
                        "Expected ',' or '}' in JSON object",
                    ))
                }
            }
        }
    }
}

struct ManifestPcrPolicy {
    pcr0: [u8; 48],
    pcr1: [u8; 48],
    pcr2: [u8; 48],
}

impl ManifestPcrPolicy {
    fn from_manifest_file(manifest_path: &str) -> Result<Self, ClientError> {
        let mut file =
            File::open(manifest_path).map_err(|_| ClientError::PcrMismatch("Manifest missing"))?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        Self::parse_json(&contents)
    }

    fn parse_json(contents: &str) -> Result<Self, ClientError> {
        let root = StrictJsonParser::new(contents).parse_root()?;
        let JsonValue::Object(root_entries) = &root else {
            return Err(ClientError::PcrMismatch("Manifest root must be JSON object"));
        };

        let measurements_val = root_entries
            .iter()
            .find(|(k, _)| k == "measurements")
            .map(|(_, v)| v)
            .ok_or(ClientError::PcrMismatch(
                "Missing 'measurements' object in manifest",
            ))?;

        let JsonValue::Object(meas_entries) = measurements_val else {
            return Err(ClientError::PcrMismatch(
                "'measurements' must be a JSON object",
            ));
        };

        if let Some((_, algo_val)) = meas_entries.iter().find(|(k, _)| k == "hash_algorithm") {
            let JsonValue::String(algo) = algo_val else {
                return Err(ClientError::PcrMismatch(
                    "Invalid 'hash_algorithm' type in manifest",
                ));
            };
            if algo != "SHA-384" {
                return Err(ClientError::PcrMismatch(
                    "Unsupported PCR hash_algorithm (expected SHA-384)",
                ));
            }
        }

        let pcr0_str = extract_required_string(meas_entries, "PCR0", "PCR0 missing from measurements")?;
        let pcr1_str = extract_required_string(meas_entries, "PCR1", "PCR1 missing from measurements")?;
        let pcr2_str = extract_required_string(meas_entries, "PCR2", "PCR2 missing from measurements")?;

        let pcr0 = parse_strict_pcr_sha384(pcr0_str, "Invalid PCR0 policy digest format")?;
        let pcr1 = parse_strict_pcr_sha384(pcr1_str, "Invalid PCR1 policy digest format")?;
        let pcr2 = parse_strict_pcr_sha384(pcr2_str, "Invalid PCR2 policy digest format")?;

        if ct_eq_48(&pcr0, &pcr1) || ct_eq_48(&pcr0, &pcr2) || ct_eq_48(&pcr1, &pcr2) {
            return Err(ClientError::PcrMismatch(
                "Degenerate PCR register collision across PCR0/PCR1/PCR2",
            ));
        }

        Ok(Self { pcr0, pcr1, pcr2 })
    }
}

fn extract_required_string<'a>(
    entries: &'a [(String, JsonValue)],
    key: &str,
    missing_err: &'static str,
) -> Result<&'a str, ClientError> {
    let val = entries
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v)
        .ok_or(ClientError::PcrMismatch(missing_err))?;
    match val {
        JsonValue::String(s) => Ok(s.as_str()),
        _ => Err(ClientError::PcrMismatch(
            "PCR policy value must be a JSON string",
        )),
    }
}

fn parse_strict_pcr_sha384(raw: &str, err_msg: &'static str) -> Result<[u8; 48], ClientError> {
    // Enforce exact 384-bit (96 hex chars) representation: reject wildcards (*, ?),
    // regex patterns, truncated prefixes, 0x prefixes, and whitespace padding.
    if raw.len() != 96 || !raw.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(ClientError::PcrMismatch(err_msg));
    }
    let decoded = hex::decode(raw).ok_or(ClientError::PcrMismatch(err_msg))?;
    let arr: [u8; 48] = decoded
        .try_into()
        .map_err(|_| ClientError::PcrMismatch(err_msg))?;
    if arr == [0u8; 48] {
        return Err(ClientError::PcrMismatch(
            "All-zero PCR register policy rejected",
        ));
    }
    Ok(arr)
}

#[inline(never)]
fn ct_eq_48(expected: &[u8; 48], actual: &[u8]) -> bool {
    if actual.len() != 48 {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in expected.iter().zip(actual.iter()) {
        diff |= a ^ b;
    }
    core::hint::black_box(diff) == 0
}
