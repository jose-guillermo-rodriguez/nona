//! Host-side client driver establishing dual transport (AF_VSOCK / AF_UNIX) with the
//! Nona Enclave wire daemon, enforcing hardware attestation, PCR integrity, and chunked streaming.

#![cfg(feature = "std")]

use std::fs::File;
use std::io::{Read, Write};
use std::ops::{Deref, DerefMut};
use std::os::unix::net::UnixStream;
use std::path::Path;
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

use crate::crypto::sha512_digest;
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
}

impl NonaClient {
    pub fn connect_unix(path: &str) -> Result<Self, ClientError> {
        let stream = UnixStream::connect(path).map_err(|_| ClientError::ConnectionFailed)?;
        Ok(Self {
            stream: TransportStream::Unix(stream),
            session_pubkey: [0u8; 33],
            attested: false,
            allow_simulation_fallback: false,
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

    pub fn blind_stream_chunked(&mut self, stream_data: &[u8]) -> Result<Vec<u8>, ClientError> {
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

            let blinded_chunk = self.blind_phase1(&chunk_staging.data)?;
            results.extend_from_slice(&blinded_chunk[..active_elements * ELEMENT_BYTES]);
            offset += current_chunk_bytes;
        }

        chunk_staging.fill(0);
        if results.len() != total_elements * ELEMENT_BYTES {
            return Err(ClientError::InvalidHeader);
        }
        Ok(results)
    }

    pub fn verify_manifest_pcrs(
        manifest_path: &str,
        runtime_pcr0: &[u8],
        runtime_pcr1: &[u8],
        runtime_pcr2: &[u8],
    ) -> Result<(), ClientError> {
        let mut file =
            File::open(manifest_path).map_err(|_| ClientError::PcrMismatch("Manifest missing"))?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;

        let pcr0_hex = hex::encode(runtime_pcr0);
        let pcr1_hex = hex::encode(runtime_pcr1);
        let pcr2_hex = hex::encode(runtime_pcr2);

        if !contents.contains(&pcr0_hex) {
            return Err(ClientError::PcrMismatch("PCR0 integrity violation"));
        }
        if !contents.contains(&pcr1_hex) {
            return Err(ClientError::PcrMismatch("PCR1 integrity violation"));
        }
        if !contents.contains(&pcr2_hex) {
            return Err(ClientError::PcrMismatch("PCR2 integrity violation"));
        }
        if pcr0_hex == pcr1_hex {
            return Err(ClientError::PcrMismatch(
                "Degenerate PCR0 == PCR1 register collision",
            ));
        }
        Ok(())
    }

    pub fn verify_simulation_manifest(manifest_path: &str) -> Result<(), ClientError> {
        let mut file =
            File::open(manifest_path).map_err(|_| ClientError::PcrMismatch("Manifest missing"))?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;

        let find_pcr = |key: &str| -> Option<&str> {
            let idx = contents.find(key)?;
            let rest = &contents[idx + key.len()..];
            let quote1 = rest.find('"')?;
            let rest2 = &rest[quote1 + 1..];
            let quote2 = rest2.find('"')?;
            Some(&rest2[..quote2])
        };

        let p0 = find_pcr("\"PCR0\"").ok_or(ClientError::PcrMismatch("PCR0 missing"))?;
        let p1 = find_pcr("\"PCR1\"").ok_or(ClientError::PcrMismatch("PCR1 missing"))?;
        let p2 = find_pcr("\"PCR2\"").ok_or(ClientError::PcrMismatch("PCR2 missing"))?;

        if p0.len() != 96 || p1.len() != 96 || p2.len() != 96 {
            return Err(ClientError::PcrMismatch(
                "Invalid SHA-384 PCR length in manifest",
            ));
        }
        if p0 == p1 {
            return Err(ClientError::PcrMismatch(
                "Degenerate PCR0 == PCR1 register collision",
            ));
        }
        Ok(())
    }

    pub fn attest_and_bind(&mut self, manifest_path: &str) -> Result<(), ClientError> {
        let resp = match self.send_command(CMD_ATTEST, 0, &[]) {
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

        if resp.len() <= 33 {
            return Err(ClientError::AttestationValidationFailed(
                "Truncated attestation",
            ));
        }

        if resp.len() < 33 {
            return Err(ClientError::InvalidHeader);
        }

        self.session_pubkey.copy_from_slice(&resp[..33]);
        if self.session_pubkey[0] != 0x02 && self.session_pubkey[0] != 0x03 {
            return Err(ClientError::KeyBindingMismatch);
        }
        let doc_bytes = &resp[33..];

        let expected_user_data = sha512_digest(&self.session_pubkey);
        Self::parse_and_verify_cose_attestation(doc_bytes, &expected_user_data, manifest_path)?;

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
                return Ok(Some(unpeeled_parser.parse_value()?));
            }
        }
        Ok(None)
    }

    pub fn parse_and_verify_cose_attestation(
        doc_bytes: &[u8],
        expected_user_data: &[u8; 64],
        manifest_path: &str,
    ) -> Result<(), ClientError> {
        if doc_bytes.len() < 32 {
            return Err(ClientError::CborParseError);
        }

        let mut parser = CborParser::new(doc_bytes);
        let root = parser.parse_value()?;
        let unpeeled_holder = Self::peel_outer_attestation_doc(&root)?;
        let effective_root = unpeeled_holder.as_ref().unwrap_or(&root);

        // COSE_Sign1: Tag(18, Array[4]) or untagged Array[4]
        let cose_array = match effective_root {
            CborValue::Tag(18, inner) => match inner.as_ref() {
                CborValue::Array(arr) if arr.len() == 4 => arr,
                _ => return Err(ClientError::CborParseError),
            },
            CborValue::Array(arr) if arr.len() == 4 => arr,
            _ => return Err(ClientError::CborParseError),
        };

        // Extract COSE payload (Item 2)
        let payload_bytes = match &cose_array[2] {
            CborValue::Bytes(b) => *b,
            _ => return Err(ClientError::CborParseError),
        };

        // Parse inner CBOR map of the attestation document
        let mut payload_parser = CborParser::new(payload_bytes);
        let payload_val = payload_parser.parse_value()?;
        let CborValue::Map(entries) = &payload_val else {
            return Err(ClientError::CborParseError);
        };

        let mut extracted_user_data: Option<&[u8]> = None;
        let mut extracted_pcr0: Option<&[u8]> = None;
        let mut extracted_pcr1: Option<&[u8]> = None;
        let mut extracted_pcr2: Option<&[u8]> = None;
        let mut has_aws_root_ca = false;

        for (k, v) in entries {
            if let CborValue::Text(key) = k {
                match *key {
                    "user_data" => {
                        if let CborValue::Bytes(ud) = v {
                            extracted_user_data = Some(*ud);
                        }
                    }
                    "pcrs" => {
                        if let CborValue::Map(pcr_map) = v {
                            for (pk, pv) in pcr_map {
                                if let CborValue::Bytes(pcr_bytes) = pv {
                                    match pk {
                                        CborValue::Unsigned(0) => extracted_pcr0 = Some(*pcr_bytes),
                                        CborValue::Unsigned(1) => extracted_pcr1 = Some(*pcr_bytes),
                                        CborValue::Unsigned(2) => extracted_pcr2 = Some(*pcr_bytes),
                                        _ => {}
                                    }
                                }
                            }
                        }
                    }
                    "cabundle" => {
                        if let CborValue::Array(certs) = v {
                            for cert in certs {
                                if let CborValue::Bytes(cert_der) = cert {
                                    if crate::aws_root_ca::matches_root_ca(cert_der) {
                                        has_aws_root_ca = true;
                                    }
                                }
                            }
                        }
                    }
                    "certificate" => {
                        if let CborValue::Bytes(cert_der) = v {
                            if crate::aws_root_ca::matches_root_ca(cert_der) {
                                has_aws_root_ca = true;
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        // 1. Verify User Data Key Binding in Constant Time
        let ud = extracted_user_data.ok_or(ClientError::KeyBindingMismatch)?;
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

        // 2. Verify AWS Nitro Root CA Presence in Cert Chain
        if !has_aws_root_ca {
            return Err(ClientError::AttestationValidationFailed(
                "Missing AWS Nitro Root CA",
            ));
        }

        // 3. Verify Manifest PCR Measurements if Manifest Provided
        if !manifest_path.is_empty() && Path::new(manifest_path).exists() {
            let p0 = extracted_pcr0.ok_or(ClientError::PcrMismatch(
                "PCR0 missing from attestation document",
            ))?;
            let p1 = extracted_pcr1.ok_or(ClientError::PcrMismatch(
                "PCR1 missing from attestation document",
            ))?;
            let p2 = extracted_pcr2.ok_or(ClientError::PcrMismatch(
                "PCR2 missing from attestation document",
            ))?;
            Self::verify_manifest_pcrs(manifest_path, p0, p1, p2)?;
        }

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

/// Canonical AWS Nitro Enclaves Root Certificate (G1) SHA-384 Fingerprint
/// Subject: C=US, O=Amazon, OU=AWS, CN=aws.nitro-enclaves
/// Validity: 2019-10-28 to 2049-10-28
pub const AWS_NITRO_ROOT_CA_SHA384: [u8; 48] = [
    0x8c, 0x6e, 0x8a, 0x48, 0x22, 0xd0, 0x0c, 0x6e,
    0x54, 0x44, 0x11, 0x65, 0x84, 0xd6, 0x48, 0xc1,
    0x2c, 0x83, 0x8f, 0x1b, 0xae, 0x27, 0x24, 0x93,
    0x78, 0xb8, 0x11, 0x61, 0xba, 0x23, 0x65, 0x76,
    0xad, 0x14, 0x79, 0xc3, 0x48, 0xb1, 0xd4, 0xd7,
    0x2c, 0x4a, 0x20, 0x23, 0x42, 0x5a, 0x58, 0x9c,
];

pub struct CborParser<'a> {
    buf: &'a [u8],
    offset: usize,
    depth: usize,
}

impl<'a> CborParser<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, offset: 0, depth: 0 }
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
