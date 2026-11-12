//! Bare-metal AWS Nitro Security Module (/dev/nsm) hardware attestation driver.
//! Enforces zero dynamic allocations (#![no_std]), cache-aligned stack buffers,
//! and binds ephemeral SECP256K1 public keys into hypervisor-signed PCR documents.

use crate::crypto::{ct_zeroize, Scalar};
use crate::psi::JacobianPoint;

// Linux NSM Kernel ioctl ABI Constants

pub const NSM_MAGIC: u8 = 0x0A;
/// _IOWR(0x0A, 0x0, sizeof(NsmRawMessage) = 32) = 0xC0200A00
pub const NSM_IOCTL_RAW: u64 = 0xC020_0A00;

pub const NONA_ERR_NSM_UNAVAILABLE: i32 = -110;
pub const NONA_ERR_NSM_IOCTL_FAILED: i32 = -111;
pub const NONA_ERR_ATTEST_OVERFLOW: i32 = -112;

pub const ATTESTATION_MAX_DOC_SIZE: usize = 12288;
pub const SECP256K1_PUBKEY_COMPRESSED_SIZE: usize = 33;

#[repr(C)]
pub struct NsmIovec {
    pub addr: u64,
    pub len: u64,
}

#[repr(C)]
pub struct NsmRawMessage {
    pub request: NsmIovec,
    pub response: NsmIovec,
}

#[repr(C, align(64))]
pub struct AttestationDocumentBuffer {
    pub data: [u8; ATTESTATION_MAX_DOC_SIZE],
    pub actual_len: usize,
}

impl AttestationDocumentBuffer {
    pub const INIT: Self = Self {
        data: [0u8; ATTESTATION_MAX_DOC_SIZE],
        actual_len: 0,
    };

    pub fn purge(&mut self) {
        ct_zeroize(&mut self.data);
        self.actual_len = 0;
    }
}

impl Drop for AttestationDocumentBuffer {
    fn drop(&mut self) {
        self.purge();
    }
}

// Ephemeral Cryptographic Key Binding (SECP256K1 SEC 1 Standard)

/// Derives a 33-byte compressed SECP256K1 public key from a 32-byte ephemeral private scalar.
/// Format: [0x02 or 0x03 parity byte] + [32-byte big-endian X coordinate].
pub fn derive_compressed_public_key(
    private_key: &[u8; 32],
    pubkey_out: &mut [u8; SECP256K1_PUBKEY_COMPRESSED_SIZE],
) -> i32 {
    let scalar = unsafe { Scalar::from_bytes_le(private_key.as_ptr()) };
    if scalar.is_zero() || !scalar.is_canonical() {
        return -1; // Invalid private key: must be non-zero and canonical (1 <= s < q)
    }

    let g = JacobianPoint::generator();
    let q = g.scalar_mul(&scalar);
    if q.is_infinity() {
        return -1;
    }

    // Invert Z once in P^2: x = X / Z mod p, y = Y / Z mod p.
    // Collapses redundant Fermat addition chains into a single inversion.
    let z_inv = q.z.invert();
    let affine_x = q.x.mul(&z_inv);
    let mut x_bytes = [0u8; 32];
    unsafe { affine_x.to_bytes_le(x_bytes.as_mut_ptr()) };
    x_bytes.reverse();

    let affine_y = q.y.mul(&z_inv);
    let is_odd = (affine_y.limbs[0] & 1) as u8;

    pubkey_out[0] = if is_odd == 1 { 0x03 } else { 0x02 };
    pubkey_out[1..33].copy_from_slice(&x_bytes);

    0
}

// Minimal Stack-Based CBOR Synthesizer for Attestation Request

/// Synthesizes a canonical CBOR NSM Attestation request on the stack.
/// Map with 1 key: {"Attestation": {"user_data": <pubkey>}}
/// user_data binds the ephemeral public key directly into hypervisor PCR measurement.
#[allow(clippy::cast_possible_truncation)]
pub fn encode_nsm_attestation_request_with_nonce(
    user_data: &[u8],
    nonce: Option<&[u8]>,
    out_buf: &mut [u8],
) -> Result<usize, i32> {
    // Canonical aws-nitro-enclaves-nsm-api CBOR envelope:
    // {"Attestation": {"user_data": <bytes>, "nonce": <bytes | null>, "public_key": null}}
    if user_data.len() > 255 {
        return Err(NONA_ERR_ATTEST_OVERFLOW);
    }
    let nonce_field_len = match nonce {
        Some(n) => {
            if n.len() > 255 {
                return Err(NONA_ERR_ATTEST_OVERFLOW);
            }
            2 + n.len()
        }
        None => 1,
    };
    let req_len = 1 + 1 + 11 + 1 + 1 + 9 + 2 + user_data.len() + 1 + 5 + nonce_field_len + 1 + 10 + 1;
    if out_buf.len() < req_len {
        return Err(NONA_ERR_ATTEST_OVERFLOW);
    }

    let mut cursor = 0;
    out_buf[cursor] = 0xa1; // Map(1)
    cursor += 1;
    out_buf[cursor] = 0x6b; // text(11)
    cursor += 1;
    out_buf[cursor..cursor + 11].copy_from_slice(b"Attestation");
    cursor += 11;

    out_buf[cursor] = 0xa3; // Map(3)
    cursor += 1;

    // Field 1: user_data
    out_buf[cursor] = 0x69; // text(9)
    cursor += 1;
    out_buf[cursor..cursor + 9].copy_from_slice(b"user_data");
    cursor += 9;
    out_buf[cursor] = 0x58; // byte string, 1-byte length
    cursor += 1;
    out_buf[cursor] = user_data.len() as u8;
    cursor += 1;
    out_buf[cursor..cursor + user_data.len()].copy_from_slice(user_data);
    cursor += user_data.len();

    // Field 2: nonce = <bstr> or null
    out_buf[cursor] = 0x65; // text(5)
    cursor += 1;
    out_buf[cursor..cursor + 5].copy_from_slice(b"nonce");
    cursor += 5;
    if let Some(n) = nonce {
        out_buf[cursor] = 0x58;
        cursor += 1;
        out_buf[cursor] = n.len() as u8;
        cursor += 1;
        out_buf[cursor..cursor + n.len()].copy_from_slice(n);
        cursor += n.len();
    } else {
        out_buf[cursor] = 0xf6; // null
        cursor += 1;
    }

    // Field 3: public_key = null
    out_buf[cursor] = 0x6a; // text(10)
    cursor += 1;
    out_buf[cursor..cursor + 10].copy_from_slice(b"public_key");
    cursor += 10;
    out_buf[cursor] = 0xf6; // null
    cursor += 1;

    Ok(cursor)
}

pub fn encode_nsm_attestation_request(user_data: &[u8], out_buf: &mut [u8]) -> Result<usize, i32> {
    encode_nsm_attestation_request_with_nonce(user_data, None, out_buf)
}

// ============================================================================
// Hardware Entropy Interlock (/dev/nsm GetRandom IOCTL)
// ============================================================================

/// Synthesizes a canonical CBOR NSM `GetRandom` request on the stack.
/// AWS Nitro NSM `Request::GetRandom` encodes as a unit variant text string `"GetRandom"` (0x69 + 9 bytes).
pub fn encode_nsm_get_random_request(out_buf: &mut [u8]) -> Result<usize, i32> {
    const REQ_BYTES: &[u8; 10] = b"\x69GetRandom";
    if out_buf.len() < REQ_BYTES.len() {
        return Err(NONA_ERR_ATTEST_OVERFLOW);
    }
    out_buf[..REQ_BYTES.len()].copy_from_slice(REQ_BYTES);
    Ok(REQ_BYTES.len())
}

/// Parses a canonical CBOR NSM `GetRandom` response map:
/// `{"GetRandom": {"random": <bstr>}}`
/// Returns the raw hardware entropy byte slice inside `resp_buf`.
#[allow(clippy::cast_possible_truncation)]
pub fn parse_nsm_get_random_response(resp_buf: &[u8]) -> Result<&[u8], i32> {
    // Minimum structure:
    // 0xa1 (map 1) + 0x69 "GetRandom" (10 B) + 0xa1 (map 1) + 0x66 "random" (7 B) + bstr header (>= 2 B)
    if resp_buf.len() < 21 {
        return Err(NONA_ERR_NSM_IOCTL_FAILED);
    }
    if resp_buf[0] != 0xa1
        || resp_buf[1] != 0x69
        || &resp_buf[2..11] != b"GetRandom"
        || resp_buf[11] != 0xa1
        || resp_buf[12] != 0x66
        || &resp_buf[13..19] != b"random"
    {
        return Err(NONA_ERR_NSM_IOCTL_FAILED);
    }

    let major = resp_buf[19] >> 5;
    let addl = resp_buf[19] & 0x1f;
    if major != 2 {
        return Err(NONA_ERR_NSM_IOCTL_FAILED);
    }

    let (bstr_len, payload_offset) = if addl < 24 {
        (addl as usize, 20usize)
    } else if addl == 24 {
        (resp_buf[20] as usize, 21usize)
    } else if addl == 25 {
        if resp_buf.len() < 22 {
            return Err(NONA_ERR_NSM_IOCTL_FAILED);
        }
        let len = u16::from_be_bytes([resp_buf[20], resp_buf[21]]) as usize;
        (len, 22usize)
    } else {
        return Err(NONA_ERR_NSM_IOCTL_FAILED);
    };

    if bstr_len == 0 || payload_offset.saturating_add(bstr_len) != resp_buf.len() {
        return Err(NONA_ERR_NSM_IOCTL_FAILED);
    }

    Ok(&resp_buf[payload_offset..payload_offset + bstr_len])
}

/// Queries `/dev/nsm` directly via `NSM_IOCTL_RAW` (`0xC0200A00`) for hardware random bytes.
/// Enforces non-empty response and rejects degenerate all-zero entropy blocks.
#[allow(clippy::cast_possible_truncation)]
pub unsafe fn query_hardware_random(out: &mut [u8]) -> i32 {
    if out.is_empty() || out.len() > 256 {
        return NONA_ERR_ATTEST_OVERFLOW;
    }

    let dev_path = b"/dev/nsm\0";
    let fd = libc::open(dev_path.as_ptr().cast::<libc::c_char>(), libc::O_RDWR);
    if fd < 0 {
        return NONA_ERR_NSM_UNAVAILABLE;
    }

    let mut req_raw = [0u8; 16];
    let req_len = match encode_nsm_get_random_request(&mut req_raw) {
        Ok(len) => len,
        Err(err) => {
            libc::close(fd);
            return err;
        }
    };

    // NSM GetRandom returns up to 256 random bytes wrapped in a 22-byte CBOR header.
    let mut resp_raw = [0u8; 320];
    let mut raw_msg = NsmRawMessage {
        request: NsmIovec {
            addr: req_raw.as_ptr() as u64,
            len: req_len as u64,
        },
        response: NsmIovec {
            addr: resp_raw.as_mut_ptr() as u64,
            len: resp_raw.len() as u64,
        },
    };

    let ret = libc::ioctl(fd, NSM_IOCTL_RAW as _, &raw mut raw_msg);
    libc::close(fd);
    ct_zeroize(&mut req_raw);

    if ret < 0 {
        ct_zeroize(&mut resp_raw);
        return NONA_ERR_NSM_IOCTL_FAILED;
    }

    let resp_len = raw_msg.response.len as usize;
    if resp_len == 0 || resp_len > resp_raw.len() {
        ct_zeroize(&mut resp_raw);
        return NONA_ERR_ATTEST_OVERFLOW;
    }

    let random_bytes = match parse_nsm_get_random_response(&resp_raw[..resp_len]) {
        Ok(bytes) => bytes,
        Err(err) => {
            ct_zeroize(&mut resp_raw);
            return err;
        }
    };

    if random_bytes.len() < out.len() {
        ct_zeroize(&mut resp_raw);
        return NONA_ERR_NSM_IOCTL_FAILED;
    }

    out.copy_from_slice(&random_bytes[..out.len()]);
    ct_zeroize(&mut resp_raw);

    // Reject degenerate all-zero entropy block
    let mut acc: u8 = 0;
    for &b in out.iter() {
        acc |= b;
    }
    if acc == 0 {
        ct_zeroize(out);
        return NONA_ERR_NSM_IOCTL_FAILED;
    }

    0
}

/// Returns `true` if `/dev/nsm` is present and accessible in the runtime environment.
#[inline]
pub fn is_nsm_available() -> bool {
    let dev_path = b"/dev/nsm\0";
    unsafe { libc::access(dev_path.as_ptr().cast::<libc::c_char>(), libc::R_OK | libc::W_OK) == 0 }
}

/// Fills `dest` solely via direct `/dev/nsm` `GetRandom` IOCTL requests.
/// Executes immediate unrecoverable `zeroize_and_abort(NONA_ERR_INTERNAL_PANIC)` on any failure.
#[inline(never)]
pub fn fill_nsm_entropy_or_abort(dest: &mut [u8]) {
    if dest.is_empty() {
        crate::exception::zeroize_and_abort(crate::gatekeeper::NONA_ERR_INTERNAL_PANIC);
    }
    for chunk in dest.chunks_mut(256) {
        let rc = unsafe { query_hardware_random(chunk) };
        if rc != 0 {
            ct_zeroize(dest);
            crate::exception::zeroize_and_abort(crate::gatekeeper::NONA_ERR_INTERNAL_PANIC);
        }
    }
}

/// Harvests a 64-bit hardware entropy word solely from `/dev/nsm` `GetRandom` IOCTL.
/// Immediately aborts via `zeroize_and_abort(NONA_ERR_INTERNAL_PANIC)` if NSM fails.
#[inline(never)]
pub fn nsm_get_random_u64() -> u64 {
    let mut buf = [0u8; 8];
    fill_nsm_entropy_or_abort(&mut buf);
    let val = u64::from_le_bytes(buf);
    ct_zeroize(&mut buf);
    val
}

// Hardware ioctl Interlock (/dev/nsm)

/// Direct zero-heap query to AWS Nitro Security Module (/dev/nsm) via ioctl.
/// Binds the ephemeral public key to obtain a hypervisor-signed attestation document.
#[allow(clippy::cast_possible_truncation)]
pub unsafe fn query_hardware_attestation_with_nonce(
    user_data: &[u8],
    nonce: Option<&[u8]>,
    doc_out: &mut AttestationDocumentBuffer,
) -> i32 {
    let dev_path = b"/dev/nsm\0";
    let fd = libc::open(dev_path.as_ptr().cast::<libc::c_char>(), libc::O_RDWR);
    if fd < 0 {
        return NONA_ERR_NSM_UNAVAILABLE;
    }

    let mut req_raw = [0u8; 512];
    let req_len = match encode_nsm_attestation_request_with_nonce(user_data, nonce, &mut req_raw) {
        Ok(len) => len,
        Err(err) => {
            libc::close(fd);
            return err;
        }
    };

    let mut raw_msg = NsmRawMessage {
        request: NsmIovec {
            addr: req_raw.as_ptr() as u64,
            len: req_len as u64,
        },
        response: NsmIovec {
            addr: doc_out.data.as_mut_ptr() as u64,
            len: ATTESTATION_MAX_DOC_SIZE as u64,
        },
    };

    let ret = libc::ioctl(fd, NSM_IOCTL_RAW as _, &raw mut raw_msg);
    libc::close(fd);
    ct_zeroize(&mut req_raw);

    if ret < 0 {
        return NONA_ERR_NSM_IOCTL_FAILED;
    }

    let resp_len = raw_msg.response.len as usize;
    if resp_len == 0 || resp_len > ATTESTATION_MAX_DOC_SIZE {
        return NONA_ERR_ATTEST_OVERFLOW;
    }

    doc_out.actual_len = resp_len;
    0
}

pub unsafe fn query_hardware_attestation(
    user_data: &[u8],
    doc_out: &mut AttestationDocumentBuffer,
) -> i32 {
    query_hardware_attestation_with_nonce(user_data, None, doc_out)
}

pub unsafe fn generate_enclave_attestation(
    ephemeral_private_key: &[u8; 32],
    doc_out: &mut AttestationDocumentBuffer,
) -> i32 {
    let mut pubkey = [0u8; SECP256K1_PUBKEY_COMPRESSED_SIZE];
    let key_res = derive_compressed_public_key(ephemeral_private_key, &mut pubkey);
    if key_res != 0 {
        return key_res;
    }

    query_hardware_attestation(&pubkey, doc_out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secp256k1_public_key_derivation() {
        let mut privkey = [0u8; 32];
        privkey[0] = 1; // scalar = 1 (Generator G) in little-endian

        let mut pubkey = [0u8; SECP256K1_PUBKEY_COMPRESSED_SIZE];
        let res = derive_compressed_public_key(&privkey, &mut pubkey);
        assert_eq!(res, 0);

        // Generator affine X = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
        // Generator affine Y is even, so compressed prefix is 0x02
        assert_eq!(pubkey[0], 0x02);
        assert_eq!(pubkey[1], 0x79);
        assert_eq!(pubkey[2], 0xbe);
        assert_eq!(pubkey[32], 0x98);
    }

    #[test]
    fn test_cbor_attestation_request_encoding() {
        let user_data = [0xAA; 33];
        let mut req_buf = [0u8; 128];
        let len = encode_nsm_attestation_request(&user_data, &mut req_buf).unwrap_or_default();
        assert!(len > 33);
        assert_eq!(req_buf[0], 0xa1); // Map(1)
        assert_eq!(req_buf[1], 0x6b); // Text(11)
        assert_eq!(&req_buf[2..13], b"Attestation");
    }

    #[test]
    fn test_cbor_get_random_request_and_response() {
        let mut req_buf = [0u8; 16];
        assert_eq!(encode_nsm_get_random_request(&mut req_buf), Ok(10));
        assert_eq!(&req_buf[..10], b"\x69GetRandom");

        // Canonical CBOR {"GetRandom": {"random": h'0102030405060708'}}
        let mut valid_resp = [0u8; 29];
        valid_resp[0] = 0xa1;
        valid_resp[1] = 0x69;
        valid_resp[2..11].copy_from_slice(b"GetRandom");
        valid_resp[11] = 0xa1;
        valid_resp[12] = 0x66;
        valid_resp[13..19].copy_from_slice(b"random");
        valid_resp[19] = 0x58;
        valid_resp[20] = 8;
        valid_resp[21..29].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);

        assert_eq!(
            parse_nsm_get_random_response(&valid_resp),
            Ok(&[1u8, 2, 3, 4, 5, 6, 7, 8][..])
        );

        // Truncated / malformed CBOR must fail closed
        assert_eq!(
            parse_nsm_get_random_response(&valid_resp[..20]),
            Err(NONA_ERR_NSM_IOCTL_FAILED)
        );
    }

    #[test]
    fn test_hardware_attestation_unavailable_fallback() {
        let dummy_key = [1u8; 32];
        // Enforce Architectural Invariant §1: AttestationDocumentBuffer (8,256 B) strictly
        // exceeds the < 4 KiB stack ceiling and must never be instantiated as a local stack variable.
        // In test environments, allocate inside a zero-heap static cell to eliminate stack activation.
        struct StaticAttestationDoc(core::cell::UnsafeCell<AttestationDocumentBuffer>);
        unsafe impl Sync for StaticAttestationDoc {}
        static TEST_DOC: StaticAttestationDoc =
            StaticAttestationDoc(core::cell::UnsafeCell::new(AttestationDocumentBuffer::INIT));

        let doc = unsafe { &mut *TEST_DOC.0.get() };
        doc.purge();
        let res = unsafe { generate_enclave_attestation(&dummy_key, doc) };
        // On non-enclave host environments (macOS/Darwin or non-Nitro containers),
        // /dev/nsm is absent, yielding NONA_ERR_NSM_UNAVAILABLE (-110) cleanly.
        assert_eq!(res, NONA_ERR_NSM_UNAVAILABLE);
    }
}
