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
pub fn encode_nsm_attestation_request(user_data: &[u8], out_buf: &mut [u8]) -> Result<usize, i32> {
    // Canonical aws-nitro-enclaves-nsm-api CBOR envelope:
    // {"Attestation": {"user_data": <bytes>, "nonce": null, "public_key": null}}
    let req_len = 1 + 1 + 11 + 1 + 1 + 9 + 2 + user_data.len() + 1 + 5 + 1 + 1 + 10 + 1;
    if out_buf.len() < req_len || user_data.len() > 255 {
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

    // Field 2: nonce = null
    out_buf[cursor] = 0x65; // text(5)
    cursor += 1;
    out_buf[cursor..cursor + 5].copy_from_slice(b"nonce");
    cursor += 5;
    out_buf[cursor] = 0xf6; // null
    cursor += 1;

    // Field 3: public_key = null
    out_buf[cursor] = 0x6a; // text(10)
    cursor += 1;
    out_buf[cursor..cursor + 10].copy_from_slice(b"public_key");
    cursor += 10;
    out_buf[cursor] = 0xf6; // null
    cursor += 1;

    Ok(cursor)
}

// Hardware ioctl Interlock (/dev/nsm)

/// Direct zero-heap query to AWS Nitro Security Module (/dev/nsm) via ioctl.
/// Binds the ephemeral public key to obtain a hypervisor-signed attestation document.
#[allow(clippy::cast_possible_truncation)]
pub unsafe fn query_hardware_attestation(
    user_data: &[u8],
    doc_out: &mut AttestationDocumentBuffer,
) -> i32 {
    let dev_path = b"/dev/nsm\0";
    let fd = libc::open(dev_path.as_ptr().cast::<libc::c_char>(), libc::O_RDWR);
    if fd < 0 {
        return NONA_ERR_NSM_UNAVAILABLE;
    }

    let mut req_raw = [0u8; 512];
    let req_len = match encode_nsm_attestation_request(user_data, &mut req_raw) {
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

    doc_out.actual_len = raw_msg.response.len as usize;
    0
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
