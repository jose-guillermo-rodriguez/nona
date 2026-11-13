//! Formal Verification Boundary Specifications for Enclave Hardware and OS Interfaces.
//! Models `/dev/nsm` hardware IOCTL and CBOR framing (`attestation.rs`), vsock wire framing,
//! monotonic session operation ceilings (`enclave_server.rs` / `ChannelToken`), FFI pointer
//! disjointness (`gatekeeper.rs`), 128-byte ring ingestion (`ingest.rs`), and fail-closed
//! sliding-window exception containment (`exception.rs`).

#[cfg(verus)]
use vstd::prelude::*;

#[cfg(verus)]
verus! {

// ============================================================================
// 1. AWS Nitro Security Module (/dev/nsm) Hardware IOCTL & CBOR ABI Boundary
// ============================================================================

pub spec const SPEC_NSM_IOCTL_RAW: u64 = 0xC020_0A00;
pub spec const SPEC_ATTESTATION_MAX_DOC_SIZE: usize = 12288;
pub spec const SPEC_NSM_MAX_RANDOM_BYTES: usize = 256;

pub struct NsmIovecModel {
    pub addr: u64,
    pub len: u64,
}

pub struct NsmRawMessageModel {
    pub request: NsmIovecModel,
    pub response: NsmIovecModel,
}

impl NsmRawMessageModel {
    pub open spec fn wf(&self, max_req: u64, max_resp: u64) -> bool {
        &&& self.request.addr != 0
        &&& self.response.addr != 0
        &&& self.request.len > 0
        &&& self.request.len <= max_req
        &&& self.response.len > 0
        &&& self.response.len <= max_resp
        &&& (self.request.addr as int) + (self.request.len as int) <= u64::MAX as int
        &&& (self.response.addr as int) + (self.response.len as int) <= u64::MAX as int
        &&& ((self.request.addr as int) + (self.request.len as int) <= (self.response.addr as int)
            || (self.response.addr as int) + (self.response.len as int) <= (self.request.addr as int))
    }
}

/// Hardware OS `/dev/nsm` `ioctl(fd, NSM_IOCTL_RAW, &raw_msg)` boundary model.
/// Captures the exact kernel/hypervisor ABI postconditions: on success (`rc == 0`),
/// response byte count is strictly bounded within `1..=msg.response.len`; on failure,
/// fail-closed negative status is returned.
#[verifier::external_body]
pub fn ffi_nsm_ioctl_raw_contract(msg: &NsmRawMessageModel, ioctl_cmd: u64) -> (res: (i32, usize))
    requires
        ioctl_cmd == SPEC_NSM_IOCTL_RAW,
        msg.wf(512, 12288),
    ensures
        res.0 == 0 ==> (res.1 > 0 && (res.1 as u64) <= msg.response.len),
        res.0 != 0 ==> res.1 == 0,
{
    let _ = (msg, ioctl_cmd);
    (-110, 0)
}

/// Satisfies [FR-12-FORMALSPEC]
/// Verified CBOR wire length bound for NSM `Attestation` request synthesis (`attestation.rs`).
pub fn compute_nsm_attestation_cbor_len(
    user_data_len: usize,
    has_nonce: bool,
    nonce_len: usize,
    out_cap: usize,
) -> (res: Result<usize, i32>)
    ensures
        match res {
            Ok(req_len) => {
                &&& user_data_len <= 255
                &&& (!has_nonce || nonce_len <= 255)
                &&& req_len <= out_cap
                &&& req_len <= 562
            },
            Err(code) => code == -112,
        }
{
    if user_data_len > 255 {
        return Err(-112);
    }
    let nonce_field_len: usize = if has_nonce {
        if nonce_len > 255 {
            return Err(-112);
        }
        2 + nonce_len
    } else {
        1
    };
    let req_len: usize = 1 + 1 + 11 + 1 + 1 + 9 + 2 + user_data_len + 1 + 5 + nonce_field_len + 1 + 10 + 1;
    if out_cap < req_len {
        return Err(-112);
    }
    Ok(req_len)
}

/// Satisfies [FR-12-FORMALSPEC]
/// Verified CBOR `GetRandom` response parser slice-bound invariant (`attestation.rs`).
pub fn validate_nsm_random_cbor_slice(
    resp_len: usize,
    addl: u8,
    bstr_len: usize,
) -> (res: Result<(usize, usize), i32>)
    requires
        addl <= 31,
    ensures
        match res {
            Ok((offset, len)) => {
                &&& len > 0
                &&& offset >= 20
                &&& offset + len == resp_len
            },
            Err(code) => code == -111,
        }
{
    if resp_len < 21 {
        return Err(-111);
    }
    let payload_offset: usize = if addl < 24 {
        20usize
    } else if addl == 24 {
        21usize
    } else if addl == 25 {
        if resp_len < 22 {
            return Err(-111);
        }
        22usize
    } else {
        return Err(-111);
    };

    if bstr_len == 0 || bstr_len > resp_len || payload_offset != resp_len - bstr_len {
        return Err(-111);
    }
    Ok((payload_offset, bstr_len))
}

// ============================================================================
// 2. Enclave Session Lifecycle, Monotonic Ceiling & Vsock Wire Framing Boundary
// ============================================================================

pub spec const SPEC_MAX_SESSION_OPS: u64 = 1_000_000;
pub spec const SPEC_MAX_PAYLOAD_SIZE: usize = 16384;
pub spec const SPEC_NONA_VSOCK_MAGIC: u32 = 0x4E4F_4E41;
pub spec const SPEC_NONA_VSOCK_VERSION: u16 = 1;

pub struct EnclaveSessionModel {
    pub state: u8,
    pub epoch: u64,
    pub op_count: u64,
}

impl EnclaveSessionModel {
    pub open spec fn wf(&self) -> bool {
        &&& (self.state == 0u8 || self.state == 1u8 || self.state == 2u8)
        &&& self.op_count <= SPEC_MAX_SESSION_OPS
        &&& (self.state == 0u8 ==> self.op_count == 0)
    }
}

/// Satisfies [FR-30-GHOSTPERM]
/// Satisfies [FR-36-TIMEWARP]
/// Satisfies [FR-12-FORMALSPEC]
/// Verified state-machine transition for `advance_session_op_counter` (`enclave_server.rs`).
/// Proves monotonic sequence progression bounded by `MAX_SESSION_OPS` and fail-closed purge.
pub fn session_advance_op_verified(session: &mut EnclaveSessionModel) -> (res: Result<u64, i32>)
    requires
        old(session).wf(),
    ensures
        final(session).wf(),
        match res {
            Ok(seq) => {
                &&& old(session).state == 2u8
                &&& old(session).op_count < SPEC_MAX_SESSION_OPS
                &&& final(session).state == 2u8
                &&& final(session).epoch == old(session).epoch
                &&& seq == old(session).op_count + 1
                &&& final(session).op_count == seq
                &&& final(session).op_count <= SPEC_MAX_SESSION_OPS
            },
            Err(code) => {
                &&& code == -1
                &&& final(session).state == 0u8
                &&& final(session).op_count == 0
            }
        }
{
    if session.state != 2u8 || session.op_count >= 1_000_000u64 {
        session.state = 0u8;
        session.op_count = 0u64;
        return Err(-1);
    }
    let next_seq = session.op_count + 1u64;
    session.op_count = next_seq;
    Ok(next_seq)
}

/// OS `CLOCK_MONOTONIC` boundary model (`monotonic_now_ns` in `enclave_server.rs`).
#[verifier::external_body]
pub fn ffi_clock_monotonic_ns(prev_ns: u64) -> (now_ns: u64)
    ensures
        now_ns >= prev_ns,
{
    prev_ns
}

/// OS `AF_VSOCK` / `AF_UNIX` exact stream frame receive boundary (`recv_exact`).
#[verifier::external_body]
pub fn ffi_vsock_recv_exact(buf_cap: usize, expected_len: usize) -> (res: Result<usize, i32>)
    requires
        expected_len <= buf_cap,
    ensures
        match res {
            Ok(n) => n == expected_len,
            Err(code) => code == -5,
        }
{
    let _ = buf_cap;
    Ok(expected_len)
}

/// Satisfies [FR-13-WIREPROT]
/// Satisfies [FR-12-FORMALSPEC]
/// Machine-checked bit-vector proof that little-endian u32 wire serialization is bijective.
pub proof fn lemma_u32_le_wire_bijective(v: u32)
    ensures
        ({
            let b0 = (v & 0xFF) as u8;
            let b1 = ((v >> 8) & 0xFF) as u8;
            let b2 = ((v >> 16) & 0xFF) as u8;
            let b3 = ((v >> 24) & 0xFF) as u8;
            let reconstructed = (b0 as u32)
                | ((b1 as u32) << 8)
                | ((b2 as u32) << 16)
                | ((b3 as u32) << 24);
            reconstructed == v
        })
{
    assert(({
        let b0 = (v & 0xFFu32) as u8;
        let b1 = ((v >> 8u32) & 0xFFu32) as u8;
        let b2 = ((v >> 16u32) & 0xFFu32) as u8;
        let b3 = ((v >> 24u32) & 0xFFu32) as u8;
        let reconstructed = (b0 as u32)
            | ((b1 as u32) << 8u32)
            | ((b2 as u32) << 16u32)
            | ((b3 as u32) << 24u32);
        reconstructed == v
    })) by(bit_vector);
}

// ============================================================================
// 3. FFI Gatekeeper Disjointness, Ring Ingress & Sliding-Window Exception Trap
// ============================================================================

pub open spec fn spec_spans_disjoint(a_start: usize, len_a: usize, b_start: usize, len_b: usize) -> bool {
    let a_end = (a_start as int) + (len_a as int);
    let b_end = (b_start as int) + (len_b as int);
    &&& a_end <= usize::MAX as int
    &&& b_end <= usize::MAX as int
    &&& (a_end <= (b_start as int) || b_end <= (a_start as int))
}

/// Satisfies [FR-19-FFIBND]
/// Satisfies [FR-08-GATEKEEPR]
/// Satisfies [FR-12-FORMALSPEC]
/// Verified spatial non-aliasing predicate matching `gatekeeper::is_disjoint`.
pub fn check_spans_disjoint_verified(
    a_start: usize,
    len_a: usize,
    b_start: usize,
    len_b: usize,
) -> (res: bool)
    ensures
        res == spec_spans_disjoint(a_start, len_a, b_start, len_b),
{
    if len_a > usize::MAX - a_start || len_b > usize::MAX - b_start {
        return false;
    }
    let a_end = a_start + len_a;
    let b_end = b_start + len_b;
    a_end <= b_start || b_end <= a_start
}

/// Satisfies [FR-08-GATEKEEPR]
/// Satisfies [FR-12-FORMALSPEC]
/// Machine-checked proof that `ct_compute_status` (`gatekeeper.rs`) deterministically
/// returns `0` iff all validity bits are `1` and maps violations to canonical error codes.
pub proof fn lemma_gatekeeper_status_soundness(s_l: u64, s_n: u64, s_h: u64)
    requires
        s_l == 0 || s_l == 1,
        s_n == 0 || s_n == 1,
        s_h == 0 || s_h == 1,
    ensures
        ({
            let sl = s_l as int;
            let sn = s_n as int;
            let sh = s_h as int;
            let status = (1 - sl) * (-3) + sl * (1 - sn) * (-10) + sl * sn * (1 - sh) * (-14);
            &&& ((status == 0) <==> (s_l == 1 && s_n == 1 && s_h == 1))
            &&& (s_l == 0 ==> status == -3)
            &&& (s_l == 1 && s_n == 0 ==> status == -10)
            &&& (s_l == 1 && s_n == 1 && s_h == 0 ==> status == -14)
        })
{
    if s_l == 0 {
        assert((s_l as int) == 0);
    } else if s_n == 0 {
        assert((s_l as int) == 1 && (s_n as int) == 0);
    } else if s_h == 0 {
        assert((s_l as int) == 1 && (s_n as int) == 1 && (s_h as int) == 0);
    } else {
        assert((s_l as int) == 1 && (s_n as int) == 1 && (s_h as int) == 1);
    }
}

/// Satisfies [FR-10-RINGMAN]
/// Satisfies [FR-17-STRMIN]
/// Satisfies [FR-12-FORMALSPEC]
/// Verified pre-flight capacity and 128-byte framing gate (`ingest.rs`).
pub fn check_ring_ingest_preflight(used_slots: usize, byte_len: usize) -> (res: Result<usize, i32>)
    requires
        used_slots <= 128,
    ensures
        match res {
            Ok(chunks) => {
                &&& byte_len > 0
                &&& byte_len <= 4096
                &&& byte_len % 128 == 0
                &&& chunks == byte_len / 128
                &&& used_slots + chunks <= 128
            },
            Err(code) => code == -1 || code == -3 || code == -4,
        }
{
    if byte_len == 0 {
        return Err(-1);
    }
    if byte_len > 4096 || (byte_len % 128) != 0 {
        return Err(-3);
    }
    let chunks = byte_len / 128;
    let available = 128usize - used_slots;
    if chunks > available {
        return Err(-4);
    }
    Ok(chunks)
}

/// Satisfies [FR-20-ABRTGATE]
/// Satisfies [FR-12-FORMALSPEC]
/// Machine-checked bit-vector proof of branchless exception cursor advancement (`exception.rs`).
pub proof fn lemma_exception_cursor_branchless(e_i: u8)
    ensures
        ({
            let delta = (((e_i as u64).wrapping_sub(1u64)) >> 63u64) & 1u64;
            (e_i == 0u8 ==> delta == 1u64) && (e_i != 0u8 ==> delta == 0u64)
        })
{
    assert(({
        let delta = (((e_i as u64).wrapping_sub(1u64)) >> 63u64) & 1u64;
        (e_i == 0u8 ==> delta == 1u64) && (e_i != 0u8 ==> delta == 0u64)
    })) by(bit_vector);
}

} // verus!
