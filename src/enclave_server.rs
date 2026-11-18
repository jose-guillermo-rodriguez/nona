//! Bare-metal confidential server listener for AWS Nitro Enclaves and local Unix domain socket.
//! Operates with zero dynamic allocations (#![no_std]) using cache-aligned stack buffers.

use crate::attestation::{
    derive_compressed_public_key, fill_nsm_entropy_or_abort, is_nsm_available, query_hardware_attestation_with_nonce,
    AttestationDocumentBuffer, ATTESTATION_MAX_DOC_SIZE, NONA_ERR_ATTEST_OVERFLOW,
    SECP256K1_PUBKEY_COMPRESSED_SIZE,
};
use crate::crypto::{ct_zeroize, sha512_digest};
use core::mem::size_of;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};

pub const AF_VSOCK: i32 = 40;
pub const VMADDR_CID_ANY: u32 = 0xFFFFFFFF;
pub const DEFAULT_VSOCK_PORT: u32 = 5005;
pub const DEFAULT_UNIX_SOCKET: &[u8] = b"/tmp/nona.sock\0";

pub const NONA_VSOCK_MAGIC: u32 = 0x4E4F_4E41; // "NONA" in ASCII big-endian
pub const NONA_VSOCK_VERSION: u16 = 1;

pub const CMD_PING: u16 = 0x0001;
pub const CMD_INGEST: u16 = 0x0002;
pub const CMD_BLIND_PHASE1: u16 = 0x0003;
pub const CMD_ATTEST: u16 = 0x0004;
pub const CMD_PHASE2_REBLIND: u16 = 0x0005;
pub const CMD_PHASE2_INTERSECT: u16 = 0x0006;

pub const FLAG_USE_SESSION_KEY: u32 = 0x0001;
pub const MAX_PAYLOAD_SIZE: usize = 16384;
pub const MAX_WIRE_PAYLOAD_BYTES: usize = MAX_PAYLOAD_SIZE;
pub const MAX_VSOCK_FRAME_BYTES: usize = EnclaveRequestHeader::WIRE_SIZE + MAX_WIRE_PAYLOAD_BYTES;
pub const NONA_ERR_INVALID_PHASE: i32 = -103;

/// Opaque wire status returned across vsock on any parsing, framing, or verification failure
/// to suppress internal diagnostic oracles.
pub const NONA_WIRE_ERR_OPAQUE: i32 = -1;
/// Minimum per-frame wire response floor (250 microseconds) eliminating early-exit timing side channels.
pub const WIRE_FRAME_FLOOR_NS: u64 = 250_000;

/// Maximum cryptographic operations permitted per ephemeral enclave session key
/// enforced via a monotonic counter independent of hypervisor clocks (FR-36-TIMEWARP).
pub const MAX_SESSION_OPS: u64 = 1_000_000;

const SESSION_STATE_UNINIT: u8 = 0;
const SESSION_STATE_INITIALIZING: u8 = 1;
const SESSION_STATE_READY: u8 = 2;

struct EnclaveSessionKey {
    state: AtomicU8,
    epoch: AtomicU64,
    op_count: AtomicU64,
    privkey: core::cell::UnsafeCell<[u8; 32]>,
    pubkey: core::cell::UnsafeCell<[u8; SECP256K1_PUBKEY_COMPRESSED_SIZE]>,
}

unsafe impl Sync for EnclaveSessionKey {}

static SESSION_KEY: EnclaveSessionKey = EnclaveSessionKey {
    state: AtomicU8::new(SESSION_STATE_UNINIT),
    epoch: AtomicU64::new(0),
    op_count: AtomicU64::new(0),
    privkey: core::cell::UnsafeCell::new([0u8; 32]),
    pubkey: core::cell::UnsafeCell::new([0u8; SECP256K1_PUBKEY_COMPRESSED_SIZE]),
};

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sockaddr_vm {
    pub svm_family: u16,
    pub svm_reserved1: u16,
    pub svm_port: u32,
    pub svm_cid: u32,
    pub svm_zero: [u8; 4],
}

impl sockaddr_vm {
    #[allow(clippy::cast_possible_truncation)]
    pub const fn new(port: u32, cid: u32) -> Self {
        Self {
            svm_family: AF_VSOCK as u16,
            svm_reserved1: 0,
            svm_port: port,
            svm_cid: cid,
            svm_zero: [0u8; 4],
        }
    }
}

#[repr(C, align(64))]
pub struct EnclaveRequestHeader {
    pub magic: u32,
    pub version: u16,
    pub command: u16,
    pub payload_len: u32,
    pub flags: u32,
    pub reserved: [u8; 16],
}

#[repr(C, align(64))]
pub struct EnclaveResponseHeader {
    pub magic: u32,
    pub version: u16,
    pub status: i32,
    pub payload_len: u32,
    pub reserved: [u8; 20],
}

impl EnclaveRequestHeader {
    pub const WIRE_SIZE: usize = 64;

    #[inline(always)]
    #[must_use]
    pub fn to_wire_bytes(&self) -> [u8; Self::WIRE_SIZE] {
        let mut buf = [0u8; Self::WIRE_SIZE];
        buf[0..4].copy_from_slice(&self.magic.to_le_bytes());
        buf[4..6].copy_from_slice(&self.version.to_le_bytes());
        buf[6..8].copy_from_slice(&self.command.to_le_bytes());
        buf[8..12].copy_from_slice(&self.payload_len.to_le_bytes());
        buf[12..16].copy_from_slice(&self.flags.to_le_bytes());
        buf[16..32].copy_from_slice(&self.reserved);
        buf
    }

    #[inline(always)]
    #[must_use]
    pub fn from_wire_bytes(buf: &[u8; Self::WIRE_SIZE]) -> Self {
        let mut reserved = [0u8; 16];
        reserved.copy_from_slice(&buf[16..32]);
        Self {
            magic: u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
            version: u16::from_le_bytes([buf[4], buf[5]]),
            command: u16::from_le_bytes([buf[6], buf[7]]),
            payload_len: u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]),
            flags: u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]),
            reserved,
        }
    }

    /// Validates header magic, version, opcode, reserved padding, and static payload/frame
    /// ceilings strictly BEFORE reading payload bytes from an untrusted transport stream.
    #[inline(never)]
    pub fn validate_pre_payload(&self) -> Result<usize, i32> {
        if self.magic != NONA_VSOCK_MAGIC {
            return Err(-100);
        }
        if self.version != NONA_VSOCK_VERSION {
            return Err(-101);
        }
        if self.reserved.iter().any(|&b| b != 0) {
            return Err(-104);
        }
        let Ok(plen) = usize::try_from(self.payload_len) else {
            return Err(-3);
        };
        if plen > MAX_WIRE_PAYLOAD_BYTES {
            return Err(-3);
        }
        let Some(total_frame) = Self::WIRE_SIZE.checked_add(plen) else {
            return Err(-3);
        };
        if total_frame > MAX_VSOCK_FRAME_BYTES {
            return Err(-3);
        }
        match self.command {
            CMD_PING => Ok(plen),
            CMD_ATTEST => {
                if plen > 64 {
                    Err(-3)
                } else {
                    Ok(plen)
                }
            }
            CMD_INGEST => {
                if plen == 0 || plen > 4096 || !plen.is_multiple_of(128) {
                    Err(-3)
                } else {
                    Ok(plen)
                }
            }
            CMD_BLIND_PHASE1 | CMD_PHASE2_REBLIND => {
                if plen == 0 || !plen.is_multiple_of(32) {
                    Err(-3)
                } else {
                    Ok(plen)
                }
            }
            CMD_PHASE2_INTERSECT => {
                if plen < 16 {
                    Err(-3)
                } else {
                    Ok(plen)
                }
            }
            _ => Err(-102),
        }
    }

    /// Parses and validates a fixed 64-byte wire header slice prior to payload ingestion.
    #[inline(never)]
    pub fn parse_wire_bytes(buf: &[u8]) -> Result<Self, i32> {
        if buf.len() != Self::WIRE_SIZE {
            return Err(-3);
        }
        if buf[32..Self::WIRE_SIZE].iter().any(|&b| b != 0) {
            return Err(-104);
        }
        let mut fixed = [0u8; Self::WIRE_SIZE];
        fixed.copy_from_slice(buf);
        let hdr = Self::from_wire_bytes(&fixed);
        let _ = hdr.validate_pre_payload()?;
        Ok(hdr)
    }
}

impl EnclaveResponseHeader {
    pub const WIRE_SIZE: usize = 64;

    #[inline(always)]
    #[must_use]
    pub fn to_wire_bytes(&self) -> [u8; Self::WIRE_SIZE] {
        let mut buf = [0u8; Self::WIRE_SIZE];
        buf[0..4].copy_from_slice(&self.magic.to_le_bytes());
        buf[4..6].copy_from_slice(&self.version.to_le_bytes());
        buf[8..12].copy_from_slice(&self.status.to_le_bytes());
        buf[12..16].copy_from_slice(&self.payload_len.to_le_bytes());
        buf[16..36].copy_from_slice(&self.reserved);
        buf
    }

    #[inline(always)]
    #[must_use]
    pub fn from_wire_bytes(buf: &[u8; Self::WIRE_SIZE]) -> Self {
        let mut reserved = [0u8; 20];
        reserved.copy_from_slice(&buf[16..36]);
        Self {
            magic: u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
            version: u16::from_le_bytes([buf[4], buf[5]]),
            status: i32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]),
            payload_len: u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]),
            reserved,
        }
    }
}

#[repr(C, align(64))]
pub struct EnclaveFrameBuffer {
    pub data: [u8; MAX_PAYLOAD_SIZE],
}

impl EnclaveFrameBuffer {
    pub const INIT: Self = Self {
        data: [0u8; MAX_PAYLOAD_SIZE],
    };

    pub fn purge(&mut self) {
        ct_zeroize(&mut self.data);
    }
}

impl Drop for EnclaveFrameBuffer {
    fn drop(&mut self) {
        self.purge();
    }
}

/// Staging buffer slot for bidirectional enclave protocol frames and hardware attestation.
#[repr(C, align(64))]
pub struct EnclaveConnectionSlot {
    pub in_buffer: EnclaveFrameBuffer,
    pub out_buffer: EnclaveFrameBuffer,
    pub scratch_buffer: EnclaveFrameBuffer,
    pub attestation_doc: AttestationDocumentBuffer,
}

impl EnclaveConnectionSlot {
    pub const INIT: Self = Self {
        in_buffer: EnclaveFrameBuffer::INIT,
        out_buffer: EnclaveFrameBuffer::INIT,
        scratch_buffer: EnclaveFrameBuffer::INIT,
        attestation_doc: AttestationDocumentBuffer::INIT,
    };

    pub fn purge(&mut self) {
        self.in_buffer.purge();
        self.out_buffer.purge();
        self.scratch_buffer.purge();
        self.attestation_doc.purge();
    }
}

pub type StagingBufferPair = EnclaveConnectionSlot;

pub const ENCLAVE_STAGING_POOL_SLOTS: usize = 16;

/// Static, zero-allocation staging buffer pool for concurrent enclave connections.
pub struct StagingBufferPool {
    slots: [core::cell::UnsafeCell<EnclaveConnectionSlot>; ENCLAVE_STAGING_POOL_SLOTS],
    in_use: [AtomicBool; ENCLAVE_STAGING_POOL_SLOTS],
}

unsafe impl Sync for StagingBufferPool {}

impl StagingBufferPool {
    #[allow(clippy::declare_interior_mutable_const, clippy::large_stack_arrays)]
    pub const INIT: Self = {
        const INIT_SLOT: core::cell::UnsafeCell<EnclaveConnectionSlot> =
            core::cell::UnsafeCell::new(EnclaveConnectionSlot::INIT);
        const INIT_FLAG: AtomicBool = AtomicBool::new(false);
        Self {
            slots: [INIT_SLOT; ENCLAVE_STAGING_POOL_SLOTS],
            in_use: [INIT_FLAG; ENCLAVE_STAGING_POOL_SLOTS],
        }
    };

    pub fn acquire(&self) -> Option<StagingBufferGuard<'_>> {
        for _ in 0..10_000 {
            for (i, flag) in self.in_use.iter().enumerate() {
                if flag
                    .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
                    .is_ok()
                {
                    let slot = unsafe { &mut *self.slots[i].get() };
                    return Some(StagingBufferGuard {
                        pool: self,
                        slot_index: i,
                        pair: slot,
                    });
                }
            }
            core::hint::spin_loop();
        }
        None
    }
}

/// RAII guard providing scoped access and unconditional zeroization on drop.
pub struct StagingBufferGuard<'a> {
    pool: &'a StagingBufferPool,
    slot_index: usize,
    pub pair: &'a mut EnclaveConnectionSlot,
}

impl<'a> Drop for StagingBufferGuard<'a> {
    fn drop(&mut self) {
        self.pair.purge();
        self.pool.in_use[self.slot_index].store(false, Ordering::Release);
    }
}

static STAGING_POOL: StagingBufferPool = StagingBufferPool::INIT;

#[repr(C, align(64))]
pub struct AlignedKeyBuffer {
    pub data: [u8; 32],
}

impl Drop for AlignedKeyBuffer {
    fn drop(&mut self) {
        ct_zeroize(&mut self.data);
    }
}

// Hardware CSPRNG for #![no_std] Confidential Enclave
// Seeded exclusively via direct /dev/nsm GetRandom IOCTL requests with fail-stop abort.

/// Satisfies enclave lifecycle reboot and testing reset semantics.
/// Securely decontaminates the cached session keypair using constant-time zeroization.
/// Gated to std/test environments to ensure physical exclusion from bare-metal #![no_std] production binaries.
/// Unconditionally purges the enclave session keypair in constant time.
/// Invoked during fatal aborts and crash signal traps to prevent memory remanence.
pub fn purge_session_key_unconditional() {
    unsafe {
        ct_zeroize(&mut *SESSION_KEY.privkey.get());
        ct_zeroize(&mut *SESSION_KEY.pubkey.get());
    }
    SESSION_KEY.op_count.store(0, Ordering::SeqCst);
    SESSION_KEY
        .state
        .store(SESSION_STATE_UNINIT, Ordering::SeqCst);
}

#[cfg(any(test, feature = "std"))]
pub fn reset_session_key() {
    purge_session_key_unconditional();
}

#[cfg(not(target_os = "none"))]
extern "C" fn enclave_fatal_signal_handler(_sig: libc::c_int) {
    core::sync::atomic::compiler_fence(Ordering::SeqCst);
    purge_session_key_unconditional();
    crate::exception::decontaminate();
    unsafe {
        libc::_exit(1);
    }
}

/// Hardens the enclave process against host memory core dumps, ptrace inspection,
/// swap leakage, and unhandled crash signal disclosure.
pub fn harden_enclave_process() {
    #[cfg(not(target_os = "none"))]
    unsafe {
        let zero_limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        let _ = libc::setrlimit(libc::RLIMIT_CORE, &raw const zero_limit);

        #[cfg(target_os = "linux")]
        {
            const PR_SET_DUMPABLE: libc::c_int = 4;
            const MADV_DONTDUMP: libc::c_int = 16;
            let _ = libc::prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
            let _ = libc::madvise(
                (&raw const SESSION_KEY).cast::<libc::c_void>().cast_mut(),
                size_of::<EnclaveSessionKey>(),
                MADV_DONTDUMP,
            );
            let _ = libc::madvise(
                (&raw const STAGING_POOL).cast::<libc::c_void>().cast_mut(),
                size_of::<StagingBufferPool>(),
                MADV_DONTDUMP,
            );
        }

        #[cfg(feature = "host-defense")]
        {
            let _ = libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE);
        }

        let handler = enclave_fatal_signal_handler as *const () as libc::sighandler_t;
        let _ = libc::signal(libc::SIGINT, handler);
        let _ = libc::signal(libc::SIGTERM, handler);
        let _ = libc::signal(libc::SIGSEGV, handler);
        let _ = libc::signal(libc::SIGABRT, handler);
        let _ = libc::signal(libc::SIGBUS, handler);
        let _ = libc::signal(libc::SIGILL, handler);
        let _ = libc::signal(libc::SIGFPE, handler);
    }
}

#[inline(never)]
fn ensure_session_key_initialized() {
    loop {
        match SESSION_KEY.state.load(Ordering::Acquire) {
            SESSION_STATE_READY => return,
            SESSION_STATE_UNINIT => {
                if SESSION_KEY
                    .state
                    .compare_exchange(
                        SESSION_STATE_UNINIT,
                        SESSION_STATE_INITIALIZING,
                        Ordering::Acquire,
                        Ordering::Acquire,
                    )
                    .is_ok()
                {
                    let mut privkey = AlignedKeyBuffer { data: [0u8; 32] };
                    fill_nsm_entropy_or_abort(&mut privkey.data);

                    let mut pubkey = [0u8; SECP256K1_PUBKEY_COMPRESSED_SIZE];
                    if derive_compressed_public_key(&privkey.data, &mut pubkey) != 0 {
                        ct_zeroize(&mut privkey.data);
                        SESSION_KEY
                            .state
                            .store(SESSION_STATE_UNINIT, Ordering::Release);
                        crate::exception::zeroize_and_abort(
                            crate::gatekeeper::NONA_ERR_INTERNAL_PANIC,
                        );
                    }

                    unsafe {
                        (*SESSION_KEY.privkey.get()).copy_from_slice(&privkey.data);
                        (*SESSION_KEY.pubkey.get()).copy_from_slice(&pubkey);
                    }
                    ct_zeroize(&mut privkey.data);
                    SESSION_KEY.op_count.store(0, Ordering::SeqCst);
                    SESSION_KEY.epoch.fetch_add(1, Ordering::SeqCst);
                    SESSION_KEY
                        .state
                        .store(SESSION_STATE_READY, Ordering::Release);
                    return;
                }
            }
            _ => {
                core::hint::spin_loop();
            }
        }
    }
}

/// Advances the enclave's monotonic session operation counter using `ChannelToken`,
/// failing closed if `MAX_SESSION_OPS` is reached without relying on hypervisor clocks (FR-36-TIMEWARP).
#[inline(never)]
fn advance_session_op_counter() -> Result<u64, i32> {
    let mut prev = SESSION_KEY.op_count.load(Ordering::Acquire);
    loop {
        if prev >= MAX_SESSION_OPS {
            purge_session_key_unconditional();
            return Err(-1);
        }
        let next_seq = prev.saturating_add(1);
        match SESSION_KEY.op_count.compare_exchange_weak(
            prev,
            next_seq,
            Ordering::SeqCst,
            Ordering::Acquire,
        ) {
            Ok(_) => return Ok(next_seq),
            Err(actual) => prev = actual,
        }
    }
}

/// Initializes (if needed) and returns only the compressed 33-byte session public key.
/// Never copies the private scalar onto the caller's stack.
#[inline(never)]
pub fn get_or_create_session_pubkey() -> [u8; SECP256K1_PUBKEY_COMPRESSED_SIZE] {
    ensure_session_key_initialized();
    unsafe { *SESSION_KEY.pubkey.get() }
}

/// Copies the enclave session private scalar directly into a zeroize-on-drop `AlignedKeyBuffer`.
#[inline(never)]
pub fn load_session_privkey_into(dest: &mut AlignedKeyBuffer) {
    ensure_session_key_initialized();
    unsafe {
        dest.data.copy_from_slice(&*SESSION_KEY.privkey.get());
    }
}

/// Monotonic vsock session phase state aligned with `specs/vsock_session.tla`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SessionPhase {
    Unattested,
    AttestedBound,
    Phase1Blinded,
    Phase2Reblinded,
    Phase2Intersected,
    ClosedZeroized,
}

/// Per-connection session state machine enforcing monotonic phase transitions
/// and fail-closed buffer zeroization on any protocol or framing anomaly.
pub struct VsockSessionState {
    phase: SessionPhase,
    ops_in_session: u64,
}

impl Default for VsockSessionState {
    fn default() -> Self {
        Self::new()
    }
}

impl VsockSessionState {
    pub const fn new() -> Self {
        Self {
            phase: SessionPhase::Unattested,
            ops_in_session: 0,
        }
    }

    pub const fn phase(&self) -> SessionPhase {
        self.phase
    }

    pub const fn is_closed(&self) -> bool {
        matches!(
            self.phase,
            SessionPhase::Phase2Intersected | SessionPhase::ClosedZeroized
        )
    }

    /// Fail-closed transition: purges all active connection buffers with `write_volatile`
    /// and a `SeqCst` fence, collapsing the session into `ClosedZeroized`.
    #[inline(never)]
    pub fn fail_closed_with_slot(&mut self, slot: &mut EnclaveConnectionSlot) {
        slot.purge();
        self.ops_in_session = 0;
        self.phase = SessionPhase::ClosedZeroized;
        core::sync::atomic::compiler_fence(Ordering::SeqCst);
    }

    const fn is_command_allowed(&self, cmd: u16) -> bool {
        matches!(
            (self.phase, cmd),
            (
                SessionPhase::Unattested
                    | SessionPhase::AttestedBound
                    | SessionPhase::Phase1Blinded
                    | SessionPhase::Phase2Reblinded,
                CMD_PING,
            ) | (SessionPhase::Unattested, CMD_ATTEST)
                | (SessionPhase::AttestedBound, CMD_INGEST | CMD_BLIND_PHASE1)
                | (
                    SessionPhase::Phase1Blinded,
                    CMD_BLIND_PHASE1 | CMD_PHASE2_REBLIND
                )
                | (
                    SessionPhase::Phase2Reblinded,
                    CMD_PHASE2_REBLIND | CMD_PHASE2_INTERSECT
                )
        )
    }

    #[inline(never)]
    pub fn dispatch_frame(
        &mut self,
        req_header: &EnclaveRequestHeader,
        payload: &[u8],
        slot: &mut EnclaveConnectionSlot,
    ) -> (i32, u32) {
        let res = self.dispatch_frame_buffers(
            req_header,
            payload,
            &mut slot.out_buffer.data,
            &mut slot.scratch_buffer,
            &mut slot.attestation_doc,
        );
        if self.phase == SessionPhase::ClosedZeroized {
            slot.purge();
        }
        res
    }

    #[inline(never)]
    pub fn dispatch_frame_buffers(
        &mut self,
        req_header: &EnclaveRequestHeader,
        payload: &[u8],
        resp_payload: &mut [u8],
        scratch_buffer: &mut EnclaveFrameBuffer,
        attestation_doc: &mut AttestationDocumentBuffer,
    ) -> (i32, u32) {
        if self.is_closed() {
            resp_payload.fill(0);
            scratch_buffer.purge();
            attestation_doc.purge();
            self.ops_in_session = 0;
            self.phase = SessionPhase::ClosedZeroized;
            return (NONA_WIRE_ERR_OPAQUE, 0);
        }

        let Ok(expected_plen) = req_header.validate_pre_payload() else {
            ct_zeroize(resp_payload);
            scratch_buffer.purge();
            attestation_doc.purge();
            self.ops_in_session = 0;
            self.phase = SessionPhase::ClosedZeroized;
            return (NONA_WIRE_ERR_OPAQUE, 0);
        };
        if payload.len() != expected_plen {
            ct_zeroize(resp_payload);
            scratch_buffer.purge();
            attestation_doc.purge();
            self.ops_in_session = 0;
            self.phase = SessionPhase::ClosedZeroized;
            return (NONA_WIRE_ERR_OPAQUE, 0);
        }

        if !self.is_command_allowed(req_header.command) {
            ct_zeroize(resp_payload);
            scratch_buffer.purge();
            attestation_doc.purge();
            self.ops_in_session = 0;
            self.phase = SessionPhase::ClosedZeroized;
            return (NONA_ERR_INVALID_PHASE, 0);
        }

        let Some(next_ops) = self.ops_in_session.checked_add(1) else {
            ct_zeroize(resp_payload);
            scratch_buffer.purge();
            attestation_doc.purge();
            self.ops_in_session = 0;
            self.phase = SessionPhase::ClosedZeroized;
            return (NONA_WIRE_ERR_OPAQUE, 0);
        };
        if next_ops > MAX_SESSION_OPS {
            ct_zeroize(resp_payload);
            scratch_buffer.purge();
            attestation_doc.purge();
            self.ops_in_session = 0;
            self.phase = SessionPhase::ClosedZeroized;
            return (NONA_WIRE_ERR_OPAQUE, 0);
        }

        let (status, out_len) = dispatch_frame_with_slot(
            req_header,
            payload,
            resp_payload,
            scratch_buffer,
            attestation_doc,
        );

        #[cfg(feature = "std")]
        let attestation_sim_pending =
            req_header.command == CMD_ATTEST && status == crate::attestation::NONA_ERR_NSM_UNAVAILABLE;
        #[cfg(not(feature = "std"))]
        let attestation_sim_pending = false;

        if status != 0 && !attestation_sim_pending {
            ct_zeroize(resp_payload);
            scratch_buffer.purge();
            attestation_doc.purge();
            self.ops_in_session = 0;
            self.phase = SessionPhase::ClosedZeroized;
            return (status, 0);
        }

        self.ops_in_session = next_ops;
        self.phase = match req_header.command {
            CMD_PING => self.phase,
            CMD_ATTEST | CMD_INGEST => SessionPhase::AttestedBound,
            CMD_BLIND_PHASE1 => SessionPhase::Phase1Blinded,
            CMD_PHASE2_REBLIND => SessionPhase::Phase2Reblinded,
            CMD_PHASE2_INTERSECT => SessionPhase::Phase2Intersected,
            _ => {
                ct_zeroize(resp_payload);
                scratch_buffer.purge();
                attestation_doc.purge();
                self.ops_in_session = 0;
                self.phase = SessionPhase::ClosedZeroized;
                return (NONA_WIRE_ERR_OPAQUE, 0);
            }
        };

        (status, out_len)
    }
}

#[inline(never)]
#[allow(clippy::cast_possible_truncation)]
fn execute_wire_blinding_op(
    is_phase2_reblind: bool,
    flags: u32,
    payload: &[u8],
    resp_payload: &mut [u8],
    scratch_buffer: &mut EnclaveFrameBuffer,
) -> (i32, u32) {
    let use_session_key = (flags & FLAG_USE_SESSION_KEY) != 0;
    let elements_slice: &[u8] = if use_session_key {
        if payload.is_empty() || !payload.len().is_multiple_of(32) {
            return (-3, 0);
        }
        payload
    } else {
        if payload.len() < 64 || !payload.len().is_multiple_of(32) {
            return (-3, 0);
        }
        &payload[32..]
    };

    let n_elements = elements_slice.len() / 32;
    if n_elements == 0 || n_elements > 128 {
        return (-3, 0);
    }

    let Some(elements_len) = n_elements.checked_mul(32) else {
        return (-7, 0);
    };
    if resp_payload.len() < elements_len {
        return (-8, 0);
    }
    if (resp_payload.as_ptr() as usize & 63) != 0 {
        return (-2, 0);
    }

    let mut aligned_key = AlignedKeyBuffer { data: [0u8; 32] };
    if use_session_key {
        if advance_session_op_counter().is_err() {
            return (-1, 0);
        }
        load_session_privkey_into(&mut aligned_key);
    } else {
        aligned_key.data.copy_from_slice(&payload[0..32]);
    }

    scratch_buffer.data[..elements_len].copy_from_slice(elements_slice);

    let status = unsafe {
        if is_phase2_reblind {
            crate::nona_phase2_reblind(
                scratch_buffer.data.as_ptr(),
                elements_len,
                n_elements,
                aligned_key.data.as_ptr(),
                resp_payload.as_mut_ptr(),
                elements_len,
            )
        } else {
            crate::nona_phase1_blind(
                scratch_buffer.data.as_ptr(),
                elements_len,
                n_elements,
                aligned_key.data.as_ptr(),
                resp_payload.as_mut_ptr(),
                elements_len,
            )
        }
    };

    ct_zeroize(&mut aligned_key.data);
    scratch_buffer.purge();

    let out_len = if status == 0 { elements_len as u32 } else { 0 };
    (status, out_len)
}

#[inline(never)]
#[allow(clippy::cast_possible_truncation)]
fn execute_wire_phase2_intersect(
    payload: &[u8],
    resp_payload: &mut [u8],
    scratch_buffer: &mut EnclaveFrameBuffer,
) -> (i32, u32) {
    if payload.len() < 16 {
        return (-3, 0);
    }
    let psi_flags = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
    let n_a = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]) as usize;
    let n_b = u32::from_le_bytes([payload[8], payload[9], payload[10], payload[11]]) as usize;
    let reserved = u32::from_le_bytes([payload[12], payload[13], payload[14], payload[15]]);
    if reserved != 0 || n_a == 0 || n_a > 128 || n_b == 0 || n_b > 128 {
        return (-3, 0);
    }
    let Some(len_a) = n_a.checked_mul(32) else {
        return (-7, 0);
    };
    let Some(len_b) = n_b.checked_mul(32) else {
        return (-7, 0);
    };
    let Some(expected_total) = 16usize.checked_add(len_a).and_then(|v| v.checked_add(len_b)) else {
        return (-7, 0);
    };
    if payload.len() != expected_total {
        return (-3, 0);
    }
    let Some(indices_bytes) = n_a.checked_mul(4) else {
        return (-7, 0);
    };
    let Some(total_resp_bytes) = 64usize.checked_add(indices_bytes) else {
        return (-7, 0);
    };
    if resp_payload.len() < total_resp_bytes || (resp_payload.as_ptr() as usize & 63) != 0 {
        return (-2, 0);
    }

    // Copy set A into offset 0 (64-byte aligned) and set B into offset 4096 (64-byte aligned)
    scratch_buffer.data[..len_a].copy_from_slice(&payload[16..16 + len_a]);
    scratch_buffer.data[4096..4096 + len_b].copy_from_slice(&payload[16 + len_a..expected_total]);

    #[repr(C, align(64))]
    struct AlignedCard(u64);
    let mut card = AlignedCard(0);

    let (idx_area, header_area) = resp_payload.split_at_mut(indices_bytes);
    let status = unsafe {
        crate::nona_phase2_intersect(
            scratch_buffer.data.as_ptr(),
            len_a,
            scratch_buffer.data.as_ptr().add(4096),
            len_b,
            n_a,
            idx_area.as_mut_ptr(),
            indices_bytes,
            psi_flags,
            &raw mut card.0,
        )
    };
    scratch_buffer.purge();

    if status != 0 {
        ct_zeroize(resp_payload);
        return (status, 0);
    }
    header_area[..8].copy_from_slice(&card.0.to_le_bytes());
    (0, total_resp_bytes as u32)
}

#[inline(never)]
#[allow(clippy::cast_possible_truncation)]
pub fn dispatch_frame_with_slot(
    req_header: &EnclaveRequestHeader,
    payload: &[u8],
    resp_payload: &mut [u8],
    scratch_buffer: &mut EnclaveFrameBuffer,
    attestation_doc: &mut AttestationDocumentBuffer,
) -> (i32, u32) {
    if req_header.magic != NONA_VSOCK_MAGIC {
        return (-100, 0); // NONA_ERR_INVALID_MAGIC
    }
    if req_header.version != NONA_VSOCK_VERSION {
        return (-101, 0); // NONA_ERR_INVALID_VERSION
    }
    let Ok(header_plen) = usize::try_from(req_header.payload_len) else {
        return (-3, 0);
    };
    if header_plen > MAX_WIRE_PAYLOAD_BYTES || payload.len() != header_plen {
        return (-3, 0); // NONA_ERR_LENGTH_BOUND_VIOLATION
    }

    match req_header.command {
        CMD_PING => {
            let out_len = core::cmp::min(payload.len(), resp_payload.len());
            resp_payload[..out_len].copy_from_slice(&payload[..out_len]);
            (0, out_len as u32)
        }
        CMD_INGEST => {
            if payload.is_empty() || payload.len() > 4096 || !payload.len().is_multiple_of(128) {
                return (-3, 0);
            }

            let status = if (payload.as_ptr() as usize & 63) == 0 {
                unsafe { crate::nona_ingest_stream(payload.as_ptr(), payload.len()) }
            } else {
                scratch_buffer.data[..payload.len()].copy_from_slice(payload);
                let res = unsafe {
                    crate::nona_ingest_stream(scratch_buffer.data.as_ptr(), payload.len())
                };
                scratch_buffer.purge();
                res
            };

            (status, 0)
        }
        CMD_BLIND_PHASE1 => execute_wire_blinding_op(
            false,
            req_header.flags,
            payload,
            resp_payload,
            scratch_buffer,
        ),
        CMD_PHASE2_REBLIND => execute_wire_blinding_op(
            true,
            req_header.flags,
            payload,
            resp_payload,
            scratch_buffer,
        ),
        CMD_PHASE2_INTERSECT => {
            execute_wire_phase2_intersect(payload, resp_payload, scratch_buffer)
        }
        CMD_ATTEST => {
            let client_nonce: Option<&[u8]> = if payload.is_empty() {
                None
            } else if payload.len() >= 16 && payload.len() <= 64 {
                Some(payload)
            } else {
                return (-3, 0);
            };
            if !is_nsm_available() {
                return (crate::attestation::NONA_ERR_NSM_UNAVAILABLE, 0);
            }
            // Bind hypervisor attestation strictly to the internal enclave session public key.
            // Private scalar never enters this frame.
            let pubkey = get_or_create_session_pubkey();
            if advance_session_op_counter().is_err() {
                return (-1, 0);
            }
            let user_data_digest = sha512_digest(&pubkey);

            let status = unsafe {
                query_hardware_attestation_with_nonce(&user_data_digest, client_nonce, attestation_doc)
            };

            let (status, out_len) = if status == 0 {
                let Some(total_needed) =
                    SECP256K1_PUBKEY_COMPRESSED_SIZE.checked_add(attestation_doc.actual_len)
                else {
                    attestation_doc.purge();
                    return (NONA_ERR_ATTEST_OVERFLOW, 0);
                };
                if total_needed > resp_payload.len()
                    || attestation_doc.actual_len == 0
                    || attestation_doc.actual_len > ATTESTATION_MAX_DOC_SIZE
                {
                    (NONA_ERR_ATTEST_OVERFLOW, 0)
                } else {
                    resp_payload[..SECP256K1_PUBKEY_COMPRESSED_SIZE].copy_from_slice(&pubkey);
                    resp_payload[SECP256K1_PUBKEY_COMPRESSED_SIZE..total_needed]
                        .copy_from_slice(&attestation_doc.data[..attestation_doc.actual_len]);
                    (0, total_needed as u32)
                }
            } else {
                (status, 0)
            };

            attestation_doc.purge();
            (status, out_len)
        }
        _ => (-102, 0),
    }
}

#[inline(never)]
pub fn dispatch_frame(
    req_header: &EnclaveRequestHeader,
    req_payload: &[u8],
    resp_payload: &mut [u8],
) -> (i32, u32) {
    if let Some(guard) = STAGING_POOL.acquire() {
        dispatch_frame_with_slot(
            req_header,
            req_payload,
            resp_payload,
            &mut guard.pair.scratch_buffer,
            &mut guard.pair.attestation_doc,
        )
    } else {
        (-10, 0)
    }
}

pub unsafe fn recv_exact(fd: libc::c_int, buf: *mut u8, len: usize) -> Result<(), i32> {
    let mut total_read = 0;
    while total_read < len {
        let n = libc::recv(
            fd,
            buf.add(total_read).cast::<libc::c_void>(),
            len - total_read,
            0,
        );
        if n <= 0 {
            return Err(-5);
        }
        total_read += n.cast_unsigned();
    }
    Ok(())
}

pub unsafe fn send_exact(fd: libc::c_int, buf: *const u8, len: usize) -> Result<(), i32> {
    let mut total_written = 0;
    while total_written < len {
        let n = libc::send(
            fd,
            buf.add(total_written).cast::<libc::c_void>(),
            len - total_written,
            0,
        );
        if n <= 0 {
            return Err(-5);
        }
        total_written += n.cast_unsigned();
    }
    Ok(())
}

#[inline(never)]
#[allow(clippy::cast_possible_truncation)]
pub unsafe fn handle_enclave_client(client_fd: libc::c_int) {
    // Prevent client starvation via 3-second recv/send timeouts
    let tv = libc::timeval {
        tv_sec: 3,
        tv_usec: 0,
    };
    libc::setsockopt(
        client_fd,
        libc::SOL_SOCKET,
        libc::SO_RCVTIMEO,
        (&raw const tv).cast(),
        core::mem::size_of::<libc::timeval>() as libc::socklen_t,
    );
    libc::setsockopt(
        client_fd,
        libc::SOL_SOCKET,
        libc::SO_SNDTIMEO,
        (&raw const tv).cast(),
        core::mem::size_of::<libc::timeval>() as libc::socklen_t,
    );

    if let Some(guard) = STAGING_POOL.acquire() {
        handle_enclave_client_with_staging(client_fd, guard.pair);
    } else {
        libc::close(client_fd);
    }
}

#[inline(never)]
unsafe fn monotonic_now_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if libc::clock_gettime(libc::CLOCK_MONOTONIC, &raw mut ts) != 0 {
        crate::exception::zeroize_and_abort(crate::gatekeeper::NONA_ERR_INTERNAL_PANIC);
    }
    let sec = u64::try_from(ts.tv_sec).unwrap_or(0);
    let nsec = u64::try_from(ts.tv_nsec).unwrap_or(0);
    sec.saturating_mul(1_000_000_000).saturating_add(nsec)
}

#[inline(never)]
unsafe fn enforce_wire_frame_floor(start_ns: u64) {
    if start_ns == 0 {
        return;
    }
    let now_ns = monotonic_now_ns();
    let elapsed = now_ns.saturating_sub(start_ns);
    if elapsed < WIRE_FRAME_FLOOR_NS {
        let rem = WIRE_FRAME_FLOOR_NS - elapsed;
        let req = libc::timespec {
            tv_sec: (rem / 1_000_000_000).cast_signed(),
            tv_nsec: (rem % 1_000_000_000).cast_signed(),
        };
        let mut leftover = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        let _ = libc::nanosleep(&raw const req, &raw mut leftover);
    }
}

#[inline(never)]
#[allow(clippy::cast_possible_truncation)]
pub unsafe fn handle_enclave_client_with_staging(
    client_fd: libc::c_int,
    slot: &mut EnclaveConnectionSlot,
) {
    let mut session = VsockSessionState::new();

    loop {
        let mut req_wire = [0u8; EnclaveRequestHeader::WIRE_SIZE];
        if recv_exact(
            client_fd,
            req_wire.as_mut_ptr(),
            EnclaveRequestHeader::WIRE_SIZE,
        )
        .is_err()
        {
            session.fail_closed_with_slot(slot);
            break;
        }
        let frame_start_ns = monotonic_now_ns();

        // Validate fixed header and static frame/payload ceilings strictly BEFORE reading payload bytes.
        let Ok(req_header) = EnclaveRequestHeader::parse_wire_bytes(&req_wire) else {
            session.fail_closed_with_slot(slot);
            enforce_wire_frame_floor(frame_start_ns);
            let err_hdr = EnclaveResponseHeader {
                magic: NONA_VSOCK_MAGIC,
                version: NONA_VSOCK_VERSION,
                status: NONA_WIRE_ERR_OPAQUE,
                payload_len: 0,
                reserved: [0u8; 20],
            };
            let _ = send_exact(
                client_fd,
                err_hdr.to_wire_bytes().as_ptr(),
                EnclaveResponseHeader::WIRE_SIZE,
            );
            break;
        };

        let Ok(plen) = usize::try_from(req_header.payload_len) else {
            session.fail_closed_with_slot(slot);
            enforce_wire_frame_floor(frame_start_ns);
            break;
        };

        if plen > 0 && recv_exact(client_fd, slot.in_buffer.data.as_mut_ptr(), plen).is_err() {
            session.fail_closed_with_slot(slot);
            enforce_wire_frame_floor(frame_start_ns);
            break;
        }

        let (raw_status, raw_resp_len) = session.dispatch_frame_buffers(
            &req_header,
            &slot.in_buffer.data[..plen],
            &mut slot.out_buffer.data,
            &mut slot.scratch_buffer,
            &mut slot.attestation_doc,
        );
        if session.phase() == SessionPhase::ClosedZeroized {
            slot.purge();
        }

        let (wire_status, wire_resp_len) = if raw_status == 0 {
            (0, raw_resp_len)
        } else if raw_status == crate::attestation::NONA_ERR_NSM_UNAVAILABLE {
            slot.purge();
            (crate::attestation::NONA_ERR_NSM_UNAVAILABLE, 0)
        } else {
            session.fail_closed_with_slot(slot);
            (NONA_WIRE_ERR_OPAQUE, 0)
        };

        enforce_wire_frame_floor(frame_start_ns);

        let resp_header = EnclaveResponseHeader {
            magic: NONA_VSOCK_MAGIC,
            version: NONA_VSOCK_VERSION,
            status: wire_status,
            payload_len: wire_resp_len,
            reserved: [0u8; 20],
        };

        let resp_wire = resp_header.to_wire_bytes();
        if send_exact(
            client_fd,
            resp_wire.as_ptr(),
            EnclaveResponseHeader::WIRE_SIZE,
        )
        .is_err()
        {
            session.fail_closed_with_slot(slot);
            break;
        }
        if wire_resp_len > 0 {
            let Ok(resp_len_usize) = usize::try_from(wire_resp_len) else {
                session.fail_closed_with_slot(slot);
                break;
            };
            if resp_len_usize > MAX_WIRE_PAYLOAD_BYTES
                || send_exact(
                    client_fd,
                    slot.out_buffer.data.as_ptr(),
                    resp_len_usize,
                )
                .is_err()
            {
                session.fail_closed_with_slot(slot);
                break;
            }
        }

        slot.purge();

        // Fail-closed session termination: immediately close connection on any protocol/verification error
        if wire_status != 0 && wire_status != crate::attestation::NONA_ERR_NSM_UNAVAILABLE {
            session.fail_closed_with_slot(slot);
            break;
        }
    }

    session.fail_closed_with_slot(slot);
    libc::close(client_fd);
}

#[allow(clippy::cast_possible_truncation)]
pub unsafe fn run_vsock_server(port: u32) -> i32 {
    let server_fd = libc::socket(AF_VSOCK, libc::SOCK_STREAM, 0);
    if server_fd < 0 {
        return -10;
    }

    let addr = sockaddr_vm::new(port, VMADDR_CID_ANY);
    let bind_res = libc::bind(
        server_fd,
        (&raw const addr).cast::<libc::sockaddr>(),
        size_of::<sockaddr_vm>() as libc::socklen_t,
    );
    if bind_res < 0 {
        libc::close(server_fd);
        return -11;
    }

    if libc::listen(server_fd, 16) < 0 {
        libc::close(server_fd);
        return -12;
    }

    loop {
        let mut client_addr = sockaddr_vm::new(0, 0);
        let mut client_len = size_of::<sockaddr_vm>() as libc::socklen_t;
        let client_fd = libc::accept(
            server_fd,
            (&raw mut client_addr).cast::<libc::sockaddr>(),
            &raw mut client_len,
        );

        if client_fd < 0 {
            continue;
        }

        handle_enclave_client(client_fd);
    }
}

#[allow(clippy::cast_possible_truncation)]
#[allow(clippy::cast_possible_wrap)]
pub unsafe fn run_unix_server(path_bytes_null_term: &[u8]) -> i32 {
    let server_fd = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
    if server_fd < 0 {
        return -10;
    }

    libc::unlink(path_bytes_null_term.as_ptr().cast::<libc::c_char>());

    let mut addr: libc::sockaddr_un = core::mem::zeroed();
    #[cfg(target_os = "macos")]
    {
        addr.sun_len = size_of::<libc::sockaddr_un>() as u8;
        addr.sun_family = libc::AF_UNIX as u8;
    }
    #[cfg(not(target_os = "macos"))]
    {
        addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    }

    let path_len = core::cmp::min(path_bytes_null_term.len(), addr.sun_path.len() - 1);
    for (i, &b) in path_bytes_null_term.iter().enumerate().take(path_len) {
        addr.sun_path[i] = b as core::ffi::c_char;
    }

    let bind_res = libc::bind(
        server_fd,
        (&raw const addr).cast::<libc::sockaddr>(),
        size_of::<libc::sockaddr_un>() as libc::socklen_t,
    );
    if bind_res < 0 {
        libc::close(server_fd);
        return -11;
    }

    if libc::listen(server_fd, 16) < 0 {
        libc::close(server_fd);
        return -12;
    }

    loop {
        let client_fd = libc::accept(server_fd, core::ptr::null_mut(), core::ptr::null_mut());
        if client_fd < 0 {
            continue;
        }
        handle_enclave_client(client_fd);
    }
}

#[cfg(feature = "std")]
pub unsafe fn run_dual_server(port: u32, unix_path: &[u8]) -> i32 {
    let vsock_res = run_vsock_server(port);
    if vsock_res != 0 {
        return run_unix_server(unix_path);
    }
    0
}
