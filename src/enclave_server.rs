//! Bare-metal confidential server listener for AWS Nitro Enclaves and local Unix domain socket.
//! Operates with zero dynamic allocations (#![no_std]) using cache-aligned stack buffers.

use crate::attestation::{
    derive_compressed_public_key, fill_nsm_entropy_or_abort, is_nsm_available, query_hardware_attestation,
    AttestationDocumentBuffer, ATTESTATION_MAX_DOC_SIZE, NONA_ERR_ATTEST_OVERFLOW,
    SECP256K1_PUBKEY_COMPRESSED_SIZE,
};
use crate::crypto::{ct_zeroize, sha512_digest};
use core::mem::size_of;
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

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

pub const FLAG_USE_SESSION_KEY: u32 = 0x0001;
pub const MAX_PAYLOAD_SIZE: usize = 16384;

const SESSION_STATE_UNINIT: u8 = 0;
const SESSION_STATE_INITIALIZING: u8 = 1;
const SESSION_STATE_READY: u8 = 2;

struct EnclaveSessionKey {
    state: AtomicU8,
    privkey: core::cell::UnsafeCell<[u8; 32]>,
    pubkey: core::cell::UnsafeCell<[u8; SECP256K1_PUBKEY_COMPRESSED_SIZE]>,
}

unsafe impl Sync for EnclaveSessionKey {}

static SESSION_KEY: EnclaveSessionKey = EnclaveSessionKey {
    state: AtomicU8::new(SESSION_STATE_UNINIT),
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
#[cfg(any(test, feature = "std"))]
pub fn reset_session_key() {
    unsafe {
        ct_zeroize(&mut *SESSION_KEY.privkey.get());
        ct_zeroize(&mut *SESSION_KEY.pubkey.get());
    }
    SESSION_KEY
        .state
        .store(SESSION_STATE_UNINIT, Ordering::Release);
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
    if payload.len() < req_header.payload_len as usize {
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
        CMD_BLIND_PHASE1 => {
            let use_session_key = (req_header.flags & FLAG_USE_SESSION_KEY) != 0;
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

            let elements_len = n_elements * 32;
            if resp_payload.len() < elements_len {
                return (-8, 0);
            }

            if (resp_payload.as_ptr() as usize & 63) != 0 {
                return (-2, 0);
            }

            let mut aligned_key = AlignedKeyBuffer { data: [0u8; 32] };
            if use_session_key {
                load_session_privkey_into(&mut aligned_key);
            } else {
                aligned_key.data.copy_from_slice(&payload[0..32]);
            }

            scratch_buffer.data[..elements_len].copy_from_slice(elements_slice);

            let status = unsafe {
                crate::nona_phase1_blind(
                    scratch_buffer.data.as_ptr(),
                    elements_len,
                    n_elements,
                    aligned_key.data.as_ptr(),
                    resp_payload.as_mut_ptr(),
                    elements_len,
                )
            };

            ct_zeroize(&mut aligned_key.data);
            scratch_buffer.purge();

            let out_len = if status == 0 { elements_len as u32 } else { 0 };

            (status, out_len)
        }
        CMD_ATTEST => {
            if !is_nsm_available() {
                return (crate::attestation::NONA_ERR_NSM_UNAVAILABLE, 0);
            }
            // Bind hypervisor attestation strictly to the internal enclave session public key.
            // Private scalar never enters this frame.
            let pubkey = get_or_create_session_pubkey();
            let user_data_digest = sha512_digest(&pubkey);

            let status = unsafe { query_hardware_attestation(&user_data_digest, attestation_doc) };

            let (status, out_len) = if status == 0 {
                let total_needed = SECP256K1_PUBKEY_COMPRESSED_SIZE + attestation_doc.actual_len;
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
#[allow(clippy::cast_possible_truncation)]
pub unsafe fn handle_enclave_client_with_staging(
    client_fd: libc::c_int,
    slot: &mut EnclaveConnectionSlot,
) {
    loop {
        let mut req_wire = [0u8; EnclaveRequestHeader::WIRE_SIZE];
        if recv_exact(
            client_fd,
            req_wire.as_mut_ptr(),
            EnclaveRequestHeader::WIRE_SIZE,
        )
        .is_err()
        {
            break;
        }
        let req_header = EnclaveRequestHeader::from_wire_bytes(&req_wire);

        let plen = req_header.payload_len as usize;
        if plen > MAX_PAYLOAD_SIZE {
            break;
        }

        if plen > 0 && recv_exact(client_fd, slot.in_buffer.data.as_mut_ptr(), plen).is_err() {
            break;
        }

        let (status, resp_len) = dispatch_frame_with_slot(
            &req_header,
            &slot.in_buffer.data[..plen],
            &mut slot.out_buffer.data,
            &mut slot.scratch_buffer,
            &mut slot.attestation_doc,
        );

        let resp_header = EnclaveResponseHeader {
            magic: NONA_VSOCK_MAGIC,
            version: NONA_VSOCK_VERSION,
            status,
            payload_len: resp_len,
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
            break;
        }
        if resp_len > 0
            && send_exact(client_fd, slot.out_buffer.data.as_ptr(), resp_len as usize).is_err()
        {
            break;
        }

        slot.purge();
    }

    slot.purge();
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
