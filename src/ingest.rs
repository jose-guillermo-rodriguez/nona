//! Synchronized Stream Ingestion Perimeter and Static Ring Buffer Interface.

pub use crate::ring_buffer::{RingBuffer, ZeroCopyRingBuffer, CAPACITY, CHUNK_SIZE};

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum IngestError {
    NullPointer = -1,
    InvalidAlignment = -3,
    CapacityExceeded = -4,
    LockBusy = -5,
}
use core::sync::atomic::{AtomicBool, Ordering};

/// Satisfies [FR-17-STRMIN]
/// Satisfies [FR-10-RINGMAN]
/// Global static zero-copy ring buffer for stream ingestion.
static mut INGEST_RING_BUFFER: ZeroCopyRingBuffer = ZeroCopyRingBuffer::INIT;
static INGEST_LOCK: AtomicBool = AtomicBool::new(false);
const MAX_SPIN_CYCLES: usize = 65_536;

#[inline(always)]
fn acquire_ingest_lock() -> bool {
    let mut backoff = 1usize;
    let mut spins = 0usize;
    while spins < MAX_SPIN_CYCLES {
        if INGEST_LOCK
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            return true;
        }
        while INGEST_LOCK.load(Ordering::Relaxed) {
            for _ in 0..backoff {
                core::hint::spin_loop();
            }
            if backoff < 64 {
                backoff = backoff.saturating_mul(2);
            } else {
                #[cfg(feature = "std")]
                std::thread::yield_now();
                #[cfg(not(feature = "std"))]
                for _ in 0..128 {
                    core::hint::spin_loop();
                }
            }
            spins += 1;
            if spins >= MAX_SPIN_CYCLES {
                return false;
            }
        }
        spins += 1;
    }
    false
}

/// Satisfies [FR-17-STRMIN]
/// Satisfies [FR-10-RINGMAN]
/// Process stream chunks and push them directly into static ring buffer under spinlock guard.
/// Enforces non-null pointer validation, boundary safety, and thread-safe re-entrancy protection.
pub unsafe fn process_ingest_stream_impl(stream_ptr: *const u8, len: usize) -> i32 {
    if stream_ptr.is_null() || len == 0 {
        return -1;
    }

    // Invariant: Enforce 128-byte framing alignment BEFORE acquiring lock to prevent poisoning
    if !len.is_multiple_of(128) {
        return -3;
    }

    // Acquire atomic spinlock guard with bounded backoff
    if !acquire_ingest_lock() {
        return -4;
    }

    let chunks = len / 128;
    let ring = &mut *core::ptr::addr_of_mut!(INGEST_RING_BUFFER);

    // Pre-flight capacity invariant: abort immediately if remaining capacity is insufficient
    let available = ring.available_capacity();
    if chunks > available {
        INGEST_LOCK.store(false, Ordering::Release);
        return -4;
    }

    let mut status = 0;
    for i in 0..chunks {
        let chunk_ptr = stream_ptr.add(i * 128);
        let chunk_ref = &*chunk_ptr.cast::<[u8; 128]>();
        if ring.try_push(chunk_ref).is_err() {
            status = -4;
            break;
        }
    }

    // Release atomic spinlock guard
    INGEST_LOCK.store(false, Ordering::Release);

    status
}

pub fn process_ingest_stream(data: &[u8]) -> Result<usize, IngestError> {
    if data.is_empty() {
        return Ok(0);
    }
    if !data.len().is_multiple_of(128) {
        return Err(IngestError::InvalidAlignment);
    }
    let res = unsafe { process_ingest_stream_impl(data.as_ptr(), data.len()) };
    match res {
        0 => Ok(data.len()),
        -1 => Err(IngestError::NullPointer),
        -3 => Err(IngestError::InvalidAlignment),
        -4 => Err(IngestError::CapacityExceeded),
        _ => Err(IngestError::LockBusy),
    }
}

#[allow(dead_code)]
/// Satisfies [FR-10-RINGMAN]
/// Thread-safe synchronized pop for ring buffer egress under spinlock guard.
pub(crate) unsafe fn pop_ingest_stream_impl(dest: &mut [u8; 128]) -> Result<(), &'static str> {
    ingest_pop(dest)
}

/// Satisfies [FR-10-RINGMAN]
/// Safe interface: pushes a 128-byte chunk into the static ring buffer under INGEST_LOCK guard.
pub fn ingest_push(chunk: &[u8; 128]) -> Result<(), &'static str> {
    if !acquire_ingest_lock() {
        return Err("Ingest lock busy");
    }
    let res = unsafe { (*core::ptr::addr_of_mut!(INGEST_RING_BUFFER)).try_push(chunk) };
    INGEST_LOCK.store(false, Ordering::Release);
    res
}

/// Satisfies [FR-10-RINGMAN]
/// Safe interface: pops a 128-byte chunk from the static ring buffer under INGEST_LOCK guard.
pub fn ingest_pop(dest: &mut [u8; 128]) -> Result<(), &'static str> {
    if !acquire_ingest_lock() {
        return Err("Ingest lock busy");
    }
    let res = unsafe { (*core::ptr::addr_of_mut!(INGEST_RING_BUFFER)).try_pop(dest) };
    INGEST_LOCK.store(false, Ordering::Release);
    res
}

/// Satisfies [FR-10-RINGMAN]
/// Safe closure wrapper: executes a closure with exclusive mutable access under INGEST_LOCK guard.
pub fn with_ingest_ring_buffer<R, F>(f: F) -> Result<R, &'static str>
where
    F: FnOnce(&mut ZeroCopyRingBuffer) -> R,
{
    if !acquire_ingest_lock() {
        return Err("Ingest lock busy");
    }
    let res = unsafe { f(&mut *core::ptr::addr_of_mut!(INGEST_RING_BUFFER)) };
    INGEST_LOCK.store(false, Ordering::Release);
    Ok(res)
}
