use std::sync::Mutex;

static TEST_MUTEX: Mutex<()> = Mutex::new(());
use nona_core::ingest::{
    ingest_pop, process_ingest_stream, process_ingest_stream_impl, with_ingest_ring_buffer,
    IngestError, CAPACITY, CHUNK_SIZE,
};

#[test]
fn test_transactional_ingest_all_or_nothing() {
    let _guard = TEST_MUTEX.lock().unwrap();
    let mut drain_slot = [0u8; CHUNK_SIZE];
    while ingest_pop(&mut drain_slot).is_ok() {}

    let slots_to_fill = CAPACITY - 2;
    let single_chunk = [0xAAu8; CHUNK_SIZE];
    for _ in 0..slots_to_fill {
        let res = unsafe { process_ingest_stream_impl(single_chunk.as_ptr(), CHUNK_SIZE) };
        assert_eq!(res, 0, "Pre-filling ring buffer failed");
    }

    let (pre_mask, pre_write_idx, available) = with_ingest_ring_buffer(|ring| {
        (
            ring.occupied_mask,
            ring.write_index,
            ring.available_capacity(),
        )
    })
    .expect("Failed to lock ring buffer");

    assert_eq!(available, 2);

    let oversized_payload = vec![0xBBu8; 3 * CHUNK_SIZE];
    let result = process_ingest_stream(&oversized_payload);

    assert_eq!(
        result,
        Err(IngestError::CapacityExceeded),
        "Multi-chunk ingest must reject stream when total chunks exceed capacity"
    );

    let raw_result =
        unsafe { process_ingest_stream_impl(oversized_payload.as_ptr(), oversized_payload.len()) };
    assert_eq!(raw_result, -4);

    let (post_mask, post_write_idx, post_available) = with_ingest_ring_buffer(|ring| {
        (
            ring.occupied_mask,
            ring.write_index,
            ring.available_capacity(),
        )
    })
    .expect("Failed to lock ring buffer");

    assert_eq!(
        post_mask, pre_mask,
        "Bitmask mutated on partial batch write! Expected: {pre_mask:#034x}, Actual: {post_mask:#034x}"
    );

    assert_eq!(
        post_write_idx, pre_write_idx,
        "write_index mutated on partial batch write! Expected: {pre_write_idx}, Actual: {post_write_idx}"
    );

    assert_eq!(post_available, 2);

    while ingest_pop(&mut drain_slot).is_ok() {}
}

#[test]
fn test_transactional_ingest_exact_capacity_boundary() {
    let _guard = TEST_MUTEX.lock().unwrap();
    let mut drain_slot = [0u8; CHUNK_SIZE];
    while ingest_pop(&mut drain_slot).is_ok() {}

    let full_batch = vec![0x77u8; CAPACITY * CHUNK_SIZE];
    let res = process_ingest_stream(&full_batch);
    assert_eq!(res, Ok(CAPACITY * CHUNK_SIZE));

    let (full_mask, full_write_idx, full_avail) = with_ingest_ring_buffer(|ring| {
        (
            ring.occupied_mask,
            ring.write_index,
            ring.available_capacity(),
        )
    })
    .expect("Lock error");

    assert_eq!(full_avail, 0);

    let overflow_chunk = [0xFFu8; CHUNK_SIZE];
    let overflow_res = process_ingest_stream(&overflow_chunk);
    assert_eq!(overflow_res, Err(IngestError::CapacityExceeded));

    let (after_mask, after_write_idx, after_avail) = with_ingest_ring_buffer(|ring| {
        (
            ring.occupied_mask,
            ring.write_index,
            ring.available_capacity(),
        )
    })
    .expect("Lock error");

    assert_eq!(after_mask, full_mask);
    assert_eq!(after_write_idx, full_write_idx);
    assert_eq!(after_avail, 0);

    while ingest_pop(&mut drain_slot).is_ok() {}
}
