use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use nona_core::ingest::{ingest_pop, process_ingest_stream_impl, CHUNK_SIZE};

#[test]
fn test_concurrency_16_threads_saturation() {
    const NUM_WORKERS: usize = 16;
    const CHUNKS_PER_WORKER: usize = 100;
    const TOTAL_CHUNKS: usize = NUM_WORKERS * CHUNKS_PER_WORKER;

    let produced_count = Arc::new(AtomicUsize::new(0));
    let workers_done = Arc::new(AtomicBool::new(false));

    let mut handles = Vec::with_capacity(NUM_WORKERS);
    for worker_id in 0..NUM_WORKERS {
        let produced_clone = Arc::clone(&produced_count);

        let handle = thread::spawn(move || {
            let mut chunk = [0u8; CHUNK_SIZE];
            chunk[0] = u8::try_from(worker_id).unwrap_or(0);

            for seq in 0..CHUNKS_PER_WORKER {
                chunk[1] = u8::try_from(seq & 0xFF).unwrap_or(0);
                chunk[2] = u8::try_from((seq >> 8) & 0xFF).unwrap_or(0);

                loop {
                    let res = unsafe { process_ingest_stream_impl(chunk.as_ptr(), CHUNK_SIZE) };
                    if res == 0 {
                        produced_clone.fetch_add(1, Ordering::Relaxed);
                        break;
                    } else if res == -4 {
                        thread::yield_now();
                    } else {
                        panic!("Worker {worker_id} encountered unexpected error: {res}");
                    }
                }
            }
        });
        handles.push(handle);
    }

    let start_time = Instant::now();
    let timeout = Duration::from_secs(30);

    let consumer_handle = thread::spawn(move || {
        let mut out_slot = [0u8; CHUNK_SIZE];
        let mut local_consumed = 0usize;

        while local_consumed < TOTAL_CHUNKS {
            assert!(
                start_time.elapsed() <= timeout,
                "Deadlock or livelock detected: timeout exceeded"
            );

            match ingest_pop(&mut out_slot) {
                Ok(_) => {
                    local_consumed += 1;
                }
                Err(_) => {
                    thread::yield_now();
                }
            }
        }
        local_consumed
    });

    for handle in handles {
        handle.join().expect("Worker thread panicked");
    }
    workers_done.store(true, Ordering::Release);

    let total_consumed = consumer_handle.join().expect("Consumer thread panicked");
    let total_produced = produced_count.load(Ordering::Acquire);

    assert_eq!(total_produced, TOTAL_CHUNKS);
    assert_eq!(total_consumed, total_produced);
}
