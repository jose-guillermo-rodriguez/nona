//! TEST-10: StaticArena Miri & Pointer Provenance Test Harness
//! Validates lifetime bounds, alignment guarantees, and borrow exclusivity.

use nona_core::allocator::{AllocError, StaticArena};

#[test]
fn test_arena_allocate_write_success() {
    let mut arena = StaticArena::<1024>::new();
    let slice = arena.allocate(128, 8).expect("allocation must succeed");
    assert_eq!(slice.len(), 128);
    assert_eq!((slice.as_ptr() as usize) % 8, 0);

    for (i, byte) in slice.iter_mut().enumerate() {
        *byte = u8::try_from(i % 256).unwrap_or(0);
    }

    assert_eq!(slice[0], 0);
    assert_eq!(slice[127], 127);
}

#[test]
fn test_arena_sequential_allocate_reset_cycle() {
    let mut arena = StaticArena::<256>::new();

    {
        let slice1 = arena.allocate(64, 16).expect("allocation 1 failed");
        slice1.fill(0xAA);
        assert_eq!(slice1[0], 0xAA);
        assert_eq!((slice1.as_ptr() as usize) % 16, 0);
    } // slice1 borrow ends here

    arena.reset();

    {
        let slice2 = arena.allocate(128, 32).expect("allocation 2 failed");
        slice2.fill(0xBB);
        assert_eq!(slice2[0], 0xBB);
        assert_eq!((slice2.as_ptr() as usize) % 32, 0);
    } // slice2 borrow ends here
}

#[test]
fn test_arena_alignment_padding_provenance() {
    let mut arena = StaticArena::<512>::new();

    let _first = arena.allocate(3, 1).expect("unaligned 3-byte alloc");
    let second = arena.allocate(16, 8).expect("8-byte aligned alloc");

    assert_eq!((second.as_ptr() as usize) % 8, 0);
    second.fill(0x7E);
    assert_eq!(second[15], 0x7E);
}

#[test]
fn test_arena_invalid_alignment() {
    let mut arena = StaticArena::<256>::new();
    assert_eq!(arena.allocate(32, 0), Err(AllocError::InvalidAlignment));
    assert_eq!(arena.allocate(32, 3), Err(AllocError::InvalidAlignment));
    assert_eq!(arena.allocate(32, 7), Err(AllocError::InvalidAlignment));
}

#[test]
fn test_arena_out_of_memory_bounds() {
    let mut arena = StaticArena::<64>::new();
    let _s = arena.allocate(60, 4).expect("fits within capacity");
    assert_eq!(arena.allocate(8, 4), Err(AllocError::OutOfMemory));
}

#[test]
fn test_arena_borrow_mutual_exclusion_invariant() {
    let mut arena = StaticArena::<128>::new();
    {
        let slice_a = arena.allocate(32, 8).expect("allocation a");
        slice_a[0] = 42;
        // slice_a lifetime ends at the close of this block
    }

    arena.reset();
    let slice_b = arena.allocate(32, 8).expect("allocation b");
    assert_eq!(slice_b[0], 0);
}
