#[cfg(verus)]
use vstd::prelude::*;

#[cfg(verus)]
verus! {

/// Satisfies [FR-28-ARENAALLOC]
/// Satisfies [FR-12-FORMALSPEC]
/// Specification predicate verifying 64-byte alignment.
pub open spec fn is_aligned_64(addr: int) -> bool {
    addr % 64 == 0
}

/// Satisfies [FR-28-ARENAALLOC]
/// Satisfies [FR-12-FORMALSPEC]
/// Verus specification state structure for bump allocator bounds.
pub struct ArenaState {
    pub base: usize,
    pub capacity: usize,
    pub cursor: usize,
}

impl ArenaState {
    pub open spec fn wf(&self) -> bool {
        &&& self.cursor as int >= self.base as int
        &&& self.cursor as int <= self.base as int + self.capacity as int
        &&& self.base as int + self.capacity as int <= usize::MAX as int
        &&& is_aligned_64(self.base as int)
        &&& self.capacity as int <= usize::MAX as int
    }
}

/// Satisfies [FR-28-ARENAALLOC]
/// Satisfies [FR-12-FORMALSPEC]
/// Formally verified bump allocation routine asserting cursor advancement bounds.
pub fn bump_allocate(arena: &mut ArenaState, size: usize) -> (res: Result<usize, ()>)
    requires
        old(arena).wf(),
        size as int <= usize::MAX as int,
    ensures
        final(arena).wf(),
        match res {
            Ok(allocated_addr) => {
                &&& allocated_addr as int == old(arena).cursor as int
                &&& final(arena).cursor as int == old(arena).cursor as int + (size as int)
                &&& final(arena).cursor as int <= final(arena).base as int + final(arena).capacity as int
            },
            Err(_) => {
                &&& final(arena).cursor == old(arena).cursor
                &&& old(arena).cursor as int + (size as int) > old(arena).base as int + old(arena).capacity as int
            }
        },
{
    let rem = arena.capacity - (arena.cursor - arena.base);
    if size <= rem {
        let old_cursor = arena.cursor;
        arena.cursor = arena.cursor + size;
        Ok(old_cursor)
    } else {
        Err(())
    }
}

} // verus!

#[cfg(not(verus))]
pub mod exec {
    // Atomic fences encapsulated inside crate::crypto::ct_zeroize

    pub const NONA_ALIGN_BYTES: usize = 64;
    pub use crate::gatekeeper::{NONA_ERR_OUT_OF_MEMORY, NONA_ERR_UNALIGNED_POINTER};

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum AllocError {
        OutOfMemory,
        InvalidAlignment,
    }

    /// Satisfies [FR-28-ARENAALLOC]
    /// Satisfies [FR-12-FORMALSPEC]
    /// State structure mirroring Verus specification for bump allocator bounds.
    #[repr(C)]
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct ArenaState {
        pub base: usize,
        pub capacity: usize,
        pub cursor: usize,
    }

    impl ArenaState {
        #[inline(always)]
        pub fn wf(&self) -> bool {
            self.cursor >= self.base
                && self.cursor <= self.base.saturating_add(self.capacity)
                && self.base.checked_add(self.capacity).is_some()
                && self.base.is_multiple_of(NONA_ALIGN_BYTES)
        }
    }

    /// Satisfies [FR-28-ARENAALLOC]
    /// Satisfies [FR-12-FORMALSPEC]
    /// Runtime realization of the formally verified bump allocation primitive.
    #[inline(always)]
    #[allow(clippy::result_unit_err)]
    pub fn bump_allocate(arena: &mut ArenaState, size: usize) -> Result<usize, ()> {
        let used = arena.cursor.checked_sub(arena.base).ok_or(())?;
        let rem = arena.capacity.checked_sub(used).ok_or(())?;
        if size <= rem {
            let old_cursor = arena.cursor;
            arena.cursor = arena.cursor.checked_add(size).ok_or(())?;
            Ok(old_cursor)
        } else {
            Err(())
        }
    }

    /// Satisfies [FR-28-ARENAALLOC]
    /// Satisfies [FR-15-NOSTD]
    /// 64-byte aligned static arena bump allocator operating in pure #![no_std].
    #[repr(C, align(64))]
    pub struct StaticArena<const CAPACITY: usize> {
        pub storage: core::cell::UnsafeCell<[u8; CAPACITY]>,
        pub cursor: usize,
        pub state: ArenaState,
    }

    impl<const CAPACITY: usize> Default for StaticArena<CAPACITY> {
        fn default() -> Self {
            Self::new()
        }
    }

    impl<const CAPACITY: usize> StaticArena<CAPACITY> {
        pub const fn new() -> Self {
            Self {
                storage: core::cell::UnsafeCell::new([0u8; CAPACITY]),
                cursor: 0,
                state: ArenaState {
                    base: 0,
                    capacity: CAPACITY,
                    cursor: 0,
                },
            }
        }

        /// Satisfies [FR-28-ARENAALLOC]
        /// Allocates 64-byte aligned memory from static arena storage.
        #[allow(clippy::needless_lifetimes)]
        pub fn allocate<'a>(
            &'a mut self,
            size: usize,
            align: usize,
        ) -> Result<&'a mut [u8], AllocError> {
            if align == 0 || !align.is_power_of_two() {
                return Err(AllocError::InvalidAlignment);
            }

            let padding = (align.wrapping_sub(self.state.cursor % align)) % align;
            let effective_size = padding.checked_add(size).ok_or(AllocError::OutOfMemory)?;

            match bump_allocate(&mut self.state, effective_size) {
                Ok(old_cursor) => {
                    let aligned_cursor = old_cursor.wrapping_add(padding);
                    self.cursor = self.state.cursor;
                    let ptr = unsafe { self.storage.get().cast::<u8>().add(aligned_cursor) };
                    let slice = unsafe { core::slice::from_raw_parts_mut(ptr, size) };
                    Ok(slice)
                }
                Err(_) => Err(AllocError::OutOfMemory),
            }
        }

        /// Satisfies [FR-28-ARENAALLOC]
        /// Satisfies [FR-05-RAMCLR]
        /// Zeroizes allocated memory and resets bump cursor.
        pub fn reset(&mut self) {
            unsafe {
                let slice = core::slice::from_raw_parts_mut(
                    self.storage.get().cast::<u8>(),
                    self.state.cursor,
                );
                crate::crypto::ct_zeroize(slice);
            }
            self.cursor = 0;
            self.state.cursor = 0;
        }
    }

    impl<const CAPACITY: usize> Drop for StaticArena<CAPACITY> {
        fn drop(&mut self) {
            self.reset();
        }
    }
}

#[cfg(not(verus))]
pub use exec::*;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::exec::*;

    #[test]
    fn test_static_arena_alignment_and_oom_boundary() {
        let mut arena: StaticArena<256> = StaticArena::new();
        let p1 = arena.allocate(64, 64).expect("Allocation 1 failed");
        assert_eq!(
            p1.as_ptr() as usize % 64,
            0,
            "Allocation must be 64-byte aligned"
        );
        let p2 = arena.allocate(128, 64).expect("Allocation 2 failed");
        assert_eq!(
            p2.as_ptr() as usize % 64,
            0,
            "Allocation must be 64-byte aligned"
        );
        let p3 = arena.allocate(128, 64);
        assert_eq!(p3.unwrap_err(), AllocError::OutOfMemory);
    }

    #[test]
    fn test_bump_allocate_model_parity() {
        let mut state = ArenaState {
            base: 0,
            capacity: 256,
            cursor: 0,
        };
        assert!(state.wf());
        let off1 = bump_allocate(&mut state, 64).expect("Model alloc 1 failed");
        assert_eq!(off1, 0);
        assert_eq!(state.cursor, 64);
        assert!(bump_allocate(&mut state, 200).is_err());
        assert_eq!(state.cursor, 64);
    }
}
