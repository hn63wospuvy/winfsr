use core::mem::size_of;

/// Plain-old-data types that can be copied to and from their native byte
/// representation.
///
/// # Safety
///
/// Implementing this trait promises all of the following:
///
/// - Every sequence of `size_of::<Self>()` bytes is a valid `Self`, because
///   [`try_decode`] accepts arbitrary input bytes and constructs `Self` with an
///   unaligned read.
/// - Every byte in the object representation of every `Self` value is
///   initialized. In particular, the type has no padding that can be
///   uninitialized when [`try_encode`] copies the full representation.
/// - The representation is stable and agreed upon by all byte producers and
///   consumers, including size, field layout, and native endianness. ABI
///   structs should use an explicit representation such as `#[repr(C)]` or
///   `#[repr(transparent)]`.
///
/// Types with references, invalid bit patterns or discriminants, or
/// potentially uninitialized padding must not implement `Pod`.
pub unsafe trait Pod: Copy {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BufferTooSmall {
    pub needed: usize,
    pub actual: usize,
}

pub fn try_encode<T: Pod>(value: &T, out: &mut [u8]) -> Result<usize, BufferTooSmall> {
    let needed = size_of::<T>();
    if out.len() < needed {
        return Err(BufferTooSmall {
            needed,
            actual: out.len(),
        });
    }
    unsafe {
        core::ptr::copy_nonoverlapping(value as *const T as *const u8, out.as_mut_ptr(), needed);
    }
    out[needed..].fill(0);
    Ok(needed)
}

pub fn try_decode<T: Pod>(input: &[u8]) -> Result<T, BufferTooSmall> {
    let needed = size_of::<T>();
    if input.len() < needed {
        return Err(BufferTooSmall {
            needed,
            actual: input.len(),
        });
    }
    Ok(unsafe { core::ptr::read_unaligned(input.as_ptr().cast::<T>()) })
}
