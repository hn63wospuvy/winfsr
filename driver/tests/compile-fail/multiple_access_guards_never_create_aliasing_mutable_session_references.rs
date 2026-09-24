use core::ptr::NonNull;
use fsring_core::adapter::lifecycle::SharedSessionProjection;

pub fn mutate_through_one_of_two_guards(value: &mut u32) {
    let pointer = NonNull::from(&mut *value);
    // SAFETY: the fixture keeps the pointee alive. Its attempted mutable
    // projection below is the operation the API must reject.
    let mut first = unsafe { SharedSessionProjection::from_non_null(pointer) };
    // SAFETY: a second live access guard may resolve the same generation.
    let _second = unsafe { SharedSessionProjection::from_non_null(pointer) };
    let _raw_escape = unsafe { first.as_ptr() };
    *first.get_mut() = 99;
}
