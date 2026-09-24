// C2 / 09-security.md section 1: a refusal happens "with no mapping or side
// effect, even before the first IOCTL executes".
//
// Authorization::Refused is a FIELDLESS variant, so a refusal that carried a
// mapping is not a value that can be constructed. The property is held by the
// type rather than by a test somebody has to remember to write.
use fsring_core::controldev::{Authorization, RequestorId};

pub fn refuse_with_a_mapping() -> Authorization {
    Authorization::Refused(RequestorId(1))
}
