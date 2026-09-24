use fsring_core::session::{DeleteSessionRight, PreparedDeleteCoreCommit};

pub fn delete_twice(consume: fn(DeleteSessionRight), right: DeleteSessionRight) {
    consume(right);
    consume(right);
}

pub fn finish_prepared_twice(
    consume: fn(PreparedDeleteCoreCommit),
    prepared: PreparedDeleteCoreCommit,
) {
    consume(prepared);
    consume(prepared);
}
