// 07-cache-mm.md section 3: "Reserve/commit the new EOF with the daemon first,
// update the FCB header and call CcSetFileSizes, then run CcCopyWrite into the
// newly visible range." Permitting the copy before publication must not
// compile -- publishing is what stops Cc rejecting a write past the old EOF.
use fsring_core::size::*;

pub fn copy_before_publish(e: Extension<ProviderCommitted>) {
    let _ = e.permit_copy_write();
}
