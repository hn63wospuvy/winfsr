// 07-cache-mm.md section 5 step 5: the VDL clamp happens "After the completion
// queue entry confirms the commit". Clamping from step 3 must not compile.
use fsring_core::size::*;

pub fn clamp_early(t: Truncation<TailPurged>) {
    let _ = t.clamp_vdl();
}
