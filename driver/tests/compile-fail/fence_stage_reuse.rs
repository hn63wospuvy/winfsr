use fsring_core::session::SessionFence;

pub fn fence_stage_reuse(fence: SessionFence) {
    let _first = fence.advance();
    let _second = fence.advance();
}
