use fsring_core::grant::ClaimedNotification;

pub fn head_advance_requires_unsafe(claim: ClaimedNotification<'_>) {
    let _proof = claim.after_release_head_advance();
}
