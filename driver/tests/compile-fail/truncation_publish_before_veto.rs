// The veto is the ONLY entry into the sequence: Truncation<VetoCleared> cannot
// be constructed except by mm_veto returning Ok, so a reduction cannot publish
// sizes without having cleared MmCanFileBeTruncated first.
use fsring_core::size::*;

pub fn publish_without_the_veto(publication: CcPublication) {
    // There is no constructor: the fields are private and mm_veto is the only
    // path in.
    let forged = Truncation::<VetoCleared> {
        trio: SizeTrio::new(1000, 300, 200),
        step: core::marker::PhantomData,
    };
    let _ = forged.publish_sizes(publication);
}
