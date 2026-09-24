use fsring_abi::codec::{try_decode, try_encode, BufferTooSmall, Pod};

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Pair {
    first: u32,
    second: u32,
}

unsafe impl Pod for Pair {}

#[test]
fn codec_rejects_short_input_and_output() {
    let value = Pair {
        first: 0x1234_5678,
        second: 0x9abc_def0,
    };
    let mut short = [0u8; 7];
    let expected = BufferTooSmall {
        needed: 8,
        actual: 7,
    };

    assert_eq!(try_encode(&value, &mut short), Err(expected));
    assert_eq!(try_decode::<Pair>(&short), Err(expected));
}

#[test]
fn codec_round_trips_and_zeroes_output_tail() {
    let value = Pair {
        first: 0x1234_5678,
        second: 0x9abc_def0,
    };
    let mut output = [0xa5; 16];

    assert_eq!(try_encode(&value, &mut output), Ok(8));
    assert_eq!(&output[8..], &[0u8; 8]);
    assert_eq!(try_decode::<Pair>(&output), Ok(value));
}
