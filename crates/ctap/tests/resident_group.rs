// SPDX-License-Identifier: Apache-2.0
use canokey_ctap::resident::{
    MAX_BYTES, MIN_BYTES,
    group::{self, Replacement},
};

#[test]
fn persisted_group_headers_reject_every_out_of_range_u16_length() {
    let mut cases = 0;
    for member in 0..group::MEMBERS {
        for length in 0..=u16::MAX {
            let mut header = group::empty();
            Replacement::set_length(&mut header, member, usize::from(length));
            let total = group::HEADER_BYTES + usize::from(length);
            let permitted = (MIN_BYTES..=MAX_BYTES).contains(&usize::from(length));
            assert_eq!(group::validate(&header, total).is_ok(), permitted);
            assert!(group::validate(&header, total + 1).is_err());
            assert!(group::validate(&header, total - 1).is_err());
            cases += 3;
        }
    }
    println!("resident group u16 length/size admission cases: {cases}");
}

#[test]
fn sparse_group_replacements_preserve_neighbor_lengths_and_offsets() {
    let mut cases = 0;
    for occupied in 0..(1 << group::MEMBERS) {
        let mut header = group::empty();
        let lengths: [usize; group::MEMBERS] = core::array::from_fn(|member| {
            if occupied & (1 << member) != 0 {
                MIN_BYTES + member
            } else {
                0
            }
        });
        for (member, length) in lengths.iter().copied().enumerate() {
            Replacement::set_length(&mut header, member, length);
        }
        for target in 0..group::MEMBERS {
            for length in [0, MIN_BYTES, MAX_BYTES] {
                let plan = Replacement::new(&header, target, length).unwrap();
                let mut updated = header;
                Replacement::set_length(&mut updated, target, length);
                assert_eq!(plan.old_length, lengths[target]);
                assert_eq!(
                    plan.offset,
                    group::HEADER_BYTES + lengths[..target].iter().sum::<usize>()
                );
                let mut cursor = group::HEADER_BYTES;
                for (member, old_length) in lengths.iter().copied().enumerate() {
                    let expected_length = if member == target { length } else { old_length };
                    assert_eq!(group::member_length(&updated, member), expected_length);
                    assert_eq!(group::member_offset(&updated, member), cursor);
                    cursor += expected_length;
                }
                assert_eq!(cursor, plan.total_bytes);
                assert_eq!(
                    group::validate(&updated, cursor).is_ok(),
                    cursor > group::HEADER_BYTES
                );
                cases += 1;
            }
        }
    }
    println!("resident sparse replacement accounting cases: {cases}");
}

#[test]
fn group_magic_layout_and_replacement_bounds_are_fixed() {
    assert_eq!(group::empty(), *b"CTG1\0\0\0\0\0\0\0\0");
    assert_eq!(group::MAX_GROUP_BYTES, 1320);
    let mut header = group::empty();
    Replacement::set_length(&mut header, 0, MAX_BYTES);
    // CTG1 v1 first u16 length is 327 = 0x0147, encoded big-endian.
    assert_eq!(&header[4..6], &[0x01, 0x47]);
    for index in 0..4 {
        for byte in 0x00..=0xff {
            if byte == group::FORMAT[index] {
                continue;
            }
            let mut corrupt = header;
            corrupt[index] = byte;
            assert!(group::validate(&corrupt, group::HEADER_BYTES + MAX_BYTES).is_err());
        }
    }
    assert!(Replacement::new(&header, group::MEMBERS, MAX_BYTES).is_err());
    for length in [1, MIN_BYTES - 1, MAX_BYTES + 1, usize::MAX] {
        assert!(Replacement::new(&header, 0, length).is_err());
    }
}
