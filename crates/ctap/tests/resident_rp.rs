// SPDX-License-Identifier: Apache-2.0
//! Independent first-occurrence oracle for both bounded RP strategies.
use canokey_ctap::resident::{RP_HASH_BYTES, rp};

type Hash = [u8; RP_HASH_BYTES];
#[derive(Clone)]
struct Reader {
    slots: Vec<Option<Hash>>,
    reads: Vec<u8>,
    passes: usize,
    fail: Option<usize>,
    loaded: Option<u8>,
}
impl Reader {
    fn new(slots: Vec<Option<Hash>>) -> Self {
        Self {
            slots,
            reads: Vec::new(),
            passes: 0,
            fail: None,
            loaded: None,
        }
    }
}
impl rp::Reader for Reader {
    type Error = ();
    fn begin_pass(&mut self) {
        self.passes += 1;
        self.loaded = None;
    }
    fn read(&mut self, index: u8) -> Result<Option<&Hash>, ()> {
        self.reads.push(index);
        self.loaded = Some(index);
        if self.fail == Some(self.reads.len()) {
            return Err(());
        }
        Ok(self.slots[usize::from(index)].as_ref())
    }
}
fn representatives(slots: &[Option<Hash>]) -> Vec<u8> {
    let mut seen = Vec::new();
    let mut result = Vec::new();
    for (index, hash) in slots.iter().enumerate() {
        if let Some(hash) = hash {
            if !seen.contains(hash) {
                seen.push(*hash);
                result.push(index as u8);
            }
        }
    }
    result
}
fn verify(slots: Vec<Option<Hash>>, window: usize) {
    let capacity = slots.len() as u8;
    let expected = representatives(&slots);
    let mut reader = Reader::new(slots);
    let mut visited = vec![0x00; rp::bitmap_bytes(capacity)];
    let mut representatives = visited.clone();
    let mut hashes = vec![[0x00; RP_HASH_BYTES]; window];
    assert_eq!(
        rp::collect(
            capacity,
            &mut visited,
            &mut representatives,
            &mut hashes,
            &mut reader
        ),
        Ok(expected.len() as u8)
    );
    assert_eq!(reader.passes, expected.len().div_ceil(window).max(1));
    let mut next = 0;
    for &index in &expected {
        assert_eq!(
            rp::next_representative(capacity, &representatives, &mut next, |slot| {
                assert_eq!(slot, index);
                Ok::<_, ()>(reader.slots[usize::from(slot)])
            }),
            Ok(Some((index, reader.slots[usize::from(index)])))
        );
        assert_eq!(next, index + 1);
    }
    assert_eq!(
        rp::next_representative(capacity, &representatives, &mut next, |_| panic!(
            "read after exhaustion"
        )),
        Ok::<_, ()>(None::<(u8, ())>)
    );

    visited.fill(0x00);
    reader.reads.clear();
    for &index in &expected {
        assert_eq!(
            rp::next_group(capacity, &mut visited, &mut reader),
            Ok(true)
        );
        assert_eq!(reader.loaded, Some(index));
    }
    assert_eq!(
        rp::next_group(capacity, &mut visited, &mut reader),
        Ok(false)
    );
}
#[test]
fn all_small_hole_duplicate_and_first_occurrence_layouts() {
    // Four states per slot: missing or one of three hashes, differing only in
    // the final byte so comparing a prefix cannot satisfy the oracle.
    for encoding in 0..256 {
        let mut value = encoding;
        let mut slots = Vec::new();
        for _ in 0..4 {
            let symbol = value % 4;
            value /= 4;
            slots.push((symbol != 0).then(|| {
                let mut hash = [0x5a; RP_HASH_BYTES];
                hash[RP_HASH_BYTES - 1] = symbol as u8;
                hash
            }));
        }
        for window in [1, 2, 4] {
            verify(slots.clone(), window);
        }
    }
    verify(Vec::new(), 1);
}
#[test]
fn full_profiles_cover_batch_boundaries_and_last_slot() {
    for capacity in [64, 100, 255] {
        for distinct in [1, 7, 40, 41, capacity] {
            let slots = (0..capacity)
                .map(|index| {
                    let mut hash = [0x5a; RP_HASH_BYTES];
                    hash[RP_HASH_BYTES - 1] = index % distinct;
                    Some(hash)
                })
                .collect::<Vec<_>>();
            for window in [1, 2, 7, 40, 100] {
                verify(slots.clone(), window);
            }
        }
    }
}
#[test]
fn every_collection_read_failure_stops_and_preserves_the_read_prefix() {
    let slots = (0..64)
        .map(|index| {
            (index % 5 != 0).then(|| {
                let mut hash = [0x5a; RP_HASH_BYTES];
                hash[RP_HASH_BYTES - 1] = index % 17;
                hash
            })
        })
        .collect();
    let mut baseline = Reader::new(slots);
    assert!(
        rp::collect(
            64,
            &mut [0x00; 8],
            &mut [0x00; 8],
            &mut [[0x00; RP_HASH_BYTES]; 7],
            &mut baseline
        )
        .is_ok()
    );
    for failure in 1..=baseline.reads.len() {
        let mut reader = Reader::new(baseline.slots.clone());
        reader.fail = Some(failure);
        assert_eq!(
            rp::collect(
                64,
                &mut [0x00; 8],
                &mut [0x00; 8],
                &mut [[0x00; RP_HASH_BYTES]; 7],
                &mut reader
            ),
            Err(())
        );
        assert_eq!(reader.reads, baseline.reads[..failure]);
    }
    baseline.reads.clear();
    let mut visited = [0x00; 8];
    while rp::next_group(64, &mut visited, &mut baseline).unwrap() {}
    for failure in 1..=baseline.reads.len() {
        let mut reader = Reader::new(baseline.slots.clone());
        reader.fail = Some(failure);
        let mut visited = [0x00; 8];
        loop {
            match rp::next_group(64, &mut visited, &mut reader) {
                Ok(true) => {}
                Err(()) => break,
                Ok(false) => panic!("failure not observed"),
            }
        }
        assert_eq!(reader.reads, baseline.reads[..failure]);
    }
}
#[test]
fn representative_read_failure_does_not_advance_the_cursor() {
    let mut next = 3;
    assert_eq!(
        rp::next_representative(64, &[0x20; 8], &mut next, |_| Err::<(), _>(())),
        Err(())
    );
    assert_eq!(next, 3);
    assert_eq!(
        rp::next_representative(64, &[0x20; 8], &mut next, |slot| Ok::<_, ()>(slot)),
        Ok(Some((5, 5)))
    );
    assert_eq!(next, 6);
}
