// SPDX-License-Identifier: Apache-2.0
use canokey_ctap::workspace::Reservation;
use canokey_ports::Memory;
use core::cell::Cell;
struct Wipe(Cell<usize>);
impl Memory for Wipe {
    fn wipe(&self, bytes: &mut [u8]) {
        self.0.set(self.0.get() + 1);
        bytes.fill(0x00);
    }
}
#[test]
fn scratch_loans_erase_the_whole_region_on_success_or_error() {
    // 981 bytes is the three-peer resident scratch contract, not a new backing.
    for length in [0, 1, 327, 981] {
        for fail in [false, true] {
            let memory = Wipe(Cell::new(0));
            let mut backing = [0xa5; 983];
            let result = (|| {
                let mut loan = Reservation::new(&mut backing[1..1 + length], &memory);
                assert!(loan.bytes().iter().all(|byte| *byte == 0xa5));
                if let Some(first) = loan.bytes().first_mut() {
                    *first = 0x42;
                }
                if fail {
                    return Err(());
                }
                Ok(())
            })();
            assert_eq!(result, if fail { Err(()) } else { Ok(()) });
            assert_eq!(memory.0.get(), 1);
            assert_eq!(backing[0], 0xa5);
            assert!(backing[1..1 + length].iter().all(|byte| *byte == 0x00));
            assert!(backing[1 + length..].iter().all(|byte| *byte == 0xa5));
        }
    }
}
#[test]
fn publishing_ends_the_loan_without_erasing_the_existing_backing() {
    let memory = Wipe(Cell::new(0));
    let mut backing = [0xa5; 4];
    let mut loan = Reservation::new(&mut backing[1..3], &memory);
    loan.bytes().copy_from_slice(&[0x41, 0x42]);
    loan.publish();
    assert_eq!(backing, [0xa5, 0x41, 0x42, 0xa5]);
    assert_eq!(memory.0.get(), 0);
}
#[test]
fn unwinding_before_publication_closes_the_loan() {
    let memory = Wipe(Cell::new(0));
    let mut backing = [0xa5; 8];
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut loan = Reservation::new(&mut backing, &memory);
        loan.bytes()[0] = 0x42;
        panic!("host-only injected unwind");
    }));
    assert!(result.is_err());
    assert_eq!(backing, [0x00; 8]);
    assert_eq!(memory.0.get(), 1);
}
