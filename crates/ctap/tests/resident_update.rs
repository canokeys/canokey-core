// SPDX-License-Identifier: Apache-2.0
use canokey_ctap::resident::{
    self, Entry, MAX_BYTES, MIN_BYTES,
    group::{
        self, Header, Replacement,
        update::{self, Backend},
    },
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Error {
    Invalid,
    Read,
    Mutation,
    Uncertain,
    Space,
}
struct Store<const BUFFERED: bool> {
    published: Option<Vec<u8>>,
    staged: Vec<u8>,
    leased: bool,
    reads: usize,
    mutations: usize,
    aborts: usize,
    fail_mutation: Option<usize>,
    fail_read: Option<usize>,
    uncertain: bool,
    no_space: bool,
}
impl<const BUFFERED: bool> Store<BUFFERED> {
    fn new(published: Option<Vec<u8>>) -> Self {
        Self {
            published,
            staged: Vec::new(),
            leased: false,
            reads: 0,
            mutations: 0,
            aborts: 0,
            fail_mutation: None,
            fail_read: None,
            uncertain: false,
            no_space: false,
        }
    }
    fn mutation(&mut self) -> Result<(), Error> {
        self.mutations += 1;
        if self.fail_mutation == Some(self.mutations) {
            Err(Error::Mutation)
        } else {
            Ok(())
        }
    }
}
impl<const BUFFERED: bool> Backend for Store<BUFFERED> {
    type Error = Error;
    const BUFFER_PEERS: bool = BUFFERED;
    const VALIDATE_PATCH_PEERS: bool = !BUFFERED;
    fn invalid_record(&self) -> Error {
        Error::Invalid
    }
    fn read(&mut self, offset: usize, out: &mut [u8]) -> Result<(), Error> {
        assert!(
            !self.leased,
            "buffered backend cannot read while staging owns its file cache"
        );
        self.reads += 1;
        if self.fail_read == Some(self.reads) {
            return Err(Error::Read);
        }
        out.copy_from_slice(&self.published.as_ref().unwrap()[offset..offset + out.len()]);
        Ok(())
    }
    fn prepare(&mut self, _: usize) -> Result<(), Error> {
        if self.no_space {
            Err(Error::Space)
        } else {
            Ok(())
        }
    }
    fn patch(&mut self, offset: usize, value: &[u8]) -> Result<(), Error> {
        self.mutation()?;
        self.published.as_mut().unwrap()[offset..offset + value.len()].copy_from_slice(value);
        if self.uncertain {
            Err(Error::Uncertain)
        } else {
            Ok(())
        }
    }
    fn remove(&mut self) -> Result<(), Error> {
        self.mutation()?;
        self.published = None;
        Ok(())
    }
    fn stage_begin(&mut self) -> Result<(), Error> {
        self.mutation()?;
        self.staged.clear();
        self.leased = BUFFERED;
        Ok(())
    }
    fn stage_append(&mut self, value: &[u8]) -> Result<(), Error> {
        self.mutation()?;
        self.staged.extend_from_slice(value);
        Ok(())
    }
    fn stage_commit(&mut self) -> Result<(), Error> {
        self.mutation()?;
        self.published = Some(self.staged.clone());
        self.leased = false;
        if self.uncertain {
            Err(Error::Uncertain)
        } else {
            Ok(())
        }
    }
    fn stage_abort(&mut self) {
        self.aborts += 1;
        self.leased = false;
        self.staged.clear();
    }
}
fn member(tag: u8, maximal: bool) -> Vec<u8> {
    let mut bytes = vec![0x00; MAX_BYTES];
    bytes[1] = resident::RESIDENT;
    bytes[2] = tag;
    let user = vec![
        tag;
        if maximal {
            64
        } else {
            1 + usize::from(tag % 4)
        }
    ];
    let text = if maximal {
        &b"r".repeat(64)[..]
    } else {
        &b""[..]
    };
    let n = resident::encode_fields(
        &mut bytes[resident::FIXED_BYTES..],
        &[
            if maximal { &text[..32] } else { b"r" },
            &user,
            text,
            text,
            if maximal { &text[..32] } else { b"" },
        ],
    );
    bytes.truncate(resident::FIXED_BYTES + n);
    Entry::decode(&bytes).unwrap();
    bytes
}
fn group(members: &[Vec<u8>; group::MEMBERS]) -> (Header, Option<Vec<u8>>) {
    let mut header = group::empty();
    for (index, value) in members.iter().enumerate() {
        Replacement::set_length(&mut header, index, value.len());
    }
    let mut bytes = header.to_vec();
    for value in members {
        bytes.extend_from_slice(value);
    }
    let published = (bytes.len() > group::HEADER_BYTES).then_some(bytes);
    if let Some(bytes) = &published {
        group::validate(&header, bytes.len()).unwrap();
    }
    (header, published)
}
fn matrix<const BUFFERED: bool>() {
    for occupied in 0..16 {
        for maximal in [false, true] {
            let members = core::array::from_fn(|i| {
                if occupied & (1 << i) == 0 {
                    Vec::new()
                } else {
                    member(i as u8, maximal)
                }
            });
            let (header, old) = group(&members);
            for target in 0..group::MEMBERS {
                for value in [
                    Vec::new(),
                    members[target].clone(),
                    member(0x7a, maximal),
                    member(0x7b, !maximal),
                ] {
                    let mut expected = members.clone();
                    expected[target] = value.clone();
                    let mut store = Store::<BUFFERED>::new(old.clone());
                    let mut scratch = vec![0xa5; if BUFFERED { 3 * MAX_BYTES } else { MAX_BYTES }];
                    update::replace(header, target, &value, &mut scratch, &mut store).unwrap();
                    assert_eq!(store.published, group(&expected).1);
                    assert!(!store.leased);
                    if !value.is_empty() && value == members[target] {
                        assert_eq!(store.mutations, 0);
                    }
                }
            }
        }
    }
}
#[test]
fn sparse_and_maximal_groups_share_replacement_without_changing_slots() {
    matrix::<true>();
    matrix::<false>();
}
fn faults<const BUFFERED: bool>() {
    let members = core::array::from_fn(|i| member(i as u8, true));
    let (header, old) = group(&members);
    let value = member(0x7a, false);
    let mut expected = members.clone();
    expected[1] = value.clone();
    let mut successful = Store::<BUFFERED>::new(old.clone());
    let mut scratch = vec![0x00; if BUFFERED { 3 * MAX_BYTES } else { MAX_BYTES }];
    update::replace(header, 1, &value, &mut scratch, &mut successful).unwrap();
    for fault in 1..=successful.mutations {
        let mut store = Store::<BUFFERED>::new(old.clone());
        store.fail_mutation = Some(fault);
        assert_eq!(
            update::replace(header, 1, &value, &mut scratch, &mut store),
            Err(Error::Mutation)
        );
        assert_eq!(store.published, old);
        assert_eq!(store.aborts, usize::from(BUFFERED));
    }
    for fault in 1..=successful.reads {
        let mut store = Store::<BUFFERED>::new(old.clone());
        store.fail_read = Some(fault);
        assert_eq!(
            update::replace(header, 1, &value, &mut scratch, &mut store),
            Err(Error::Read)
        );
        assert_eq!(store.published, old);
    }
    let mut store = Store::<BUFFERED>::new(old);
    store.uncertain = true;
    assert_eq!(
        update::replace(header, 1, &value, &mut scratch, &mut store),
        Err(Error::Uncertain)
    );
    assert_eq!(store.published, group(&expected).1);
    assert_eq!(store.mutations, successful.mutations);
}
#[test]
fn every_read_and_publication_boundary_propagates_failure_without_retry() {
    faults::<true>();
    faults::<false>();
}
fn validation<const BUFFERED: bool>() {
    let members = core::array::from_fn(|i| member(i as u8, true));
    let (header, old) = group(&members);
    let mut scratch = vec![0x00; if BUFFERED { 3 * MAX_BYTES } else { MAX_BYTES }];
    // No-op needs no allocation preflight even when writes would fail for space.
    let mut store = Store::<BUFFERED>::new(old.clone());
    store.no_space = true;
    update::replace(header, 1, &members[1], &mut scratch, &mut store).unwrap();
    assert_eq!(store.mutations, 0);
    assert_eq!(store.reads, if BUFFERED { 1 } else { 4 });
    for corrupt_member in 0..group::MEMBERS {
        let mut store = Store::<BUFFERED>::new(old.clone());
        let offset = group::member_offset(&header, corrupt_member);
        store.published.as_mut().unwrap()[offset + 1] = 0x00;
        let result = update::replace(header, 1, &members[1], &mut scratch, &mut store);
        assert_eq!(
            result,
            if BUFFERED {
                Ok(())
            } else {
                Err(Error::Invalid)
            }
        );
        // Core replaces the corrupted target in full; untouched peers remain
        // outside its same-length validation policy. Streamed owners reject all.
        assert_eq!(
            store.mutations,
            usize::from(BUFFERED && corrupt_member == 1)
        );
    }
    let mut store = Store::<BUFFERED>::new(old);
    assert_eq!(
        update::replace(header, 4, &members[1], &mut scratch, &mut store),
        Err(Error::Invalid)
    );
    assert_eq!(store.reads, 0);
    assert_eq!(store.mutations, 0);
    assert!(MIN_BYTES < members[1].len());
}
#[test]
fn noop_and_corrupt_member_policy_remain_explicit_for_each_backend() {
    validation::<true>();
    validation::<false>();
}

fn patch_faults<const BUFFERED: bool>() {
    let members = core::array::from_fn(|i| member(i as u8, true));
    let (header, old) = group(&members);
    let mut value = members[1].clone();
    value[2] = 0x7a;
    let mut scratch = vec![0x00; if BUFFERED { 3 * MAX_BYTES } else { MAX_BYTES }];
    for (no_space, fail, uncertain, expected) in [
        (true, None, false, Error::Space),
        (false, Some(1), false, Error::Mutation),
        (false, None, true, Error::Uncertain),
    ] {
        let mut store = Store::<BUFFERED>::new(old.clone());
        store.no_space = no_space;
        store.fail_mutation = fail;
        store.uncertain = uncertain;
        assert_eq!(
            update::replace(header, 1, &value, &mut scratch, &mut store),
            Err(expected)
        );
        assert_eq!(store.mutations, usize::from(!no_space));
        let mut expected = members.clone();
        if uncertain {
            expected[1] = value.clone();
        }
        assert_eq!(store.published, group(&expected).1);
        assert_eq!(store.aborts, 0);
    }
    let mut store = Store::<BUFFERED>::new(old.clone());
    assert_eq!(
        update::replace(header, 1, &value, &mut [], &mut store),
        Err(Error::Invalid)
    );
    assert_eq!(store.published, old);
    assert_eq!(store.reads, 0);
    assert_eq!(store.mutations, 0);
}
#[test]
fn patch_space_failure_short_scratch_and_uncertain_commit_never_retry() {
    patch_faults::<true>();
    patch_faults::<false>();
}
