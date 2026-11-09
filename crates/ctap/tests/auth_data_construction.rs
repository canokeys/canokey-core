// SPDX-License-Identifier: Apache-2.0
use canokey_ctap::response::auth_data::{
    self, Constructed, Construction, Constructor, ExtensionFlag,
};

const PREPARE: u8 = 0x01;
const PUBLIC: u8 = 0x02;
const EXTENSIONS: u8 = 0x03;
const ATTESTED: u8 = 0x04;
const COSE: &[u8] = &[0xa1, 0x01, 0x02];
const EXTENSION: &[u8] = &[0xa1, 0x61, 0x78, 0xf5];
struct Backend<'a> {
    output: &'a mut [u8],
    events: Vec<u8>,
    fail: Option<u8>,
    extensions: bool,
    external: bool,
}
impl Constructor for &mut Backend<'_> {
    type Error = u8;
    type Public = usize;
    type Extensions = ();
    fn data(&mut self) -> &mut [u8] {
        self.output
    }
    fn prepare_public(&mut self) -> Result<usize, u8> {
        self.events.push(PREPARE);
        if self.fail == Some(PREPARE) {
            return Err(PREPARE);
        }
        Ok(COSE.len())
    }
    fn attested(&mut self) -> usize {
        self.events.push(ATTESTED);
        auth_data::attested(self.output, &[0x99; 16], &[0x55; 34]);
        89
    }
    fn public(&mut self, cursor: usize, prepared: usize) -> Result<usize, u8> {
        self.events.push(PUBLIC);
        assert_eq!(prepared, COSE.len());
        if self.fail == Some(PUBLIC) || self.output.len() - cursor < COSE.len() {
            return Err(PUBLIC);
        }
        self.output[cursor..cursor + COSE.len()].copy_from_slice(COSE);
        Ok(cursor + COSE.len())
    }
    fn external_public(&self) -> bool {
        self.external
    }
    fn prepare_extensions(&self) -> Option<()> {
        self.extensions.then_some(())
    }
    fn extensions(&mut self, cursor: usize, (): ()) -> Result<usize, u8> {
        self.events.push(EXTENSIONS);
        assert_ne!(self.output[32] & 0x80, 0x00);
        if self.fail == Some(EXTENSIONS) || self.output.len() - cursor < EXTENSION.len() {
            return Err(EXTENSIONS);
        }
        self.output[cursor..cursor + EXTENSION.len()].copy_from_slice(EXTENSION);
        Ok(cursor + EXTENSION.len())
    }
}
fn fields(make: bool, _extensions: bool, before: bool, _external: bool) -> Construction<'static> {
    Construction {
        rp: &[0x42; 32],
        counter: &[0x12, 0x34, 0x56, 0x78],
        up: true,
        uv: true,
        make,
        extension_flag: if before {
            ExtensionFlag::BeforeAttested
        } else {
            ExtensionFlag::AfterPublic
        },
    }
}
// Independent WebAuthn 6.1 layout: rpIdHash32, flags1, counter4, optionally
// AAGUID16, big-endian ID length2, ID34, COSE, then extension CBOR.
fn reference(output: &mut [u8], make: bool, extensions: bool, external: bool) -> usize {
    output[..32].fill(0x42);
    output[32] = 0x01 | 0x04 | if make { 0x40 } else { 0x00 };
    output[33..37].copy_from_slice(&[0x12, 0x34, 0x56, 0x78]);
    if make && external {
        return 37;
    }
    let mut cursor = 37;
    if make {
        output[37..53].fill(0x99);
        output[53..55].copy_from_slice(&[0x00, 0x22]);
        output[55..89].fill(0x55);
        output[89..92].copy_from_slice(COSE);
        cursor = 92;
    }
    if extensions {
        output[32] |= 0x80;
        output[cursor..cursor + EXTENSION.len()].copy_from_slice(EXTENSION);
        cursor += EXTENSION.len();
    }
    cursor
}
#[test]
fn both_profiles_match_independent_layout_and_pq_exits_before_callbacks() {
    for make in [false, true] {
        for extensions in [false, true] {
            for before in [false, true] {
                for external in [false, true] {
                    let mut output = [0xa5; 160];
                    let mut expected = output;
                    let length = reference(&mut expected, make, extensions, external);
                    let mut backend = Backend {
                        output: &mut output,
                        events: Vec::new(),
                        fail: None,
                        extensions,
                        external,
                    };
                    let result = auth_data::construct(
                        fields(make, extensions, before, external),
                        &mut backend,
                    )
                    .unwrap();
                    assert_eq!(backend.output, expected);
                    if make && external {
                        assert_eq!(result, Constructed::ExternalPublic);
                        assert!(backend.events.is_empty());
                    } else {
                        assert_eq!(result, Constructed::Complete(length));
                        let mut events = Vec::new();
                        if make {
                            events.extend_from_slice(&[PREPARE, ATTESTED, PUBLIC]);
                        }
                        if extensions {
                            events.push(EXTENSIONS);
                        }
                        assert_eq!(backend.events, events);
                    }
                }
            }
        }
    }
}
#[test]
fn public_and_extension_errors_stop_construction_with_original_ed_timing() {
    for before in [false, true] {
        for failed in [PREPARE, PUBLIC, EXTENSIONS] {
            let mut output = [0xa5; 160];
            let mut backend = Backend {
                output: &mut output,
                events: Vec::new(),
                fail: Some(failed),
                extensions: true,
                external: false,
            };
            assert_eq!(
                auth_data::construct(fields(true, true, before, false), &mut backend),
                Err(failed)
            );
            let mut expected = [0xa5; 160];
            reference(&mut expected, true, true, false);
            if failed == PREPARE {
                assert_eq!(backend.events, [PREPARE]);
                assert!(backend.output[37..].iter().all(|byte| *byte == 0xa5));
            } else if failed == PUBLIC {
                assert_eq!(backend.events, [PREPARE, ATTESTED, PUBLIC]);
                assert_eq!(&backend.output[37..89], &expected[37..89]);
                assert!(backend.output[89..].iter().all(|byte| *byte == 0xa5));
            } else {
                assert_eq!(backend.events, [PREPARE, ATTESTED, PUBLIC, EXTENSIONS]);
                assert_eq!(&backend.output[37..92], &expected[37..92]);
                assert!(backend.output[92..].iter().all(|byte| *byte == 0xa5));
            }
            assert_eq!(
                backend.output[32] & 0x80 != 0x00,
                before || failed == EXTENSIONS
            );
        }
    }
}

fn short_suffix<const N: usize>(make: bool, before: bool) {
    let complete = if make { 96 } else { 41 };
    let mut output = [0xa5; N];
    let mut backend = Backend {
        output: &mut output,
        events: Vec::new(),
        fail: None,
        extensions: true,
        external: false,
    };
    let result = auth_data::construct(fields(make, true, before, false), &mut backend);
    if N == complete {
        assert_eq!(result, Ok(Constructed::Complete(complete)));
    } else {
        assert_eq!(
            result,
            Err(if make && N < 92 { PUBLIC } else { EXTENSIONS })
        );
    }
    let used = if make && N >= 92 {
        92
    } else if make {
        89
    } else {
        37
    };
    if N < complete {
        assert!(backend.output[used..].iter().all(|byte| *byte == 0xa5));
    }
}
#[test]
fn short_public_and_extension_suffixes_cannot_publish_or_overwrite_sentinels() {
    for before in [false, true] {
        short_suffix::<37>(false, before);
        short_suffix::<38>(false, before);
        short_suffix::<39>(false, before);
        short_suffix::<40>(false, before);
        short_suffix::<41>(false, before);
        short_suffix::<89>(true, before);
        short_suffix::<90>(true, before);
        short_suffix::<91>(true, before);
        short_suffix::<92>(true, before);
        short_suffix::<93>(true, before);
        short_suffix::<94>(true, before);
        short_suffix::<95>(true, before);
        short_suffix::<96>(true, before);
    }
}

struct ExtensionStage;
impl auth_data::ExtensionConstructor for ExtensionStage {
    type Request = (bool, bool);
    type Workspace = [u8; 80];
    type Platform = Vec<usize>;
    type Prepared = ();
    type Error = u8;
    fn prepare(request: &Self::Request) -> Option<()> {
        request.0.then_some(())
    }
    fn data(workspace: &mut Self::Workspace) -> &mut [u8] {
        workspace
    }
    fn encode(
        request: &Self::Request,
        workspace: &mut Self::Workspace,
        platform: &mut Self::Platform,
        cursor: usize,
        (): (),
    ) -> Result<usize, u8> {
        platform.push(cursor);
        assert_ne!(workspace[32] & 0x80, 0x00);
        if request.1 {
            return Err(EXTENSIONS);
        }
        workspace[cursor..cursor + EXTENSION.len()].copy_from_slice(EXTENSION);
        Ok(cursor + EXTENSION.len())
    }
}
#[test]
fn outlined_extension_stage_preserves_no_output_and_failure_boundaries() {
    for present in [false, true] {
        for fail in [false, true] {
            let mut workspace = [0xa5; 80];
            workspace[32] = 0x05;
            let mut events = Vec::new();
            let result = auth_data::extend::<ExtensionStage>(
                &(present, fail),
                &mut workspace,
                &mut events,
                37,
            );
            if present {
                assert_eq!(events, [37]);
                assert_eq!(workspace[32], 0x85);
                if fail {
                    assert_eq!(result, Err(EXTENSIONS));
                    assert!(workspace[37..].iter().all(|byte| *byte == 0xa5));
                } else {
                    assert_eq!(result, Ok(41));
                    assert_eq!(&workspace[37..41], EXTENSION);
                    assert!(workspace[41..].iter().all(|byte| *byte == 0xa5));
                }
            } else {
                assert_eq!(result, Ok(37));
                assert!(events.is_empty());
                assert_eq!(workspace[32], 0x05);
                assert!(workspace[37..].iter().all(|byte| *byte == 0xa5));
            }
        }
    }
}
