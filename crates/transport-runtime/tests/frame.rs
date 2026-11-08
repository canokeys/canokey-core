// SPDX-License-Identifier: Apache-2.0
use canokey_protocol::apdu::{Error, FrameDecoder, FrameEvent};
use canokey_transport_runtime::frame::Frame;

// Independent pre-extraction framing lifecycle: callbacks stop after the first
// structural or application error, and finish preserves that exact status.
struct Previous {
    decoder: Option<FrameDecoder>,
    error: Option<u16>,
}
impl Previous {
    fn feed(&mut self, bytes: &[u8], consumer: &mut impl FnMut(FrameEvent<'_>) -> Result<(), u16>) {
        if self.error.is_some() {
            return;
        }
        let Some(decoder) = &mut self.decoder else {
            self.error = Some(0x6700);
            return;
        };
        if decoder
            .feed_events(bytes, &mut |event| {
                consumer(event).map_err(|sw| {
                    self.error = Some(sw);
                    Error::Consumer
                })
            })
            .is_err()
            && self.error.is_none()
        {
            self.error = Some(0x6700);
        }
    }
}
fn consume(event: FrameEvent<'_>, trace: &mut Vec<u8>, reject: usize) -> Result<(), u16> {
    match event {
        FrameEvent::Start(info) => {
            trace.extend_from_slice(&[
                info.header.cla,
                info.header.ins,
                info.header.p1,
                info.header.p2,
            ]);
        }
        FrameEvent::Data(bytes) => trace.extend_from_slice(bytes),
    }
    if trace.len() >= reject {
        Err(0x6985)
    } else {
        Ok(())
    }
}
#[test]
fn fragmented_frames_preserve_errors_events_and_finish_metadata() {
    let frames: &[&[u8]] = &[
        &[],
        &[0x00],
        &[0x00, 0xa4, 0x04, 0x00],
        &[0x00, 0xc0, 0x00, 0x00, 0x00],
        &[0x80, 0x10, 0x00, 0x00, 0x03, 0x01, 0x02, 0x03],
        &[0x90, 0x10, 0x00, 0x00, 0x03, 0x01, 0x02, 0x03, 0x00],
        &[
            0x80, 0x10, 0x00, 0x00, 0x00, 0x00, 0x03, 0x01, 0x02, 0x03, 0x00, 0x00,
        ],
        &[0x80, 0x10, 0x00, 0x00, 0x03, 0x01],
    ];
    for bytes in frames {
        for total in 0..=bytes.len() + 2 {
            for split in 0..=bytes.len() {
                for reject in [0, 4, 5, 7, usize::MAX] {
                    let mut previous = Previous {
                        decoder: FrameDecoder::new(total).ok(),
                        error: None,
                    };
                    let mut shared = Frame::new(total);
                    let mut old_trace = Vec::new();
                    let mut new_trace = Vec::new();
                    for chunk in [&bytes[..split], &bytes[split..], &[]] {
                        previous.feed(chunk, &mut |event| consume(event, &mut old_trace, reject));
                        shared.feed(chunk, 0x6700, &mut |event| {
                            consume(event, &mut new_trace, reject)
                        });
                        assert_eq!(old_trace, new_trace);
                        let expected = previous.error.map_or_else(
                            || {
                                previous
                                    .decoder
                                    .as_ref()
                                    .ok_or(0x6700)
                                    .and_then(|d| d.finish().map_err(|_| 0x6700))
                            },
                            Err,
                        );
                        assert_eq!(
                            format!("{expected:?}"),
                            format!("{:?}", shared.finish(0x6700))
                        );
                    }
                }
            }
        }
    }
}
