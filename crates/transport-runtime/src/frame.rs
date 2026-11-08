// SPDX-License-Identifier: Apache-2.0
//! Incremental APDU framing with exact consumer errors and sticky failure.
use canokey_protocol::apdu::{CommandInfo, Error, FrameDecoder, FrameEvent};

/// Preserve the consumer status when decoding stops inside an application callback.
/// Structural errors use the product's length error; no payload is retained here.
pub fn feed<E: Copy>(
    decoder: &mut FrameDecoder,
    bytes: &[u8],
    malformed: E,
    consumer: &mut impl FnMut(FrameEvent<'_>) -> Result<(), E>,
) -> Result<(), E> {
    let mut status = malformed;
    decoder
        .feed_events(bytes, &mut |event| {
            consumer(event).map_err(|error| {
                status = error;
                Error::Consumer
            })
        })
        .map_err(|_| status)
}

/// Input remains provisional until finish validates the complete envelope.
/// Failure is sticky: subsequent fragments cannot restart application callbacks.
pub struct Frame<E> {
    decoder: Option<FrameDecoder>,
    error: Option<E>,
}
impl<E: Copy> Frame<E> {
    pub fn new(total: usize) -> Self {
        Self {
            decoder: FrameDecoder::new(total).ok(),
            error: None,
        }
    }
    pub fn feed(
        &mut self,
        bytes: &[u8],
        malformed: E,
        consumer: &mut impl FnMut(FrameEvent<'_>) -> Result<(), E>,
    ) {
        if self.error.is_some() {
            return;
        }
        let result = match &mut self.decoder {
            Some(decoder) => feed(decoder, bytes, malformed, consumer),
            None => Err(malformed),
        };
        self.error = result.err();
    }
    pub fn finish(&self, malformed: E) -> Result<CommandInfo, E> {
        if let Some(error) = self.error {
            return Err(error);
        }
        self.decoder
            .as_ref()
            .ok_or(malformed)?
            .finish()
            .map_err(|_| malformed)
    }
}
