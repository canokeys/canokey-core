// SPDX-License-Identifier: Apache-2.0
//! Incremental APDU framing with exact consumer errors and sticky failure.
use canokey_protocol::apdu::{CommandInfo, Error, FrameDecoder, FrameEvent, Header};
use canokey_protocol::response::{Response, Source, StatusWord};

/// GET RESPONSE retains the current input and output leases. Every other
/// admitted command closes unread output before routing or consuming its body.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ResponseRoute {
    Command,
    Continuation,
}
impl ResponseRoute {
    #[inline]
    pub fn begin(
        header: Header,
        blocked: bool,
        response: &mut Response,
        source: &mut impl Source,
    ) -> Result<Self, StatusWord> {
        if header.is_get_response() {
            return Ok(Self::Continuation);
        }
        if blocked {
            return Err(StatusWord::CONDITIONS_NOT_SATISFIED);
        }
        response.clear(source);
        Ok(Self::Command)
    }
    /// The complete GET RESPONSE envelope supplies only its Le budget. P1/P2
    /// and any data do not enter the applet. Absent Le consumes no response
    /// bytes; no pending response returns 0x6986 without cancelling input.
    #[inline]
    pub fn continuation(info: CommandInfo, response: &Response) -> Result<u32, StatusWord> {
        if response.active() {
            Ok(info.le.unwrap_or(0))
        } else {
            Err(StatusWord::COMMAND_NOT_ALLOWED)
        }
    }
}

// ISO 7816-4 application names contain at most sixteen bytes. An oversized
// name is drained without retaining it; P2 is checked before name matching.
pub struct Selection {
    used: usize,
}
impl Default for Selection {
    fn default() -> Self {
        Self::new()
    }
}
impl Selection {
    pub const AID_BYTES: usize = 16;
    pub const fn new() -> Self {
        Self { used: 0 }
    }
    /// The owner lends stable public-AID backing; it may reuse a closed response
    /// allocation while retaining a different unfinished command input.
    pub fn consume(&mut self, bytes: &[u8], aid: &mut [u8; Self::AID_BYTES]) {
        let Some(end) = self
            .used
            .checked_add(bytes.len())
            .filter(|n| *n <= aid.len())
        else {
            self.used = aid.len() + 1;
            return;
        };
        aid[self.used..end].copy_from_slice(bytes);
        self.used = end;
    }
    /// Call only after the complete APDU envelope passes validation. Collecting
    /// an AID never changes the selected applet or its authorization.
    pub fn finish<'a>(
        &self,
        p2: u8,
        aid: &'a [u8; Self::AID_BYTES],
    ) -> Result<&'a [u8], StatusWord> {
        if p2 != 0x00 {
            Err(StatusWord::WRONG_P1P2)
        } else if self.used > aid.len() {
            Err(StatusWord::FILE_NOT_FOUND)
        } else {
            Ok(&aid[..self.used])
        }
    }
}

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
