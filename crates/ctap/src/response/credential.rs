// SPDX-License-Identifier: Apache-2.0
//! Classic credential reply envelopes over existing contiguous or segmented
//! backing. External bodies record insertion points without retaining a lease.
use super::encoding::{self, EncodeError, Encoder, assertion_response, make_response};

/// A byte-string body is either present now or inserted by the response owner.
/// External bodies consume no encoder bytes; the owner validates and streams
/// their exact length before publishing the assembled response.
#[derive(Clone, Copy)]
pub enum Body<'a> {
    Bytes(&'a [u8]),
    External(usize),
}
impl Body<'_> {
    fn write(self, e: &mut Encoder<&mut [u8]>) -> usize {
        let length = match self {
            Self::Bytes(bytes) => bytes.len(),
            Self::External(length) => length,
        };
        e.bytes_len(length as u64);
        let remaining = e.writer().len();
        if let Self::Bytes(bytes) = self {
            e.encoded(bytes);
        }
        remaining
    }
}

pub struct Envelope<'a> {
    pub make: bool,
    pub id: &'a [u8],
    pub user: bool,
    pub count: u8,
    pub blob_key: Option<&'a [u8]>,
}
/// Positions are remaining physical encoder capacity at each insertion point.
/// The product subtracts from its original capacity (including a status prefix
/// where applicable); logical external lengths never advance the encoder.
#[derive(Debug, PartialEq, Eq)]
pub struct Layout {
    pub auth_remaining: usize,
    pub certificate_remaining: Option<usize>,
}
#[derive(Debug, PartialEq, Eq)]
pub enum Error<E> {
    Encoding,
    User(E),
}
impl<E> From<EncodeError> for Error<E> {
    fn from(_: EncodeError) -> Self {
        Self::Encoding
    }
}

#[inline(always)]
pub fn start(
    e: &mut Encoder<&mut [u8]>,
    envelope: &Envelope<'_>,
    auth: Body<'_>,
) -> Result<usize, EncodeError> {
    e.map(
        3 + u64::from(envelope.user)
            + u64::from(envelope.count > 1)
            + u64::from(envelope.blob_key.is_some()),
    );
    if envelope.make {
        e.encoded(&encoding::MAKE_HEADER[1..]);
    } else {
        e.u8(assertion_response::CREDENTIAL);
        encoding::descriptor(e, envelope.id)?;
        e.u8(assertion_response::AUTH_DATA);
    }
    Ok(auth.write(e))
}
/// The platform may supply a provisioned packed statement after this key.
#[inline(always)]
pub fn statement_key(e: &mut Encoder<&mut [u8]>) -> Result<(), EncodeError> {
    e.u8(assertion_response::SIGNATURE);
    Ok(())
}
#[inline(always)]
pub fn statement(
    e: &mut Encoder<&mut [u8]>,
    make: bool,
    self_algorithm: Option<i32>,
    signature: &[u8],
    certificate: Option<Body<'_>>,
) -> Result<Option<usize>, EncodeError> {
    statement_key(e)?;
    if make {
        if let Some(algorithm) = self_algorithm {
            e.encoded(encoding::SELF_ATTESTATION)
                .i32(algorithm)
                .str("sig");
        } else {
            e.encoded(encoding::ATTESTATION);
        }
    }
    e.bytes(signature);
    let remaining = if let Some(certificate) = certificate {
        e.encoded(encoding::CERTIFICATE);
        Some(certificate.write(e))
    } else {
        None
    };
    Ok(remaining)
}
/// The staged form accepts an already materialized user encoder, with no IO.
/// Use assemble for deferred reads so encoding failures precede storage errors.
#[inline(always)]
pub fn tail<E>(
    e: &mut Encoder<&mut [u8]>,
    envelope: &Envelope<'_>,
    user: impl FnOnce(&mut Encoder<&mut [u8]>) -> Result<(), E>,
) -> Result<(), Error<E>> {
    if envelope.user {
        e.u8(assertion_response::USER);
        user(e).map_err(Error::User)?;
    }
    if envelope.count > 1 {
        e.u8(assertion_response::COUNT).u8(envelope.count);
    }
    if let Some(key) = envelope.blob_key {
        e.u8(if envelope.make {
            make_response::LARGE_BLOB_KEY
        } else {
            assertion_response::LARGE_BLOB_KEY
        })
        .bytes(key);
    }
    e.finish()?;
    Ok(())
}
/// User reads occur only at their wire field, after signature/certificate work.
/// An error never publishes a response or an external-body lease; the caller's
/// existing rollback/erasure owner retains all emitted physical prefix bytes.
#[inline(always)]
pub fn assemble<E>(
    e: &mut Encoder<&mut [u8]>,
    envelope: &Envelope<'_>,
    auth: Body<'_>,
    self_algorithm: Option<i32>,
    signature: &[u8],
    certificate: Option<Body<'_>>,
    user: impl FnOnce(&mut Encoder<&mut [u8]>) -> Result<(), E>,
) -> Result<Layout, Error<E>> {
    let auth_remaining = start(e, envelope, auth)?;
    let certificate_remaining =
        statement(e, envelope.make, self_algorithm, signature, certificate)?;
    tail(e, envelope, |e| {
        // A deferred user read must not run after any earlier encoding failure,
        // including a USER key that did not fit in the output suffix.
        e.finish().map_err(|_| Error::Encoding)?;
        user(e).map_err(Error::User)
    })
    .map_err(|error| match error {
        Error::Encoding => Error::Encoding,
        Error::User(error) => error,
    })?;
    Ok(Layout {
        auth_remaining,
        certificate_remaining,
    })
}
