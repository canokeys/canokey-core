// SPDX-License-Identifier: Apache-2.0
//! COSE EC2 agreement schema; point validation stays with the crypto adapter.
pub const COORDINATE_BYTES: usize = 32;
pub const POINT_BYTES: usize = 2 * COORDINATE_BYTES;
pub const REQUIRED_FIELDS: u8 = 0x1f;
pub const FIELD_COUNT: usize = 5;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Field {
    KeyType,
    Algorithm,
    Curve,
    X,
    Y,
}
impl Field {
    pub fn decode(label: i64) -> Option<Self> {
        match label {
            0x01 => Some(Self::KeyType),
            0x03 => Some(Self::Algorithm),
            -0x01 => Some(Self::Curve),
            -0x02 => Some(Self::X),
            -0x03 => Some(Self::Y),
            _ => None,
        }
    }
    pub const fn bit(self) -> u8 {
        match self {
            Self::KeyType => 0x01,
            Self::Algorithm => 0x02,
            Self::Curve => 0x04,
            Self::X => 0x08,
            Self::Y => 0x10,
        }
    }
    pub const fn scalar(self) -> Option<i64> {
        // COSE_Key kty=EC2(2), alg=ECDH-ES+HKDF-256(-25), crv=P-256(1).
        match self {
            Self::KeyType => Some(0x02),
            Self::Algorithm => Some(-25),
            Self::Curve => Some(0x01),
            Self::X | Self::Y => None,
        }
    }
    pub const fn coordinate_offset(self) -> Option<usize> {
        match self {
            Self::X => Some(0),
            Self::Y => Some(COORDINATE_BYTES),
            _ => None,
        }
    }
}

/// Borrowed reader calls are synchronous. Decoding errors keep the product's
/// CBOR status; schema failures use its explicit invalid-parameter mapping.
pub trait Reader {
    type Error;
    fn invalid_parameter() -> Self::Error;
    fn map(&mut self) -> Result<usize, Self::Error>;
    fn integer(&mut self) -> Result<i64, Self::Error>;
    fn bytes(&mut self) -> Result<&[u8], Self::Error>;
}

/// Strict five-field product policy: order-independent, no optional members,
/// no duplicate labels. The enclosing reader owns the map and its byte backing.
/// Incremental products use Field with their existing ordered/optional policy.
pub fn read_strict<R: Reader>(
    reader: &mut R,
    point: &mut [u8; POINT_BYTES],
) -> Result<(), R::Error> {
    if reader.map()? != FIELD_COUNT {
        return Err(R::invalid_parameter());
    }
    let mut seen = 0x00;
    for _ in 0..FIELD_COUNT {
        let field = Field::decode(reader.integer()?).ok_or_else(R::invalid_parameter)?;
        if seen & field.bit() != 0x00 {
            return Err(R::invalid_parameter());
        }
        seen |= field.bit();
        if let Some(expected) = field.scalar() {
            if reader.integer()? != expected {
                return Err(R::invalid_parameter());
            }
        } else {
            let coordinate = reader.bytes()?;
            if coordinate.len() != COORDINATE_BYTES {
                return Err(R::invalid_parameter());
            }
            let offset = field.coordinate_offset().unwrap();
            point[offset..offset + COORDINATE_BYTES].copy_from_slice(coordinate);
        }
    }
    Ok(())
}

/// Private candidates remain in existing owner storage. Generation may reject a
/// raw random candidate and redraw; validated native generators return true.
/// Cached owners restore existing key scratch without exporting a public key.
/// commit publishes only product key metadata/public output, never token grants.
/// All operations are synchronous; products erase partial private/output state
/// on failure and retain their eager/lazy policy and readiness publication point.
pub trait Generation {
    type Error;
    type Output;
    fn ready(&self) -> bool;
    fn generate(&mut self) -> Result<bool, Self::Error>;
    fn commit(&mut self) -> Result<Self::Output, Self::Error>;
    fn restore(&mut self) -> Result<Self::Output, Self::Error>;
}

#[inline]
pub fn establish<G: Generation>(backend: &mut G) -> Result<G::Output, G::Error> {
    if backend.ready() {
        return backend.restore();
    }
    while !backend.generate()? {}
    backend.commit()
}

/// Peer validation belongs to the P-256 primitive. Output borrows existing
/// product scratch and starts with the 32-byte ECDH x coordinate on success.
/// The adapter owns primitive scratch erasure; the caller erases this output on
/// every completion/failure. No private key or secret output is retained here.
pub trait Exchange: super::Derivation {
    fn agree(&mut self, peer: &[u8; POINT_BYTES], output: &mut [u8]) -> Result<(), Self::Error>;
}

/// ECDH precedes protocol admission and KDF. This preserves incremental products
/// that report primitive/length failures before an unsupported internal protocol.
/// Products lend the same x-coordinate and output-key buffers used by derive.
#[inline]
pub fn decapsulate<X: Exchange>(
    protocol: impl FnOnce() -> Result<super::Protocol, X::Error>,
    peer: &[u8; POINT_BYTES],
    scratch: &mut [u8],
    mac_key: &mut [u8; super::KEY_BYTES],
    aes_key: &mut [u8; super::KEY_BYTES],
    backend: &mut X,
) -> Result<(), X::Error> {
    // The product installs at least one x-coordinate worth of scratch. Slice
    // shape is an internal capability contract, not untrusted request length.
    assert!(scratch.len() >= super::KEY_BYTES);
    backend.agree(peer, scratch)?;
    let protocol = protocol()?;
    super::derive(
        protocol,
        (&scratch[..super::KEY_BYTES]).try_into().unwrap(),
        mac_key,
        aes_key,
        backend,
    )
}
