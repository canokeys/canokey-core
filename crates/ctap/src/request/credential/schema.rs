// SPDX-License-Identifier: Apache-2.0
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Context {
    Root,
    Rp,
    User,
    Algorithms,
    Algorithm,
    List,
    Descriptor,
    Options,
    Extensions,
}
#[derive(Clone, Copy)]
pub(crate) enum Field {
    Ignore,
    TextOnly,
    ClientHash,
    Rp,
    User,
    UserId,
    Name,
    Display,
    Algorithms,
    Algorithm,
    List,
    DescriptorId,
    Type,
    Options,
    Resident,
    Up,
    Uv,
    Auth,
    Protocol,
    Extensions,
    Protection,
    MinPinLength,
    LargeBlobKey,
    CredBlob,
    ThirdPartyPayment,
    HmacSecret,
    HmacSecretMc,
    Enterprise,
}
/// Both parsers check the CBOR type before applying command-specific boolean rules.
#[inline(always)]
pub(super) fn admit_boolean<E: crate::request::Error>(
    make: bool,
    field: Field,
    value: bool,
) -> Result<(), E> {
    match field {
        Field::Resident if !make => Err(E::UNSUPPORTED_OPTION),
        Field::Up if make && !value => Err(E::INVALID_OPTION),
        Field::LargeBlobKey if !value => Err(E::INVALID_OPTION),
        _ => Ok(()),
    }
}

#[inline(always)]
pub(super) fn admit_auth<E: crate::request::Error>(
    protocol: u8,
    length: Option<usize>,
) -> Result<(), E> {
    if length.is_some_and(|length| length != 0) && protocol == 0 {
        return Err(E::MISSING_PARAMETER);
    }
    if length.is_some_and(|length| {
        length != 0
            && length
                != if protocol == crate::client_pin::Protocol::One as u8 {
                    crate::client_pin::Protocol::One.auth_bytes()
                } else {
                    crate::client_pin::Protocol::Two.auth_bytes()
                }
    }) {
        return Err(E::PIN_AUTH_INVALID);
    }
    Ok(())
}
// Names are CBOR text keys (header then spelling) in one byte string, so a
// record needs no length or fat slice pointer. Extension names are the shared
// GetInfo array; every other name comes from the literals below.
pub(crate) fn text_field(context: Context, key: &[u8], make: bool) -> Field {
    macro_rules! fields {
        ($(($scope:ident, $name:literal, $field:ident, $make_only:literal)),* $(,)?) => {
            const NAMES: [u8; 0 $(+ 1 + $name.len())*] = {
                let mut names = [0; 0 $(+ 1 + $name.len())*];
                let mut at = 0;
                $(
                    let name = $name.as_bytes();
                    assert!(name.len() < 24);
                    names[at] = 0x60 | name.len() as u8;
                    let mut i = 0;
                    while i < name.len() {
                        names[at + 1 + i] = name[i];
                        i += 1;
                    }
                    at += 1 + name.len();
                )*
                assert!(at == names.len());
                names
            };
            const FIELDS: &[(Context, Field, bool)] = &[$(
                (Context::$scope, Field::$field, $make_only),
            )*];
        };
    }
    // Each entry is (context, wire key, destination, makeCredential only).
    fields![
        (Rp, "id", Rp, false),
        (Rp, "name", TextOnly, false),
        (Rp, "icon", TextOnly, false),
        (User, "id", UserId, false),
        (User, "name", Name, false),
        (User, "displayName", Display, false),
        (Algorithm, "alg", Algorithm, false),
        (Algorithm, "type", Type, false),
        (Descriptor, "type", Type, false),
        (Descriptor, "id", DescriptorId, false),
        (Options, "rk", Resident, false),
        (Options, "uv", Uv, false),
        (Options, "up", Up, false),
    ];
    // Destinations in `extensions::NAMES` order.
    const EXTENSIONS: &[(Context, Field, bool)] = &[
        (Context::Extensions, Field::CredBlob, false),
        (Context::Extensions, Field::Protection, true),
        (Context::Extensions, Field::HmacSecret, false),
        (Context::Extensions, Field::HmacSecretMc, true),
        (Context::Extensions, Field::LargeBlobKey, false),
        (Context::Extensions, Field::MinPinLength, true),
        (Context::Extensions, Field::ThirdPartyPayment, false),
    ];
    let (mut names, fields): (&[u8], _) = if context == Context::Extensions {
        (&crate::extensions::NAMES[1..], EXTENSIONS)
    } else {
        (&NAMES, FIELDS)
    };
    for &(scope, field, make_only) in fields {
        let Some((name, rest)) = names
            .split_first()
            .and_then(|(&header, rest)| rest.split_at_checked(usize::from(header & 0x1f)))
        else {
            break;
        };
        names = rest;
        if scope == context && name == key && (!make_only || make) {
            return field;
        }
    }
    // CanoKey validates every RP value as text, including unknown metadata.
    // User metadata has no corresponding map-wide type requirement.
    if context == Context::Rp {
        Field::TextOnly
    } else {
        Field::Ignore
    }
}

/// CTAP makeCredential/getAssertion integer labels (CTAP 2.2 section 6).
#[inline(always)]
pub(super) fn root_field(key: Option<i8>, make: bool) -> Field {
    if make {
        match key {
            Some(1) => Field::ClientHash,
            Some(2) => Field::Rp,
            Some(3) => Field::User,
            Some(4) => Field::Algorithms,
            Some(5) => Field::List,
            Some(6) => Field::Extensions,
            Some(7) => Field::Options,
            Some(8) => Field::Auth,
            Some(9) => Field::Protocol,
            Some(10) => Field::Enterprise,
            _ => Field::Ignore,
        }
    } else {
        match key {
            Some(1) => Field::Rp,
            Some(2) => Field::ClientHash,
            Some(3) => Field::List,
            Some(4) => Field::Extensions,
            Some(5) => Field::Options,
            Some(6) => Field::Auth,
            Some(7) => Field::Protocol,
            _ => Field::Ignore,
        }
    }
}
