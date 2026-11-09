// SPDX-License-Identifier: Apache-2.0
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Context {
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
pub(super) enum Field {
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
// Compact records carry a byte length instead of a fat slice pointer. Build
// names and lengths from the same literals so the two arrays cannot drift.
pub(super) fn text_field(context: Context, key: &[u8], make: bool) -> Field {
    macro_rules! fields {
        ($(($scope:ident, $name:literal, $field:ident, $make_only:literal)),* $(,)?) => {
            const NAMES: &[u8] = concat!($($name),*).as_bytes();
            const FIELDS: &[(Context, u8, Field, bool)] = &[$(
                (Context::$scope, const {
                    assert!($name.len() <= u8::MAX as usize);
                    $name.len() as u8
                }, Field::$field, $make_only),
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
        (Extensions, "thirdPartyPayment", ThirdPartyPayment, false),
        (Extensions, "hmac-secret", HmacSecret, false),
        (Extensions, "hmac-secret-mc", HmacSecretMc, true),
        (Extensions, "credBlob", CredBlob, false),
        (Extensions, "largeBlobKey", LargeBlobKey, true),
        (Extensions, "minPinLength", MinPinLength, true),
        (Extensions, "credProtect", Protection, true),
    ];
    let mut names = NAMES;
    for &(scope, length, field, make_only) in FIELDS {
        let (name, rest) = names.split_at(usize::from(length));
        names = rest;
        if scope == context && name == key && (!make_only || make) {
            return field;
        }
    }
    Field::Ignore
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
