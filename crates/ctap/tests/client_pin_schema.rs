// SPDX-License-Identifier: Apache-2.0
use canokey_ctap::client_pin::{Protocol, agreement, request::*};

#[test]
fn command_requirements_scope_and_error_order_cover_every_field_subset() {
    // CTAP labels: protocol=1, agreement=3, auth=4, newPIN=5, pinHash=6,
    // permissions=9, rpId=10. Fixed masks below describe the wire schema.
    for (command, required) in [
        (Command::Retries, 0x00),
        (Command::Agreement, 0x02),
        (Command::Set, 0x3a),
        (Command::Change, 0x7a),
        (Command::Token, 0x4a),
        (Command::TokenPermissions, 0x24a),
    ] {
        assert_eq!(command.required(), required);
        for seen in 0..2048 {
            for rp in [false, true] {
                for permissions in [0x00, 0x01, 0x02, 0x04, 0x0100] {
                    let missing = (seen & required != required).then_some(Error::MissingParameter);
                    let scope = if command == Command::Token && seen & 0x600 != 0x00 {
                        Some(Error::InvalidParameter)
                    } else if command == Command::TokenPermissions
                        && permissions & 0x03 != 0x00
                        && !rp
                    {
                        Some(Error::MissingParameter)
                    } else {
                        None
                    };
                    assert_eq!(
                        admit(command, seen, permissions, rp),
                        missing.or(scope).map_or(Ok(()), Err)
                    );
                }
            }
        }
    }
    for unknown in [0x00, 0x06, 0x07, 0x08, 0x0a, 0x100, u64::MAX] {
        assert_eq!(Command::decode(unknown), None);
    }
}

#[test]
fn permission_profiles_preserve_reject_and_ignore_policies() {
    let standard = PermissionPolicy {
        supported: 0x3f,
        rejected: 0x08,
        maximum: Some(0x3f),
        protocol_two_only: 0x00,
    };
    let extended = PermissionPolicy {
        supported: 0x0707,
        rejected: 0x78,
        maximum: None,
        protocol_two_only: 0x0700,
    };
    for protocol in [Protocol::One, Protocol::Two] {
        for requested in
            (0..=u64::from(u16::MAX)).chain([0x1_0000, 0x8000_0000_0000_0000, u64::MAX])
        {
            let standard_result = if requested == 0 {
                Err(Error::InvalidParameter)
            } else if requested > 0x3f || requested & 0x08 != 0x00 {
                Err(Error::UnauthorizedPermission)
            } else {
                Ok(requested as u16)
            };
            let extended_result = if requested == 0 {
                Err(Error::InvalidParameter)
            } else if requested & 0x78 != 0x00
                || protocol == Protocol::One && requested & 0x0700 != 0x00
            {
                Err(Error::UnauthorizedPermission)
            } else {
                Ok((requested & 0x0707) as u16)
            };
            assert_eq!(standard.validate(protocol, requested), standard_result);
            assert_eq!(extended.validate(protocol, requested), extended_result);
        }
    }
}

#[test]
fn ciphertext_lengths_include_exact_iv_prefix_and_pin_policy_boundary() {
    for (protocol, lengths) in [(Protocol::One, [16, 64, 16]), (Protocol::Two, [32, 80, 32])] {
        for (index, field) in [
            EncryptedField::Auth,
            EncryptedField::NewPin,
            EncryptedField::PinHash,
        ]
        .into_iter()
        .enumerate()
        {
            for length in 0..=241 {
                let expected = if length == lengths[index] {
                    Ok(())
                } else if index == 1 && length > lengths[index] {
                    Err(LengthError::PinTooLong)
                } else {
                    Err(LengthError::WrongLength)
                };
                assert_eq!(field.validate(protocol, length), expected);
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReadError {
    Schema,
    Input,
}
#[derive(Clone)]
enum Value {
    Integer(i64),
    Bytes(Vec<u8>),
}
struct Input {
    values: Vec<Value>,
    at: usize,
    calls: usize,
    fail_at: usize,
    count: usize,
}
impl Input {
    fn new(labels: [i64; 5]) -> Self {
        let mut values = Vec::new();
        for label in labels {
            values.push(Value::Integer(label));
            values.push(match label {
                0x01 => Value::Integer(0x02),
                0x03 => Value::Integer(-25),
                -0x01 => Value::Integer(0x01),
                -0x02 => Value::Bytes(vec![0x55; 32]),
                -0x03 => Value::Bytes(vec![0xaa; 32]),
                _ => Value::Integer(0x00),
            });
        }
        Self {
            values,
            at: 0,
            calls: 0,
            fail_at: 0,
            count: 5,
        }
    }
    fn check(&mut self) -> Result<(), ReadError> {
        self.calls += 1;
        if self.calls == self.fail_at {
            Err(ReadError::Input)
        } else {
            Ok(())
        }
    }
}
impl agreement::Reader for Input {
    type Error = ReadError;
    fn invalid_parameter() -> ReadError {
        ReadError::Schema
    }
    fn map(&mut self) -> Result<usize, ReadError> {
        self.check()?;
        Ok(self.count)
    }
    fn integer(&mut self) -> Result<i64, ReadError> {
        self.check()?;
        let value = &self.values[self.at];
        self.at += 1;
        match value {
            Value::Integer(value) => Ok(*value),
            _ => Err(ReadError::Input),
        }
    }
    fn bytes(&mut self) -> Result<&[u8], ReadError> {
        self.check()?;
        let value = &self.values[self.at];
        self.at += 1;
        match value {
            Value::Bytes(value) => Ok(value),
            _ => Err(ReadError::Input),
        }
    }
}
#[test]
fn strict_agreement_accepts_all_field_orders_and_propagates_each_read_failure() {
    let labels = [0x01, 0x03, -0x01, -0x02, -0x03];
    let mut permutations = 0;
    for mut code in 0..3125 {
        let mut order = [0; 5];
        for index in &mut order {
            *index = code % 5;
            code /= 5;
        }
        if (0..5).any(|at| order[..at].contains(&order[at])) {
            continue;
        }
        let fields = order.map(|index| labels[index]);
        let mut point = [0x00; 64];
        let mut input = Input::new(fields);
        agreement::read_strict(&mut input, &mut point).unwrap();
        assert_eq!(&point[..32], &[0x55; 32]);
        assert_eq!(&point[32..], &[0xaa; 32]);
        for fail_at in 1..=input.calls {
            let mut failing = Input::new(fields);
            failing.fail_at = fail_at;
            assert_eq!(
                agreement::read_strict(&mut failing, &mut point),
                Err(ReadError::Input)
            );
            assert_eq!(failing.calls, fail_at);
        }
        permutations += 1;
    }
    assert_eq!(permutations, 120);
}
#[test]
fn strict_agreement_rejects_unknown_duplicate_missing_and_wrong_field_values() {
    let labels = [0x01, 0x03, -0x01, -0x02, -0x03];
    let mut point = [0x00; 64];
    for count in [0, 4, 6, usize::MAX] {
        let mut input = Input::new(labels);
        input.count = count;
        assert_eq!(
            agreement::read_strict(&mut input, &mut point),
            Err(ReadError::Schema)
        );
    }
    for index in 0..5 {
        let mut input = Input::new(labels);
        input.values[2 * index] = Value::Integer(0x7f);
        assert_eq!(
            agreement::read_strict(&mut input, &mut point),
            Err(ReadError::Schema)
        );
    }
    for (index, bad_value) in [
        (1, Value::Integer(0x03)),
        (3, Value::Integer(-24)),
        (5, Value::Integer(0x02)),
        (7, Value::Bytes(vec![0x55; 31])),
        (9, Value::Bytes(vec![0xaa; 33])),
    ] {
        let mut input = Input::new(labels);
        input.values[index] = bad_value;
        assert_eq!(
            agreement::read_strict(&mut input, &mut point),
            Err(ReadError::Schema)
        );
    }
    let mut duplicate = Input::new(labels);
    duplicate.values[8] = Value::Integer(-0x02);
    assert_eq!(
        agreement::read_strict(&mut duplicate, &mut point),
        Err(ReadError::Schema)
    );
}
