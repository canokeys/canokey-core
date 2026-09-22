<!-- SPDX-License-Identifier: Apache-2.0 -->
# OATH services

Safe `no_std` domain/service crate; no APDU, status words, FFI, allocation or
runtime dependency. See [implementation checkpoint](../docs/oath.md) for
ownership, protocol coverage and normal tests. The protocol adapter and
concrete repository live in `core/oath_protocol.rs` and `core/oath_backend.rs`;
neither is hidden inside this domain crate.
