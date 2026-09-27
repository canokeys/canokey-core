# Developer documentation

Current contracts are organized by ownership. Migration checkpoints under
`history/` are explanatory records, not current feature or build instructions.

- [Architecture](architecture/README.md) and [PIN mechanism](architecture/pin-mechanism.md)
- Applets: [ADMIN/PASS](applets/admin-pass.md), [OATH](applets/oath.md),
  [OpenPGP](applets/openpgp.md), [PIV](applets/piv.md), [CTAP/U2F](applets/ctap.md)
- Platform: [integration and release versions](platform/README.md), [device runtime](platform/device.md), [NFC](platform/nfc.md)
- [Testing and profiles](testing/README.md), [replacement coverage](testing/legacy-test-coverage.md)
- [Product protocols](applets/product-protocol.md)

Production applets and portable transport policy are implemented in Rust.
Historical statements about C-owned transport framing or absent CTAP credential
commands apply only to their dated checkpoints. Current implementation coverage
is described in the corresponding applet and platform documents.
