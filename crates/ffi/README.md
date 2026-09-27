# Native facade

This crate owns the unsafe C boundary around the safe core. `abi/` exports core
entrypoints, `runtime/` handles device lifecycle, `transport/` groups hardware
facades, and `platform/` constructs native capability bindings. C headers live
in `../../native/include/`. See [architecture](../../docs/architecture/README.md)
for serialization and buffer ownership. No applet policy belongs here.
