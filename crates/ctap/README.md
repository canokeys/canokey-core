# canokey-ctap

Allocator-free standard CTAP contracts, independent of Core, FFI and product
applications. `config` owns command bytes, `status` owns standard wire status
values, `request` validates parameterless commands, and `ports` exposes the
existing static request budget contract.

CanoKey and vLEI consume the same parameterless parser and standard tables.
Product adapters keep their public command/status names and vendor extensions.
The parser receives only command/extra-data metadata; it retains no backing,
secret, application capability or response lease.

This is the first extraction unit. GetInfo encoding/build schema, borrowed
workspace capabilities, authorization session and storage/crypto operations
remain in product modules until their production consumers are migrated.

Run the standalone contract test without linking a product:

```sh
cargo test -p canokey-ctap --test standalone
```
