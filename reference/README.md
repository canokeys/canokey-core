# Legacy migration reference

`legacy-c/` is a byte-for-byte snapshot of the former C applets, transports,
core services, headers and tests immediately before their removal. Its original
README and CMake files describe the historical implementation, not current build
instructions. See `legacy-c/SNAPSHOT.json` for the source revision and SHA-256
checksums. Third-party sources are not duplicated.

Do not add this directory to Cargo, CMake, include paths or native source
allowlists. Consult it to compare behavior while completing resource and
compatibility acceptance. Production logic lives in `../crates/`; permitted
native adapters live in `../native/`. This snapshot is not a fallback runtime.
