# Removed extended CCID feature

Disposition: `removed intentional difference`. This was a delivered feature,
removed to use C 3.1.2’s short-only USB CCID contract. It was not a parser bug.
The pinned blobs in provenance.json preserve all prior Core/ffi/card regression
assets without compiling historical code in the current product.

Use a separate historical checkout of platform d99bae8 and Core
15d2b3bac17c6db238a9c12da1c0a02cc736e430, with its pinned submodules.
Run `cargo test -p canokey-rust-core --features ctap --test ccid --test streaming`
from that Core checkout; use its documented CTest USB-session fixture for
actual ffi/native execution. Platform tools/hil/rust_ctap_smoke.py at d99bae8
contains the original hardware tests (requires a dedicated historical device).
Do not run historical acceptance expectations against the new short-only build.

Preserved expectations include extended descriptor advertising, PKE body staging,
all USB packet splits, malformed Lc/Le, release-before-crypto, and the 2000 ms
receive-gap deadline. The deadline was part of that implementation. Current
short and discarded RX drain indefinitely until their declared length or an
explicit USB lifecycle reset. The 500 ms processing extension is retained.

Current replacement tests require bounded extended APDUs to return 6700 and
oversized CCID requests to drain before bError01. Accepted extended vectors
move to the real NFC facade, with finite Le, retransmit and reset checks.
