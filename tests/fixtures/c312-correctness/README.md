# Correctness decisions with unchanged wire expectations

Generate with `tests/support/c312_correctness_vectors.py`. The134 cases reuse
the exact operations, fixture states, schedules and expected bytes from five
historical USB suites. Only difference metadata changes. The historical input
vectors/reports remain untouched; all seventeen unequal cases stay unequal.

[Current decisions](../../../docs/sync/c312-correctness-decisions.md) retain
Rust response/channel isolation, fresh PIN retries and USB request validation.
Independent descriptor storage remains an intentional implementation difference.
The paired report executes pinned C and current Rust again; every C/Rust output
array must also match its original suite's archived report. Passing independent
expectations does not add these cases to parity totals or approve physical tests.

Run `c312-correctness-wire` for Rust CI, or `tests/support/c312_ccid.py` with
this directory's vectors and a separate pinned C checkout for paired execution.
E63 WTX retry/cache policy remains outside these decisions.
