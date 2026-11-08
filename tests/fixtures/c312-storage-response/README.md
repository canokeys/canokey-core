# C 3.1.2 response-file faults

The report executes 114 pinned-C and 144 Rust checks through actual CCID,
WebUSB, native HID MSG/CBOR and NFC facades. Classical/PQ MakeCredential and
largeBlob responses run on all five transports; U2F registration runs on
CCID, WebUSB, native MSG and NFC.
Rust additionally exercises ML-DSA-44. These are independent contract checks,
separate from literal equal-byte comparisons and their unresolved-case counts.

Each case schedules one negative, zero-byte or one-byte read at the first or
second matching certificate/largeBlob read. It checks that the fault was
consumed at a recorded offset and requested length, retains raw output, probes
GET RESPONSE before any replacement command, then verifies a complete recovery
response with independent CBOR, blob bytes or attestation/signature checks.
Failed ISO chunks contain no data and return 6900; native HID returns ERROR7F.
Earlier successfully transmitted chunks remain visible in the raw trace.

The separate C build renames only fs.c's read_file symbol and forwards normal
reads to that unchanged implementation. A host adapter injects errors/short
reads after writing actual data or a poisoned unused suffix. Production C
files and transport/applet code remain unchanged. Rust injects at the test
Storage capability: read_at stays exact-or-error; read_some_at preserves the
actual native prefix count for ISO U2F registration. Unreported suffix bytes
are poisoned. This is not a physical LittleFS or native-backend fault run.

Three NFC U2F cases now match the C partial-progress contract: zero
certificate bytes with an already copied registration prefix, or one byte at
either read position, can be followed by successful reads and a valid complete
signature. Rust also returns only the actual prefix and retries the remainder.
The original differing outcomes remain archived in the response-file-fault
checkpoint; the preceding runner fails the current success expectation.
Negative reads or zero total progress still close the source with6900.

USB U2F uses ordinary presence polling with bounded retries. The
[extended NFC companion](../c312-storage-response-nfc-extended/README.md)
adds response aggregation and R-block retries during file-read faults.
All file offsets/certificate lengths, cancellation, withheld endpoint
completion, physical RF/storage failures and CIU resources remain outside this
checkpoint. No authorization bypass is used to extend the U2F coverage.

See the [testing guide](../../../docs/testing/README.md) for reproduction.
