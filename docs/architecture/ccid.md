# Shared CCID short-APDU card contract

CanoKey and vLEI use `canokey_transport_runtime::ccid::ShortApdu`, including
card identity, slot/control-envelope validation, automatic voltage selection,
read-only parameters, success bError and logical slot activation. Their ingress
backing and asynchronous application execution remain separate capabilities.
Only main-loop execution may enter an application. Invalid streamed headers
must fail before reserving its input owner. Power commands and USB reset revoke
selection and authentication; a short APDU may activate the logical slot without
restoring either authority.

GetParameters returns `11 10 00 65 00 fe 00` (hexadecimal): Fi/Di,
T=1 direct convention/checksum, guard time, BWI/CWI, clock stop, IFSC and NAD
(CCID 1.1 section 6.1.8). BWI6/CWI5 and IFSC254 agree with ATR TB3/TA3.
At the descriptor's 4 MHz clock, ISO 7816-3 gives BWT approximately 5.715 s,
longer than the common 500 ms CCID time-extension interval.

This deliberately corrects pinned C 3.1.2's `11 10 00 15 00 fe 00` parameters.
BWI1 gives BWT approximately 180 ms, expiring before that extension interval.
The ATR and descriptor remain unchanged for CanoKey. The three archived input
cases that query parameters during HID/WebUSB ownership retain literal C
expectations in `expected_ccid_c` and literal corrected Rust expectations in
`expected_ccid`. Their explicit intentional differences link this decision and
are excluded from C/Rust wire-parity totals. Saved historical reports remain
unchanged. No response normalization or broad exception is applied.

The two ingress strategies still differ in first-header fragmentation, trailing
bytes and receive deadline. These remain open convergence work; a shared card
policy alone does not establish complete CCID behavioral parity or physical
USB/timing acceptance.
