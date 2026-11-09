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

Both ingress strategies now reassemble the ten-byte header and reject bytes
beyond dwLength with BAD_LENGTH, retaining the shared slot/control error
precedence. CCID 1.1 section 6 defines the message header, not a complete-header
first-packet restriction; section 5.2.1 even permits an eight-byte endpoint.
The chosen receiver accepts split headers without treating their prefix as
permission to claim another transport's workspace.

After the complete bounded XfrBlock header validates, Backend::admit runs once.
CanoKey checks HID and WebUSB ownership there; a fragmented header cannot bypass
or perform this admission early. Refusal stays latched while the declared body
drains. Buffered receive does not dispatch an application; streaming begin/feed
can reserve and parse the product's existing input owner. Power still validates
its entire envelope before its separate slot_power admission.

The shared local receive deadline is 2000 ms, using wrapping u32 arrival ticks;
it is not a timeout mandated by CCID. Partial headers expire silently because
no response slot/sequence is known. A valid partial body that expires loses its
RX backing and execution permission, but its declared bytes still drain before
one BAD_LENGTH reply. Rejected/refused envelopes retain CanoKey's complete-drain
rule; they have no application input owner to revoke. Late body bytes must
never become independently executable power/APDU headers. USB reset aborts the
drain. No new request/response allocation is introduced: the buffered owner adds
one four-byte clock; streaming moves its existing clock to Transport. Only
successful streaming begin authorizes a timeout to cancel its provisional input
through Backend::abort_input. This capability must preserve selected applets and
their PIN/token authority; it does not advance the card-session generation.
Envelope errors with a live input use the same cancellation. Backend::reset is
reserved for card power and transport reset. Buffered ingress never lent that
input owner and does not invoke the cancellation capability.

SELECT AID collection and P2 admission are shared with the APDU runtime through
frame::Selection. An unmatchable name is drained before final rejection; P2
errors precede name matching. Only a completely validated SELECT can change
selection. The same selected applet retains its grants. Rejected USB SELECT
revokes FIDO only; NFC retains its selection and unfinished FIDO command prefix.
Provisional frame cancellation preserves selection and authority. Streaming
input/response backing preservation still needs separate convergence: cancelling
a streamed frame may already have overwritten a logical prefix or closed its
response before the outer CCID envelope was complete.

Both USB facades process the mailbox arrival tick before checking current loop
time. This accepts a continuation that arrived before the deadline even if the
loop runs later. Presence progress remains a transport-only bodyless slot-status
path: it never expires a session or consumes power/APDU packets.

The archived short-header recovery inputs retain literal C expectations in
expected_c and intentional Rust differences linked here. Separate successful
fragmentation and WebUSB completion inputs establish actual reassembly and
ownership revocation; these are excluded from C/Rust wire-parity totals.
Historical reports remain unchanged. Physical USB/timing acceptance and the
CanoKey complete product stack/resource gates remain open.
