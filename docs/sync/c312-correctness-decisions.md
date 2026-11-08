# Correctness decisions against C 3.1.2

C is a comparison target, not an authority for invalid protocol behavior.
Preserve these Rust behaviors rather than reproducing defects or unnecessary
resource coupling. These decisions close the five named wire-disposition
questions; they do not grant source-hunk, physical or resource acceptance.

| ID | Decision and independent invariant |
| --- | --- |
| L8 | VERSION must return its own version result, and an invalid native GET RESPONSE must report its error. A retained GetInfo generator must not replace either reply or advance because an unrelated command failed. Retain Rust response isolation. |
| C1-RETRIES | A fresh authenticator starts with eight PIN retries. A filesystem missing-attribute error is not a retry count and must not be serialized as negative retries. Retain Rust's eight. |
| CID1 | A response continuation belongs to its producing HID channel. Foreign GET RESPONSE must return busy and leave the owner's exact next byte intact. Never reproduce C's disclosure or transfer ownership after refused foreign traffic. |
| U3 | USB endpoint GET_STATUS uses wValue zero, reserved/high wIndex bits zero and wLength two. Reject malformed requests rather than submitting two bytes for a contradictory request. |
| U4 | A valid descriptor request may be answered from separate bounded control storage while an APDU response is pending. Retain that response and its exact next byte. C's shared-buffer refusal is an implementation limitation, not a behavior Rust needs to introduce. This is a valid implementation difference, distinct from the protocol/isolation defects above. |

The original five fixture directories retain their historical `unresolved`
metadata and reports unchanged. `c312-correctness` copies their same operations,
fixture states and literal C/Rust expected bytes, adding these current decisions.
Its seventeen unequal cases remain unequal and excluded from parity claims.
The generator changes only difference metadata; the paired report executes
the actual pinned C and current Rust transports again.

NFC WTX is separate. Do not send an APDU after deselect or treat an incorrect
WTX multiplier as a matching echo just because C continues. Retain cancellation
and reply-turn checks. ISO-DEP retry/cache policy for R-blocks while awaiting
WTX, the mixed cache/cleanup/TXEN source delta and physical timing remain open;
these USB decisions do not close E63 or declare Rust's entire WTX policy final.
