# Deferred registration: draft artifact revalidation

Implementation `91b1f711` changes two targets already listed in the C 3.1.2
draft: `crates/core/src/applets/ctap/{mod,applet}.rs`. Their current identities
are updated to keep the draft structurally inspectable. This grants no source
hunk, behavior, physical or release approval. Existing evidence keeps its
original scope and revision; all earlier remaining items are preserved.

The common registration engine now returns an unpublished capability after
create/stage/response construction. Core retains one nonzero record ID and
finishes publication after command dispatch returns. Classic signing completes
during dispatch; PQ public hashing, attestation and reopen happen before commit
in completion. Both stages remain in the serialized transport execution guard.
Failed or abandoned work discards staging and response backing once. Uncertain
publication never authorizes deleting the destination.

| Draft behavior | Effect of the reviewed source change | Acceptance still required |
| --- | --- | --- |
| G6 | Request constants, GetInfo encoding and transport admission remain unchanged. Session entry cancels an abandoned publication before workspace reuse. | Existing request-path stack/PKE/RF and current-consumer revalidation. |
| C2 | Parsing, unknown-value budgets and request fields remain unchanged. The retained continuation owns no request/source/PKE loan. Replacement cancels its stage and erases backing. | Broader source-fault/error-order and paired transport cancellation schedules. |
| C3 | Completion prepares generated PQ output before publication; failure closes the primitive and erases backing. Existing segmented/file reads and largeBlob processing are unchanged. | Existing response/storage fault, execution cancellation, Linux and physical/resource revalidation. |
| T16 | Source classification, 250-byte APDU chunks and Le handling remain unchanged. Completed generated output becomes externally readable only after commit succeeds. | Existing wider source/fault schedules and physical/resource revalidation. |
| T17 | Native MSG buffered/source dispatch in message.rs is unchanged. Session replacement additionally consumes abandoned publication. | Existing buffered error/constant, cancellation and physical/resource revalidation. |
| T18 | U2F signing, certificate-prefix reads and native exact-read rules remain unchanged. Closing a prior CTAP publication cannot expose its old response. | Existing broader file/IRQ/cancellation and physical/CIU revalidation. |

Local validation includes 275 all-applet Core tests, 275 restricted-algorithm
Core tests, 158 shared CTAP streaming/schema tests, supported profiles and
transport matrices. The registration tests exercise classic and both ML-DSA
algorithms, new/existing groups, primitive/commit failures, uncertain commit,
and close/reset/replacement before completion. The native host run passes all
56 distinct CTests after correcting one stale copied test assertion. Those
results do not renew the historical draft behavior acceptance.

Both ordinary CIU boards link with unchanged RAM spans. The new command/PQ
phase separation still needs complete exact-ELF context, ROM and IRQ stack
review, plus hardware acceptance. No firmware was flashed.
