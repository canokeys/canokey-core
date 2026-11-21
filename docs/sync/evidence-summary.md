# C312 evidence archive

The original captures, reviews and patches remain recoverable from Core
commit `884e68d4191cdbe0c157d6db271ec523ad52c508`. Each entry records the original path, SHA-256 and
scoped conclusion. Use `git show <commit>:<path>` to recover the bytes.
The manifest retains the behavior dispositions and source hunk mappings.

## auth-response-checkpoint.json

Host coverage established classification and buffered Le for the tested response cases. Broader file faults, cancellation, physical transport and resources remain open.

Original `docs/sync/evidence/auth-response-checkpoint.json`

SHA-256 `a39533f251ae757f31184c2948f9e5024f9b027ff24a3eec5e68fa5334855cc1`

## auth-response-source-review.json

Reviewed selected response classification and wire and crypto behavior. Review scope is limited to the mapped cases.

Original `docs/sync/evidence/auth-response-source-review.json`

SHA-256 `cf4bb34b7b101fcd878275a1d996d72cd951fe54d0cfdc8735e0e5f1e0e3af1d`

## chain-control-source-review.json

Preserved FIDO chains across response polling and rejected NFC SELECT. Malformed WebUSB fails before routing and empty CBOR APDUs return 6700. Full chain and physical review remain open.

Original `docs/sync/evidence/chain-control-source-review.json`

SHA-256 `fe20055530d5dab9139b9203241bc30adb410e92d00821c0049c2cd7fdf74dab`

## chain-encoding-source-review.json

Bounded WebUSB and NDEF chains continue across encodings. Extended NFC CLA 80/90 resets earlier FIDO input. Beyond the sampled encodings and failures, equivalence remains open.

Original `docs/sync/evidence/chain-encoding-source-review.json`

SHA-256 `944f20b9b8e94d86a66418ae88a7b51a6643f42bed9c1b3fe7acc79e64c4a502`

## cleanup-irq-source-review.json

Reviewed 22 specified cleanup units and exercised real Rust erasure IRQ injection. CAS, reset acquisition and broader concurrency and physical cases remain open.

Original `docs/sync/evidence/cleanup-irq-source-review.json`

SHA-256 `8c486e546be44894a9ce54e7033dfe8ec76e2983aa6a407f4eb9236962d03e25`

## ctap-parser-source-review.json

Reviewed 87 specified units for full RP matching, scratch/window behavior and cancellation. The emitted-response regression passed within its stated scope.

Original `docs/sync/evidence/ctap-parser-source-review.json`

SHA-256 `df7bc965af4bead6112e3ad0c58ffc1345ddd2713e95af16592f2ac75d9dfe43`

## hid-source-review.json

Mapped 32 units from seven CTAPHID diffs. L9 error ordering, CID1, L8, C1-RETRIES and physical acceptance remain open.

Original `docs/sync/evidence/hid-source-review.json`

SHA-256 `5525464d2d3cd07e31bc3d09b2d28d476b4affe42cb487fc389a4c4e415612e6`

## host-ctest.log

Historical host CTest checkpoint passed 42 of 42. This run covers the recorded host suite.

Original `docs/sync/evidence/host-ctest.log`

SHA-256 `4f94eab0a1ddf9c865bef05b07e987e821218e658796157c36aafa1f5d49776b`

## native-storage-progress-checkpoint.json

Native LittleFS APDU fixtures demonstrated prefix progress and exact whole-record loads. Additional native and physical fault coverage remains open.

Original `docs/sync/evidence/native-storage-progress-checkpoint.json`

SHA-256 `b3b902d7a0066f1eea1e7c6e2b9fb0d00102dec45919675693a0d75c3e524d3d`

## native-storage-progress-source-review.json

The native count-propagation repair was inspected and exercised. MCU execution and further I/O and cancellation schedules remain open.

Original `docs/sync/evidence/native-storage-progress-source-review.json`

SHA-256 `46a2e0311fe1a3215d4a7ba5ce8117dfaee9d7ddf9a27c75b0fe0844c869eca7`

## nfc-activation-source-review.json

Eight mapped source units cover coalesced HALT/ACTIVE and the silence mask. Mixed WTX/TXEN behavior and physical acceptance remain open.

Original `docs/sync/evidence/nfc-activation-source-review.json`

SHA-256 `5315482567575e9eed6eb99afd066ed91817f8a09584e4bf4dcd2a1072dfbb12`

## nfc-execution-source-review.json

Scheduled IRQ fixtures established pending-turn ownership and normal WTX. E63 wrong multiplier, ACK, NAK and deselect responses and the mixed WTX/cache/TXEN hunk remain unresolved.

Original `docs/sync/evidence/nfc-execution-source-review.json`

SHA-256 `e10812c6f0af7cdd568a1fcc04695530eeff8a1f3c4c5f941cf0669555764c36`

## nfc-mailbox-source-review.json

Overlapping pre-execution FIFO traffic drains while the accepted frame stays owned. Live-execution hunk 57 and WTX/IRQ interleavings remain open.

Original `docs/sync/evidence/nfc-mailbox-source-review.json`

SHA-256 `1b4b44fa6dcc9013878f8f908e1d136ba7434083392e0892e66bbe6cd00e23bd`

## nfc-rblock-source-review.json

Mapped 16 units for duplicate I-block ACK and ISO-DEP rules 12 and 13. Mixed caching/TXEN hunk 19 remains open.

Original `docs/sync/evidence/nfc-rblock-source-review.json`

SHA-256 `74f8c8909ea4e3b573ec0721dd0da6001a9d604ebc56b47e5584a77e43f0e68c`

## nfc-rejection-source-review.json

Tested staged prefix refusal and final malformed cleanup. Inline envelopes and additional cancellation and response-source cases remain open.

Original `docs/sync/evidence/nfc-rejection-source-review.json`

SHA-256 `19cef6832bfcd03334ee6edb5376c8b2584517760fde4f5af8d110441b2e717f`

## nfc-source-before.log

The old NFC source fixture reproduced dispatch after cancelled clear. The follow-up regression covers this failure.

Original `docs/sync/evidence/nfc-source-before.log`

SHA-256 `ca2b517d12cd87553bfa557709e2f5f6ac95ea01915a271bb21fb92debc8f767`

## nfc-source.json

Rust FIFO/IRQ fixture covers production dispatch with injected staging and erasure. Paired C schedules, other faults and physical coverage remain open.

Original `docs/sync/evidence/nfc-source.json`

SHA-256 `43afedd41da56f2a6ff7608b50451d98829bbfdd84e62cbb34b1bd26df8856e4`

## nfc-source.log

The NFC source fault test passed after the follow-up. The historical log records a separate pre-follow-up failure.

Original `docs/sync/evidence/nfc-source.log`

SHA-256 `57e6754fca355dcfad33577a9937ba0b3c1625736939112abe2a597734401bd3`

## nfc-state-rename.json

Established exact mechanical equivalence for the rename and its merge-parent delta. Earlier NFC behavior retains its own review scope.

Original `docs/sync/evidence/nfc-state-rename.json`

SHA-256 `27270f305b89b6c1a457d87c81d3b8975830e061deb94799c52d16532463c552`

## protocol-values-20261110.json

Moved the CTAP request-too-large constant to the shared status table. The emitted CTAP 0x39 and APDU 0x9000 remain unchanged.

Original `docs/sync/evidence/protocol-values-20261110.json`

SHA-256 `7b6a9a7a82eb5d9ee41e732f789f78c773b67f385bc6fe072c5bc11dff009ff1`

## response-stream-31e6788c-ctap.c.patch

Pinned implementation delta for response-source aliasing and cleanup, used in the source comparison.

Original `docs/sync/evidence/response-stream-31e6788c-ctap.c.patch`

SHA-256 `ccc1f2b3c0a6865ee29f671d7f15128c48bc428ce79fa87b1856ae273edeeb2c`

## response-stream-31e6788c-ctap.h.patch

Pinned declaration delta for the same response-source change, used in the source comparison.

Original `docs/sync/evidence/response-stream-31e6788c-ctap.h.patch`

SHA-256 `c4d6a8911e6bff1f9ab55c0585c89bcfda94baab5f7ec8b9d628bae3f633a48a`

## response-stream-836a50a5-ctap.c.patch

Pinned implementation delta for streamed input and file-backed largeBlob replies, used in the source comparison.

Original `docs/sync/evidence/response-stream-836a50a5-ctap.c.patch`

SHA-256 `7237c00b5ae1185037f74bb340ad6d3eed520340a4f6e334bd9dc252fc0c3ef9`

## response-stream-836a50a5-ctap.h.patch

Pinned declaration delta for the generic source contract, used in the source comparison.

Original `docs/sync/evidence/response-stream-836a50a5-ctap.h.patch`

SHA-256 `b5a35b2375974a2bd8d37bb9d04432553e1518e80b957372071a74bd5e713b1c`

## response-stream-a349b268-ctap.c.patch

Pinned merge-parent implementation delta. Its compared source changes match 31e6788c.

Original `docs/sync/evidence/response-stream-a349b268-ctap.c.patch`

SHA-256 `ccc1f2b3c0a6865ee29f671d7f15128c48bc428ce79fa87b1856ae273edeeb2c`

## response-stream-a349b268-ctap.h.patch

Pinned merge-parent declaration delta. Its compared source changes match 31e6788c.

Original `docs/sync/evidence/response-stream-a349b268-ctap.h.patch`

SHA-256 `c4d6a8911e6bff1f9ab55c0585c89bcfda94baab5f7ec8b9d628bae3f633a48a`

## response-stream-before.json

Exploratory differences preceded paired retesting. Initial chunk and fetch assumptions were superseded.

Original `docs/sync/evidence/response-stream-before.json`

SHA-256 `ff755f4748439e84cd8d4452da7aeee973c50bff305283a08c8c455eb43d08c6`

## response-stream-source-review.json

Compared pinned aliases, cleanup, largeBlob segmented output and merge deltas. Broader response classes, I/O faults and hardware remain open.

Original `docs/sync/evidence/response-stream-source-review.json`

SHA-256 `0420fd272ceb2d643d2c47818a5ebc928ca62643b35e6efd924ae1669de2b0ca`

## rom-review-20261108-narrow.json

Measured a behavior-preserving range-check rewrite on both products. NFCC was still oversized at that checkpoint.

Original `docs/sync/evidence/rom-review-20261108-narrow.json`

SHA-256 `fd44ef016ccec1a28381caa02213ba93317ced7e81985c797336067f25ec14b2`

## rom-review-20261108.json

Recorded ROM-only preservation checks. Source-unit review and hardware acceptance remain separate.

Original `docs/sync/evidence/rom-review-20261108.json`

SHA-256 `3e31f8b3954facd8915f6120e728feb917b2f4a3cbc54da924e875e4810905de`

## select-config-source-review.json

Tested disabled NDEF SELECT preserving ADMIN and NFC FIDO context while retaining USB FIDO cleanup. Wider SELECT and configuration transitions remain open.

Original `docs/sync/evidence/select-config-source-review.json`

SHA-256 `33f7e70c679065d63f193db4b62b10f993774ee6d034aee910e2bf6655415598`

## select-finalization-source-review.json

Tested draining oversized SELECT input before finalization while preserving context on malformed envelopes. Broader mutations and physical comparison remain open.

Original `docs/sync/evidence/select-finalization-source-review.json`

SHA-256 `e99eadb1a880a8555548f9abaf6e0555d4845e04dc401efd86d2623ef6514cde`

## select-header-source-review.json

Tested SELECT status and header handling, NDEF INS dispatch and terminal FIDO validation. Broader header and state mutations remain open.

Original `docs/sync/evidence/select-header-source-review.json`

SHA-256 `169e4e1340c6b5c76c88e711bcf85441eb8774b0513a475a8474f8518898f234`

## session-yield-checkpoint.json

Host evidence covers retained scratch admission and native HID borrowing across the sampled sessions. Unresolved wire behaviors and resource acceptance remain open.

Original `docs/sync/evidence/session-yield-checkpoint.json`

SHA-256 `101daee2ad30b444b3cd4dcbe3a69c8993d13d1aa50f5540e97e6c33ab1fa1d9`

## session-yield-source-review.json

Mapped exactly 16 source units from four deltas repeated across two commits. Endpoint, physical and additional continuation paths remain open.

Original `docs/sync/evidence/session-yield-source-review.json`

SHA-256 `59e2ac6f29702ed220195fdefab8e7cb7593f4fa27b35f6eb9c996c50acac253`

## source-review.json

Historical pinned-source and host checkpoint recorded 348 equal-output cases out of 365 paired cases and 17 unresolved cases. CID1, L8, C1-RETRIES, U3 and U4 retain separate dispositions.

Original `docs/sync/evidence/source-review.json`

SHA-256 `9eeefa2393f099c97f8171182aabcd621e7040522633e12fad9fad35ed1bbac1`

## storage-response-checkpoint.json

Host file faults established fail-closed response behavior and recovery in sampled cases. Native fault parity and T18 remain open.

Original `docs/sync/evidence/storage-response-checkpoint.json`

SHA-256 `d52936727d4b770daafb43883e76417dd0cd32784dd5d7c48698190ad9b9d9c6`

## storage-response-source-review.json

Compared file reads, response closure and recovery. Three T18/E58 NFC U2F short-read cases differed, with C signing and Rust failing closed. Disposition remains unresolved.

Original `docs/sync/evidence/storage-response-source-review.json`

SHA-256 `948fd9449fa8f665d301e6ee2797f51e7e5874d70e44aa7e49ec32fdb36e32c3`

## u2f-progress-checkpoint.json

ISO U2F response reads permit progress within the checked contract. Generic CTAP and native HID retain exact reads. Further native and physical checks remain open.

Original `docs/sync/evidence/u2f-progress-checkpoint.json`

SHA-256 `d83d78188dd4b6ac4f934221f9a04281259db7b4f6e86b0d7912ee06d6cb2bfd`

## u2f-progress-source-review.json

Mapped pinned U2F definitions to Rust capabilities. Native-backend faults and USB polling remain outside this review.

Original `docs/sync/evidence/u2f-progress-source-review.json`

SHA-256 `6f0f0355285d2b175b90d30c4d9dfb06a62059967e48b30ee5182f94150e59ba`

## usb-control-source-review.json

Reviewed 37 USB control and 54 descriptor units. U3 GET_STATUS, U4 busy descriptors and broader lifecycle and physical schedules remain open.

Original `docs/sync/evidence/usb-control-source-review.json`

SHA-256 `53203d837ed4c08eeebba3cfef969ebab1790b62171d1bb61aeef9904268c7c5`

## usb-lifecycle-source-review.json

Reviewed 41 source units and E49–E51 serialized schedules. Deferred service IRQ, pending native GET RESPONSE and physical behavior remain open.

Original `docs/sync/evidence/usb-lifecycle-source-review.json`

SHA-256 `2a13036534bc5261b1a92d502e4eb4fa65d47d971d6c06c030e998910c828054`

## usb-readiness-source-review.json

Reviewed 12 source units and executed actual C DataOut readiness checks. Stale acknowledgement coverage is a Rust model. L8/E53 and physical cases remain open.

Original `docs/sync/evidence/usb-readiness-source-review.json`

SHA-256 `bad0d2bc46194afda6f6cd91e4fc3f33ec43c1d161064d8e4096e2e13c4fb375`

## usb-u2f-polling-checkpoint.json

Host-only USB U2F sampling and deferred file faults were exercised. Native failures, physical sensor behavior and broader schedules remain open.

Original `docs/sync/evidence/usb-u2f-polling-checkpoint.json`

SHA-256 `8beec4c194ed39fb6034efa48ee23f2f2b2e0c744f46d55d7b9ea061883da610`

## usb-u2f-polling-source-review.json

Mapped presence provenance and transport behavior within the fixtures. Physical sensor timing and latch equivalence remain open.

Original `docs/sync/evidence/usb-u2f-polling-source-review.json`

SHA-256 `c1f2ad14c4253c6409e58635cdde06ee3956a28a23befd0630e69049265a1b5e`

## webusb-readiness-source-review.json

Reviewed two acquisition guard hunks and compared fresh-product readiness cases. Retained status and cleanup interruption remained separate.

Original `docs/sync/evidence/webusb-readiness-source-review.json`

SHA-256 `9cc35aeb236c894a79bba015b02f269ec791ff5171d8b6616102ea10f1b48341`

## webusb-retained-source-review.json

Reviewed two context clear/init hunks and exercised retained EP0 state. Other executing, IRQ, erasure and physical cases remain open.

Original `docs/sync/evidence/webusb-retained-source-review.json`

SHA-256 `beecfb93164f6498b9ed51c9029776cc2d177d65658def2e36f5523438b4f368`
