# USB endpoint halt regression

Run `python3 test-real/test-usb-endpoint-halt.py` with PyUSB/libusb and
python-fido2 installed, exactly one CanoKey attached, and applications using
the key closed. The test temporarily halts CTAPHID IN endpoint 0x82 and clears
it in cleanup, including after a failed assertion. It does not alter credentials.

Standard SET_FEATURE/CLEAR_FEATURE(ENDPOINT_HALT) requests must complete their
EP0 status stage without being forwarded to HID Setup. GET_STATUS returns the
two literal USB little-endian bytes `01 00` when halted and `00 00` otherwise,
including on big-endian platforms. The test also clears an unhalted endpoint,
then verifies CTAPHID PING and CTAP2 GetInfo after recovery.

This checks host-observable transfers and recovery. A USB analyzer is needed
to confirm that clearing halt resets the endpoint's next DATA packet to DATA0,
even if it was not previously halted.

Invalid requests must STALL EP0 without changing endpoint 0x82's halt state.
The test checks both SET and CLEAR while 0x82 is halted and unhalted, including
reserved wIndex high bytes, endpoint zero, out-of-range/reserved addresses,
unsupported feature values, incorrect direction and nonzero length.

Endpoint membership is captured when the composite class opens its endpoints
at SET_CONFIGURATION, separately for IN and OUT. It is cleared on class
deinitialization. Only endpoints opened in this configuration may be halted;
changing a persistent interface setting does not change that membership until
reconfiguration.

For absent in-range endpoint coverage, build with an interface disabled (for
example `ENABLE_IFACE_KBDHID=OFF`) and run with `--require-absent-endpoint`.
The test derives absent addresses from the active configuration descriptor.
Without this flag, it reports a skip when every in-range endpoint is present.
Restore the ordinary firmware after testing a reduced-interface image.

Run `python3 test/usb-endpoint/run.py` for device-independent regression tests.
It compiles the actual control-request source with mocked low-level calls,
checking both SET and CLEAR, endpoint direction/membership, malformed fields,
unconfigured states, little-endian bytes and absence of unintended changes.

On macOS, malformed CLEAR_FEATURE requests are skipped in the hardware test:
observed host API results do not reliably reflect the device's rejection
(the high-byte-invalid CLEAR returned success while the analogous SET stalled).
Use the native test for both handler branches; use Linux or a USB analyzer to
validate malformed CLEAR on the wire. Timeouts and other host errors never
count as successful protocol rejection.
