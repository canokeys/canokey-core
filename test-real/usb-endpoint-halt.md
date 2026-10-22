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
even if it was not previously halted. Invalid endpoint/request validation is
not covered by this test.
