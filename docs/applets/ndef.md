# NDEF

CanoKey exposes an NFC Forum Type 4 NDEF application. The factory default
permits reads and writes without authentication, as on a writable Type 4 tag.
A nearby reader can replace the URI with a phishing link, and repeated writes
consume Flash endurance.

The NDEF file is 1024 bytes, including the two-byte big-endian message length.
Storage keeps only the written prefix; bytes past it read as zero. A write that
starts past the prefix first extends it with zeros in 256-byte chunks, so an
interrupted write leaves only bytes that already read as zero. Records written
by earlier firmware at the full 1024 bytes remain valid unchanged.
The Capability Container's read and write access bytes are at offsets 13 and
14. A value of `0x00` permits access without authentication. A value of
`0xff` denies the corresponding access.

With ADMIN and NDEF enabled in the build, select ADMIN and verify its PIN in
the same session. Send ADMIN INS `0x08` without a data field, using
P1 `0x01` and P2 `0x00` to make NDEF read-only. P1 `0x00` restores
write access. The command changes only the write access byte.

Factory reset restores the default writable Capability Container and the
initial HTTPS URI for `canokeys.org`.
