<!-- SPDX-License-Identifier: Apache-2.0 -->
# Safe TLV length primitives

Allocation-free `no_std` length decoding used by `protocol/tlv.rs`. No C ABI,
platform dependencies or applet code. Streaming tag/value handling belongs to
the common protocol crate.
