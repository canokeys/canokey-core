#!/usr/bin/env python3
"""Generate pre-encoded CBOR segments for authenticatorGetInfo.

The generated file intentionally contains only static CTAP GetInfo bytes.
Runtime code adds status and dynamic fields such as clientPin, alwaysUv,
minPinLength, remainingDiscoverableCredentials, and SM2 algorithm id.
"""

import argparse
import re
import struct
import sys


def parse_defines(header_paths, needed):
    pattern = re.compile(r'^\s*#define\s+(\w+)\s+(-?(?:0[xX][0-9a-fA-F]+|\d+)|\w+)\b')
    raw = {}
    for path in header_paths:
        with open(path) as f:
            for line in f:
                m = pattern.match(line)
                if m:
                    raw[m.group(1)] = m.group(2)

    def resolve(name, seen=None):
        if seen is None:
            seen = set()
        if name in seen or name not in raw:
            return None
        seen.add(name)
        val_str = raw[name]
        if re.match(r'-?(?:0[xX][0-9a-fA-F]+|\d+)$', val_str):
            return int(val_str, 0)
        return resolve(val_str, seen)

    found = {}
    for name in needed:
        value = resolve(name)
        if value is not None:
            found[name] = value

    missing = [k for k in needed if k not in found]
    if missing:
        print(f"ERROR: missing #define constants: {', '.join(missing)}", file=sys.stderr)
        print(f"  Searched in: {', '.join(header_paths)}", file=sys.stderr)
        sys.exit(1)

    return found


def encode_uint(n):
    if n < 0:
        raise ValueError(f"negative uint: {n}")
    if n <= 23:
        return bytes([n])
    if n <= 0xFF:
        return bytes([0x18, n])
    if n <= 0xFFFF:
        return bytes([0x19, (n >> 8) & 0xFF, n & 0xFF])
    if n <= 0xFFFFFFFF:
        return struct.pack('>BI', 0x1A, n)
    return struct.pack('>BQ', 0x1B, n)


def encode_int(n):
    if n >= 0:
        return encode_uint(n)
    v = -1 - n
    if v <= 23:
        return bytes([0x20 | v])
    if v <= 0xFF:
        return bytes([0x38, v])
    if v <= 0xFFFF:
        return bytes([0x39, (v >> 8) & 0xFF, v & 0xFF])
    if v <= 0xFFFFFFFF:
        return struct.pack('>BI', 0x3A, v)
    return struct.pack('>BQ', 0x3B, v)


def encode_text(s):
    b = s.encode('utf-8')
    if len(b) <= 23:
        return bytes([0x60 | len(b)]) + b
    if len(b) <= 0xFF:
        return bytes([0x78, len(b)]) + b
    return bytes([0x79, (len(b) >> 8) & 0xFF, len(b) & 0xFF]) + b


def encode_bytes(b):
    if len(b) <= 23:
        return bytes([0x40 | len(b)]) + b
    if len(b) <= 0xFF:
        return bytes([0x58, len(b)]) + b
    return bytes([0x59, (len(b) >> 8) & 0xFF, len(b) & 0xFF]) + b


def encode_bool(v):
    return bytes([0xF5 if v else 0xF4])


def encode_array_header(n):
    if n <= 23:
        return bytes([0x80 | n])
    return bytes([0x98, n])


def encode_map_header(n):
    if n <= 23:
        return bytes([0xA0 | n])
    return bytes([0xB8, n])


AAGUID = bytes([0x24, 0x4E, 0xB2, 0x9E, 0xE0, 0x90, 0x4E, 0x49,
                0x81, 0xFE, 0x1F, 0x20, 0xF8, 0xD3, 0xB8, 0xF4])


def algorithm_entry(alg_id):
    return (encode_map_header(2) +
            encode_text("alg") + encode_int(alg_id) +
            encode_text("type") + encode_text("public-key"))


def split_at_placeholder(data, placeholder):
    pos = data.index(placeholder)
    before = data[:pos]
    after = data[pos + len(placeholder):]
    return before, after


def build_segments(c):
    segments = {}

    versions_u2f = (encode_array_header(4) + encode_text("U2F_V2") +
                    encode_text("FIDO_2_0") + encode_text("FIDO_2_1") + encode_text("FIDO_2_3"))
    versions_no_u2f = (encode_array_header(3) +
                       encode_text("FIDO_2_0") + encode_text("FIDO_2_1") + encode_text("FIDO_2_3"))

    segments["cbor_gi_prefix_before_versions"] = encode_map_header(21) + encode_uint(c['GI_RESP_VERSIONS'])
    segments["cbor_gi_prefix_before_versions_force"] = encode_map_header(22) + encode_uint(c['GI_RESP_VERSIONS'])
    segments["cbor_gi_versions_with_u2f"] = versions_u2f
    segments["cbor_gi_versions_without_u2f"] = versions_no_u2f

    after_versions = bytearray()
    after_versions += encode_uint(c['GI_RESP_EXTENSIONS'])
    after_versions += encode_array_header(7)
    for ext in ["credBlob", "credProtect", "hmac-secret", "hmac-secret-mc",
                "largeBlobKey", "minPinLength", "thirdPartyPayment"]:
        after_versions += encode_text(ext)

    after_versions += encode_uint(c['GI_RESP_AAGUID'])
    after_versions += encode_bytes(AAGUID)

    after_versions += encode_uint(c['GI_RESP_OPTIONS'])
    after_versions += encode_map_header(9)
    after_versions += encode_text("rk") + encode_bool(True)
    after_versions += encode_text("alwaysUv")
    always_uv_marker = b'\xF0ALWAYSUV'
    after_versions += always_uv_marker
    after_versions += encode_text("credMgmt") + encode_bool(True)
    after_versions += encode_text("authnrCfg") + encode_bool(True)
    after_versions += encode_text("clientPin")
    client_pin_marker = b'\xF0CLIENTPIN'
    after_versions += client_pin_marker
    after_versions += encode_text("largeBlobs") + encode_bool(True)
    after_versions += encode_text("pinUvAuthToken") + encode_bool(True)
    after_versions += encode_text("setMinPINLength") + encode_bool(True)
    after_versions += encode_text("makeCredUvNotRqd")
    make_cred_uv_not_rqd_marker = b'\xF0MAKECRED'
    after_versions += make_cred_uv_not_rqd_marker

    after_versions += encode_uint(c['GI_RESP_MAX_MSG_SIZE'])
    # CTAP_MAX_MSG_SIZE may depend on platform ABI/compiler flags via
    # MAX_CTAP_BUFSIZE, so runtime C code patches it instead of baking the
    # generator host's value into this static segment.
    max_msg_size_marker = b'\xF0MAXMSG'
    after_versions += max_msg_size_marker
    after_versions += encode_uint(c['GI_RESP_PIN_UV_AUTH_PROTOCOLS'])
    after_versions += encode_array_header(2) + encode_uint(1) + encode_uint(2)
    after_versions += encode_uint(c['GI_RESP_MAX_CREDENTIAL_COUNT_IN_LIST'])
    after_versions += encode_uint(c['MAX_CREDENTIAL_COUNT_IN_LIST'])
    after_versions += encode_uint(c['GI_RESP_MAX_CREDENTIAL_ID_LENGTH'])
    after_versions += encode_uint(c['CREDENTIAL_ID_SIZE'])
    after_versions += encode_uint(c['GI_RESP_TRANSPORTS'])
    after_versions += encode_array_header(2) + encode_text("nfc") + encode_text("usb")
    after_versions += encode_uint(c['GI_RESP_ALGORITHMS'])
    after_versions += encode_array_header(4)
    after_versions += algorithm_entry(c['COSE_ALG_ES256'])
    after_versions += algorithm_entry(c['COSE_ALG_EDDSA'])
    after_versions += algorithm_entry(c['COSE_ALG_ML_DSA_65'])
    sm2_marker = b'\xF0SM2ALG'
    sm2_entry = encode_map_header(2) + encode_text("alg") + sm2_marker + encode_text("type") + encode_text("public-key")
    after_versions += sm2_entry

    chunks = [("cbor_gi_after_versions", bytes(after_versions))]
    markers = [
        (always_uv_marker, "always_uv"),
        (client_pin_marker, "client_pin"),
        (make_cred_uv_not_rqd_marker, "make_cred_uv_not_rqd"),
        (max_msg_size_marker, "max_msg_size"),
        (sm2_marker, "sm2_alg"),
    ]
    for marker, name in markers:
        next_chunks = []
        for chunk_name, chunk_data in chunks:
            if marker in chunk_data:
                before, after = split_at_placeholder(chunk_data, marker)
                next_chunks.append((chunk_name + "_before_" + name, before))
                segments[name + "_placeholder"] = b""
                next_chunks.append(("cbor_gi_after_" + name, after))
            else:
                next_chunks.append((chunk_name, chunk_data))
        chunks = next_chunks
    for name, data in chunks:
        segments[name] = data

    segments["cbor_gi_force_pin_change_entry"] = encode_uint(c['GI_RESP_FORCE_PIN_CHANGE']) + encode_bool(True)

    suffix = bytearray()
    suffix += encode_uint(c['GI_RESP_MAX_SERIALIZED_LARGE_BLOB_ARRAY'])
    suffix += encode_uint(c['LARGE_BLOB_SIZE_LIMIT'])
    suffix += encode_uint(c['GI_RESP_MIN_PIN_LENGTH'])
    min_pin_marker = b'\xF0MINPIN'
    suffix += min_pin_marker
    suffix += encode_uint(c['GI_RESP_FIRMWARE_VERSION'])
    suffix += encode_uint(c['FIRMWARE_VERSION'])
    suffix += encode_uint(c['GI_RESP_MAX_CRED_BLOB_LENGTH'])
    suffix += encode_uint(c['MAX_CRED_BLOB_LENGTH'])
    suffix += encode_uint(c['GI_RESP_MAX_RPIDS_FOR_SET_MIN_PIN_LENGTH'])
    suffix += encode_uint(c['CTAP_MAX_RPIDS_FOR_SET_MIN_PIN_LENGTH'])
    suffix += encode_uint(c['GI_RESP_REMAINING_DISCOVERABLE_CREDENTIALS'])
    remaining_marker = b'\xF0REMAINING'
    suffix += remaining_marker
    suffix += encode_uint(c['GI_RESP_ATTESTATION_FORMATS'])
    suffix += encode_array_header(1) + encode_text("packed")
    suffix += encode_uint(c['GI_RESP_LONG_TOUCH_FOR_RESET'])
    long_touch_marker = b'\xF0LONGTOUCH'
    suffix += long_touch_marker
    suffix += encode_uint(c['GI_RESP_TRANSPORTS_FOR_RESET'])
    suffix += encode_array_header(2) + encode_text("nfc") + encode_text("usb")
    suffix += encode_uint(c['GI_RESP_MAX_PIN_LENGTH'])
    max_pin_marker = b'\xF0MAXPIN'
    suffix += max_pin_marker
    suffix += encode_uint(c['GI_RESP_AUTHENTICATOR_CONFIG_COMMANDS'])
    suffix += encode_array_header(3)
    suffix += encode_uint(c['CONFIG_CMD_TOGGLE_ALWAYS_UV'])
    suffix += encode_uint(c['CONFIG_CMD_SET_MIN_PIN_LENGTH'])
    suffix += encode_uint(c['CONFIG_CMD_ENABLE_LONG_TOUCH_FOR_RESET'])

    chunks = [("cbor_gi_suffix", bytes(suffix))]
    for marker, name in [
        (min_pin_marker, "min_pin_length"),
        (remaining_marker, "remaining_discoverable_credentials"),
        (long_touch_marker, "long_touch_for_reset"),
        (max_pin_marker, "max_pin_length"),
    ]:
        next_chunks = []
        for chunk_name, chunk_data in chunks:
            if marker in chunk_data:
                before, after = split_at_placeholder(chunk_data, marker)
                next_chunks.append((chunk_name + "_before_" + name, before))
                segments[name + "_placeholder"] = b""
                next_chunks.append(("cbor_gi_suffix_after_" + name, after))
            else:
                next_chunks.append((chunk_name, chunk_data))
        chunks = next_chunks
    for name, data in chunks:
        segments[name] = data

    return segments


def format_c_array(data):
    if not data:
        return ""
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        lines.append("  " + ", ".join(f"0x{b:02x}" for b in chunk) + ",")
    return "\n".join(lines)


def write_array(f, name, data):
    f.write(f"static const uint8_t {name}[{len(data)}] = {{\n")
    body = format_c_array(data)
    if body:
        f.write(body + "\n")
    f.write("};\n\n")


def main():
    parser = argparse.ArgumentParser(description="Generate const CBOR segments for CTAP GetInfo")
    parser.add_argument("--headers", nargs="+", required=True)
    parser.add_argument("--credential-id-size", type=int, required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    needed = {
        'GI_RESP_VERSIONS': None,
        'GI_RESP_EXTENSIONS': None,
        'GI_RESP_AAGUID': None,
        'GI_RESP_OPTIONS': None,
        'GI_RESP_MAX_MSG_SIZE': None,
        'GI_RESP_PIN_UV_AUTH_PROTOCOLS': None,
        'GI_RESP_MAX_CREDENTIAL_COUNT_IN_LIST': None,
        'GI_RESP_MAX_CREDENTIAL_ID_LENGTH': None,
        'GI_RESP_TRANSPORTS': None,
        'GI_RESP_ALGORITHMS': None,
        'GI_RESP_MAX_SERIALIZED_LARGE_BLOB_ARRAY': None,
        'GI_RESP_FORCE_PIN_CHANGE': None,
        'GI_RESP_MIN_PIN_LENGTH': None,
        'GI_RESP_FIRMWARE_VERSION': None,
        'GI_RESP_MAX_CRED_BLOB_LENGTH': None,
        'GI_RESP_MAX_RPIDS_FOR_SET_MIN_PIN_LENGTH': None,
        'GI_RESP_REMAINING_DISCOVERABLE_CREDENTIALS': None,
        'GI_RESP_ATTESTATION_FORMATS': None,
        'GI_RESP_LONG_TOUCH_FOR_RESET': None,
        'GI_RESP_TRANSPORTS_FOR_RESET': None,
        'GI_RESP_MAX_PIN_LENGTH': None,
        'GI_RESP_AUTHENTICATOR_CONFIG_COMMANDS': None,
        'MAX_CREDENTIAL_COUNT_IN_LIST': None,
        'LARGE_BLOB_SIZE_LIMIT': None,
        'MAX_CRED_BLOB_LENGTH': None,
        'CTAP_MAX_RPIDS_FOR_SET_MIN_PIN_LENGTH': None,
        'FIRMWARE_VERSION': None,
        'COSE_ALG_ES256': None,
        'COSE_ALG_EDDSA': None,
        'COSE_ALG_ML_DSA_65': None,
        'CONFIG_CMD_TOGGLE_ALWAYS_UV': None,
        'CONFIG_CMD_SET_MIN_PIN_LENGTH': None,
        'CONFIG_CMD_ENABLE_LONG_TOUCH_FOR_RESET': None,
    }
    consts = parse_defines(args.headers, needed)
    consts['CREDENTIAL_ID_SIZE'] = args.credential_id_size

    segments = build_segments(consts)
    with open(args.output, 'w') as f:
        f.write("// Auto-generated by scripts/gen_ctap_get_info.py. DO NOT EDIT.\n")
        f.write("// Static CTAP GetInfo CBOR segments; dynamic fields are inserted at runtime.\n\n")
        for key in sorted(consts):
            f.write(f"// {key} = {consts[key]}\n")
        f.write("\n")
        for name, data in segments.items():
            if name.endswith("_placeholder"):
                continue
            write_array(f, name, data)

    total_static = sum(len(v) for k, v in segments.items() if not k.endswith("_placeholder"))
    print(f"Generated {args.output}: {total_static} static bytes in {len([k for k in segments if not k.endswith('_placeholder')])} segments")


if __name__ == "__main__":
    main()
