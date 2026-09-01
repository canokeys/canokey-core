#!/usr/bin/env python3
"""Generate pre-encoded CBOR segments for ctap_get_info response.

Usage:
  python3 gen_ctap_get_info.py \
    --headers ctap-internal.h ctaphid.h \
    --credential-id-size 70 \
    --enable-nfc 1 \
    --output ctap_get_info_cbor.inc

The script parses #define constants directly from header files.
Missing constants cause a hard error (no defaults).

Output segments (concatenated at runtime in C):
  1. cbor_gi_prefix[]     — map header through algorithms key (0x0A)
  2. cbor_gi_alg_base[]   — ES256 + EdDSA algorithm entries
  3. cbor_gi_alg_sm2[]    — SM2 algorithm entry (conditional)
  4. cbor_gi_suffix[]     — remaining fields after algorithms

Dynamic patches at runtime:
  - clientPin boolean (1 byte in prefix)
  - SM2 algo_id (1–2 bytes in SM2 entry)
  - algorithms array header (1 byte, 0x82 or 0x83)
"""

import argparse
import re
import struct
import sys


# --- Parse #define from C headers ---

def parse_defines(header_paths, needed):
    """Parse integer #define values from C headers.
    
    Args:
        header_paths: list of header file paths to scan
        needed: dict of {name: None} — filled in with parsed values
    
    Returns dict {name: int_value}. Raises if any needed key is missing.
    """
    # Match: #define NAME value  (decimal, hex, negative, or simple alias)
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


# --- Minimal CBOR encoder (no dependencies) ---

def encode_uint(n):
    if n <= 23:
        return bytes([n])
    elif n <= 0xFF:
        return bytes([0x18, n])
    elif n <= 0xFFFF:
        return bytes([0x19, (n >> 8) & 0xFF, n & 0xFF])
    elif n <= 0xFFFFFFFF:
        return struct.pack('>BI', 0x1A, n)
    else:
        return struct.pack('>BQ', 0x1B, n)


def encode_int(n):
    if n >= 0:
        return encode_uint(n)
    # Negative: major type 1, value = -1 - n
    v = -1 - n
    if v <= 23:
        return bytes([0x20 | v])
    elif v <= 0xFF:
        return bytes([0x38, v])
    elif v <= 0xFFFF:
        return bytes([0x39, (v >> 8) & 0xFF, v & 0xFF])
    else:
        raise ValueError(f"Negative int too large: {n}")


def encode_text(s):
    b = s.encode('utf-8')
    if len(b) <= 23:
        return bytes([0x60 | len(b)]) + b
    elif len(b) <= 0xFF:
        return bytes([0x78, len(b)]) + b
    else:
        return bytes([0x79, (len(b) >> 8) & 0xFF, len(b) & 0xFF]) + b


def encode_bytes(b):
    if len(b) <= 23:
        return bytes([0x40 | len(b)]) + b
    elif len(b) <= 0xFF:
        return bytes([0x58, len(b)]) + b
    else:
        return bytes([0x59, (len(b) >> 8) & 0xFF, len(b) & 0xFF]) + b


def encode_bool(v):
    return bytes([0xF5 if v else 0xF4])


def encode_array_header(n):
    return bytes([0x80 | n]) if n <= 23 else bytes([0x98, n])


def encode_map_header(n):
    return bytes([0xA0 | n]) if n <= 23 else bytes([0xB8, n])


# --- Constants ---

GI_VERSIONS = 0x01
GI_EXTENSIONS = 0x02
GI_AAGUID = 0x03
GI_OPTIONS = 0x04
GI_MAX_MSG_SIZE = 0x05
GI_PIN_UV_AUTH_PROTOCOLS = 0x06
GI_MAX_CREDENTIAL_COUNT = 0x07
GI_MAX_CREDENTIAL_ID_LENGTH = 0x08
GI_TRANSPORTS = 0x09
GI_ALGORITHMS = 0x0A
GI_MAX_SERIALIZED_LARGE_BLOB = 0x0B
GI_FIRMWARE_VERSION = 0x0E
GI_MAX_CRED_BLOB_LENGTH = 0x0F

COSE_ALG_ES256 = -7
COSE_ALG_EDDSA = -8
COSE_ALG_ML_DSA_65 = -49

AAGUID = bytes([0x24, 0x4e, 0xb2, 0x9e, 0xe0, 0x90, 0x4e, 0x49,
                0x81, 0xfe, 0x1f, 0x20, 0xf8, 0xd3, 0xb8, 0xf4])


def build_algorithm_entry(alg_id):
    return (encode_map_header(2) +
            encode_text("alg") + encode_int(alg_id) +
            encode_text("type") + encode_text("public-key"))


def parse_bool(value):
    normalized = value.lower()
    if normalized in ("1", "on", "true", "yes"):
        return True
    if normalized in ("0", "off", "false", "no"):
        return False
    raise argparse.ArgumentTypeError(f"invalid boolean value: {value}")


def build_segments(consts, sm2_algo_id, enable_nfc):
    """Build the four CBOR segments.
    
    Returns (prefix, alg_base, alg_sm2, suffix, client_pin_offset, sm2_algo_offset).
    """
    # --- Segment 1: prefix (map header through algorithms key) ---
    prefix = bytearray()

    # Top-level map: 13 entries
    prefix += encode_map_header(13)

    # 1. versions
    prefix += encode_uint(GI_VERSIONS)
    prefix += encode_array_header(3)
    prefix += encode_text("U2F_V2")
    prefix += encode_text("FIDO_2_0")
    prefix += encode_text("FIDO_2_1")

    # 2. extensions
    prefix += encode_uint(GI_EXTENSIONS)
    prefix += encode_array_header(4)
    prefix += encode_text("credBlob")
    prefix += encode_text("credProtect")
    prefix += encode_text("hmac-secret")
    prefix += encode_text("largeBlobKey")

    # 3. aaguid
    prefix += encode_uint(GI_AAGUID)
    prefix += encode_bytes(AAGUID)

    # 4. options
    prefix += encode_uint(GI_OPTIONS)
    prefix += encode_map_header(6)
    prefix += encode_text("rk") + encode_bool(True)
    prefix += encode_text("credMgmt") + encode_bool(True)
    prefix += encode_text("clientPin")
    client_pin_offset = len(prefix)
    prefix += encode_bool(False)  # patched at runtime
    prefix += encode_text("largeBlobs") + encode_bool(True)
    prefix += encode_text("pinUvAuthToken") + encode_bool(True)
    prefix += encode_text("makeCredUvNotRqd") + encode_bool(True)

    # 5. maxMsgSize
    prefix += encode_uint(GI_MAX_MSG_SIZE)
    prefix += encode_uint(consts['MAX_CTAP_BUFSIZE'])

    # 6. pinUvAuthProtocols
    prefix += encode_uint(GI_PIN_UV_AUTH_PROTOCOLS)
    prefix += encode_array_header(2)
    prefix += encode_uint(1)
    prefix += encode_uint(2)

    # 7. maxCredentialCountInList
    prefix += encode_uint(GI_MAX_CREDENTIAL_COUNT)
    prefix += encode_uint(consts['MAX_CREDENTIAL_COUNT_IN_LIST'])

    # 8. maxCredentialIdLength
    prefix += encode_uint(GI_MAX_CREDENTIAL_ID_LENGTH)
    prefix += encode_uint(consts['CREDENTIAL_ID_SIZE'])

    # 9. transports
    prefix += encode_uint(GI_TRANSPORTS)
    prefix += encode_array_header(2 if enable_nfc else 1)
    if enable_nfc:
        prefix += encode_text("nfc")
    prefix += encode_text("usb")

    # 10. algorithms key only (array header emitted at runtime)
    prefix += encode_uint(GI_ALGORITHMS)

    # --- Segment 2: base algorithm entries (ES256 + EdDSA + ML-DSA-65) ---
    alg_base = bytearray()
    alg_base += build_algorithm_entry(COSE_ALG_ES256)
    alg_base += build_algorithm_entry(COSE_ALG_EDDSA)
    alg_base += build_algorithm_entry(COSE_ALG_ML_DSA_65)

    # --- Segment 3: SM2 algorithm entry ---
    alg_sm2 = bytearray()
    alg_sm2_entry = build_algorithm_entry(sm2_algo_id)
    # Find the algo_id byte offset within this entry
    # Entry: map(2){text("alg"), int(algo_id), text("type"), text("public-key")}
    # map_header(1) + text("alg")(4) = 5 bytes, then the int encoding
    sm2_algo_offset = 1 + len(encode_text("alg"))
    alg_sm2 += alg_sm2_entry

    # --- Segment 4: suffix (remaining fields) ---
    suffix = bytearray()

    # 11. maxSerializedLargeBlobArray
    suffix += encode_uint(GI_MAX_SERIALIZED_LARGE_BLOB)
    suffix += encode_uint(consts['LARGE_BLOB_SIZE_LIMIT'])

    # 12. firmwareVersion
    suffix += encode_uint(GI_FIRMWARE_VERSION)
    suffix += encode_uint(consts['FIRMWARE_VERSION'])

    # 13. maxCredBlobLength
    suffix += encode_uint(GI_MAX_CRED_BLOB_LENGTH)
    suffix += encode_uint(consts['MAX_CRED_BLOB_LENGTH'])

    return (bytes(prefix), bytes(alg_base), bytes(alg_sm2), bytes(suffix),
            client_pin_offset, sm2_algo_offset)


def format_c_array(data):
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_str = ", ".join(f"0x{b:02X}" for b in chunk)
        lines.append(f"  {hex_str},")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Generate CBOR segments for ctap_get_info")
    parser.add_argument("--headers", nargs="+", required=True,
                        help="C header files to parse for #define constants")
    parser.add_argument("--credential-id-size", type=int, required=True,
                        help="sizeof(credential_id) — not a #define, passed from CMake")
    parser.add_argument("--enable-nfc", type=parse_bool, required=True,
                        help="whether the target includes the NFC transport")
    parser.add_argument("--sm2-algo-id", type=int, default=-48)
    parser.add_argument("--output", type=str, required=True)
    args = parser.parse_args()

    # Constants we need from headers
    needed = {
        'FIRMWARE_VERSION': None,
        'CTAP_MAX_MSG_SIZE': None,
        'MAX_CREDENTIAL_COUNT_IN_LIST': None,
        'LARGE_BLOB_SIZE_LIMIT': None,
        'MAX_CRED_BLOB_LENGTH': None,
    }
    consts = parse_defines(args.headers, needed)
    consts['MAX_CTAP_BUFSIZE'] = consts['CTAP_MAX_MSG_SIZE']
    consts['CREDENTIAL_ID_SIZE'] = args.credential_id_size

    prefix, alg_base, alg_sm2, suffix, pin_off, sm2_algo_off = \
        build_segments(consts, args.sm2_algo_id, args.enable_nfc)

    total_no_sm2 = len(prefix) + 1 + len(alg_base) + len(suffix)
    total_sm2 = len(prefix) + 1 + len(alg_base) + len(alg_sm2) + len(suffix)

    with open(args.output, 'w') as f:
        f.write("// Auto-generated by scripts/gen_ctap_get_info.py — DO NOT EDIT\n")
        f.write("// Re-generate: cmake reconfigure (constants parsed from headers)\n")
        f.write("//\n")
        f.write(f"// Parsed constants:\n")
        for k, v in sorted(consts.items()):
            f.write(f"//   {k} = {v}\n")
        f.write(f"//   enable_nfc = {int(args.enable_nfc)}\n")
        f.write(f"//   sm2_algo_id = {args.sm2_algo_id} (default, patched at runtime)\n")
        f.write(f"//\n")
        f.write(f"// Total response size: {total_no_sm2} bytes (no SM2), "
                f"{total_sm2} bytes (with SM2)\n\n")

        f.write(f"// Byte offset of clientPin boolean within cbor_gi_prefix\n")
        f.write(f"#define CTAP_GI_CLIENT_PIN_OFFSET {pin_off}\n")
        f.write(f"// Byte offset of SM2 algo_id within cbor_gi_alg_sm2\n")
        f.write(f"#define CTAP_GI_SM2_ALGO_OFFSET {sm2_algo_off}\n")
        f.write(f"// SM2 algo_id encoding length in default template\n")
        # Record the encoding length of the default algo_id by locating where the
        # \"type\" text key starts after the integer encoding.
        from_offset = sm2_algo_off
        # Find where "type" text starts after the int
        type_text = encode_text("type")
        type_pos = alg_sm2.index(bytes(type_text), from_offset)
        default_algo_enc_len = type_pos - from_offset
        f.write(f"#define CTAP_GI_SM2_ALGO_ENC_LEN {default_algo_enc_len}\n\n")

        f.write(f"// Segment 1: map header through algorithms key ({len(prefix)} bytes)\n")
        f.write(f"// clientPin boolean is at offset {pin_off}\n")
        f.write(f"static const uint8_t cbor_gi_prefix[{len(prefix)}] = {{\n")
        f.write(format_c_array(prefix))
        f.write(f"\n}};\n\n")

        f.write(f"// Segment 2: ES256 + EdDSA + ML-DSA-65 algorithm entries ({len(alg_base)} bytes)\n")
        f.write(f"static const uint8_t cbor_gi_alg_base[{len(alg_base)}] = {{\n")
        f.write(format_c_array(alg_base))
        f.write(f"\n}};\n\n")

        f.write(f"// Segment 3: SM2 algorithm entry ({len(alg_sm2)} bytes)\n")
        f.write(f"// algo_id at offset {sm2_algo_off}, {default_algo_enc_len} byte(s)\n")
        f.write(f"static const uint8_t cbor_gi_alg_sm2[{len(alg_sm2)}] = {{\n")
        f.write(format_c_array(alg_sm2))
        f.write(f"\n}};\n\n")

        f.write(f"// Segment 4: remaining fields after algorithms ({len(suffix)} bytes)\n")
        f.write(f"static const uint8_t cbor_gi_suffix[{len(suffix)}] = {{\n")
        f.write(format_c_array(suffix))
        f.write(f"\n}};\n")

    print(f"Generated {args.output}:")
    print(f"  prefix:   {len(prefix)} bytes (clientPin at offset {pin_off})")
    print(f"  alg_base: {len(alg_base)} bytes")
    print(f"  alg_sm2:  {len(alg_sm2)} bytes (algo_id at offset {sm2_algo_off})")
    print(f"  suffix:   {len(suffix)} bytes")
    print(f"  Total:    {total_no_sm2} / {total_sm2} bytes (no SM2 / SM2)")
    print(f"  Constants parsed from: {', '.join(args.headers)}")


if __name__ == "__main__":
    main()
