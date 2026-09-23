#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Independent SM2 arithmetic and GM/T 0003.5 vectors for PIV APDU tests.

Derived from the CIU reference used to verify the mask-ROM key exchange; no
production crypto implementation is called by these expected-result functions.
"""
import hashlib

P = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
A = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
B = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
GX = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
GY = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0
N = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
G = (GX, GY)

ID_DEFAULT = b"1234567812345678"

# GM/T 0003.5-2012 Annex A vector (klen=128)
V_DA = bytes.fromhex("81EB26E941BB5AF16DF116495F90695272AE2CD63D6C4AE1678418BE48230029")
V_PA = bytes.fromhex(
    "160E12897DF4EDB61DD812FEB96748FBD3CCF4FFE26AA6F6DB9540AF49C94232"
    "4A7DAD08BB9A459531694BEB20AA489D6649975E1BFCF8C4741B78B4B223007F")
V_RA = bytes.fromhex("D4DE15474DB74D06491C440D305E012400990F3E390C7E87153C12DB2EA60BB3")
V_EA = bytes.fromhex(
    "64CED1BDBC99D590049B434D0FD73428CF608A5DB8FE5CE07F15026940BAE40E"
    "376629C7AB21E7DB260922499DDB118F07CE8EAAE3E7720AFEF6A5CC062070C0")
V_DB = bytes.fromhex("785129917D45A9EA5437A59356B82338EAADDA6CEB199088F14AE10DEFA229B5")
V_PB = bytes.fromhex(
    "6AE848C57C53C7B1B5FA99EB2286AF078BA64C64591B8B566F7357D576F16DFB"
    "EE489D771621A27B36C5C7992062E9CD09A9264386F3FBEA54DFF69305621C4D")
V_RB = bytes.fromhex("7E07124814B309489125EAED101113164EBF0F3458C5BD88335C1F9D596243D6")
V_EB = bytes.fromhex(
    "ACC27688A6F7B706098BC91FF3AD1BFF7DC2802CDB14CCCCDB0A90471F9BD707"
    "2FEDAC0494B2FFC4D6853876C79B8F301C6573AD0AA50F39FC87181E1A1B46FE")
V_ZA = bytes.fromhex("3B85A57179E11E7E513AA622991F2CA74D1807A0BD4D4B38F90987A17AC245B1")
V_ZB = bytes.fromhex("79C988D63229D97EF19FE02CA1056E01E6A7411ED24694AA8F834F4A4AB022F7")
V_KEY16 = bytes.fromhex("6C89347354DE2484C60B4AB1FDE4C6E5")


def sm3(data: bytes) -> bytes:
    h = hashlib.new("sm3")
    h.update(data)
    return h.digest()


def point_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2:
        if (y1 + y2) % P == 0:
            return None
        lam = (3 * x1 * x1 + A) * pow(2 * y1, P - 2, P) % P
    else:
        lam = (y2 - y1) * pow((x2 - x1) % P, P - 2, P) % P
    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)


def point_mul(k, p):
    r = None
    while k:
        if k & 1:
            r = point_add(r, p)
        p = point_add(p, p)
        k >>= 1
    return r


def b2i(b):
    return int.from_bytes(b, "big")


def i2b(x, n=32):
    return x.to_bytes(n, "big")


def on_curve(pub: bytes) -> bool:
    x, y = b2i(pub[:32]), b2i(pub[32:])
    if not (0 <= x < P and 0 <= y < P):
        return False
    return (y * y - (x * x * x + A * x + B)) % P == 0


def sm2_z(id_bytes: bytes, pub: bytes) -> bytes:
    entl = (len(id_bytes) * 8).to_bytes(2, "big")
    return sm3(entl + id_bytes + i2b(A) + i2b(B) + i2b(GX) + i2b(GY) + pub)


def bar(x_bytes: bytes, w: int, force_top: bool) -> int:
    """GM/T 0003.2 6.1: 2^w + (x & (2^w - 1)); variants for ROM analysis."""
    if w == 127:
        low = b2i(x_bytes[16:]) & ((1 << 127) - 1)
    elif w == 128:
        low = b2i(x_bytes[16:])
    else:
        raise ValueError(w)
    return (1 << w) | low if force_top else low


def kdf(xs: bytes, ys: bytes, za: bytes, zb: bytes, out_len: int, counter: str) -> bytes:
    out = b""
    ct0 = 0 if counter.endswith("@0") else 1
    mode = counter.split("@")[0]
    ct = ct0
    while len(out) < out_len:
        if mode == "be32":
            data = xs + ys + za + zb + ct.to_bytes(4, "big")
        elif mode == "le32":
            data = xs + ys + za + zb + ct.to_bytes(4, "little")
        elif mode == "none":  # single block, no counter
            data = xs + ys + za + zb
        elif mode == "xy-only":  # legacy SM2 KDF without Z
            data = xs + ys + ct.to_bytes(4, "big")
        else:
            raise ValueError(counter)
        out += sm3(data)
        ct += 1
        if mode == "none":
            break
    return out[:out_len]


def key_exchange_full(role, id_self, id_peer, d_self, pub_self, r_self_bytes, eph_self_pub,
                      peer_static_pub, peer_eph_pub, out_len,
                      w=127, force_top=True, counter="be32", zswap=False):
    xbar = bar(eph_self_pub[:32], w, force_top)
    ybar = bar(peer_eph_pub[:32], w, force_top)
    t = (b2i(d_self) + xbar * b2i(r_self_bytes)) % N
    if t == 0:
        return None
    u = point_add((b2i(peer_static_pub[:32]), b2i(peer_static_pub[32:])),
                  point_mul(ybar, (b2i(peer_eph_pub[:32]), b2i(peer_eph_pub[32:]))))
    if u is None:
        return None
    s = point_mul(t, u)
    if s is None:
        return None
    xs, ys = i2b(s[0]), i2b(s[1])
    z_self = sm2_z(id_self, pub_self)
    z_peer = sm2_z(id_peer, peer_static_pub)
    za, zb = (z_self, z_peer) if role == 0 else (z_peer, z_self)
    if zswap:
        za, zb = zb, za
    return kdf(xs, ys, za, zb, out_len, counter), xs, ys
