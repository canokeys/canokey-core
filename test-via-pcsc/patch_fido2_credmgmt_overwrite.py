#!/usr/bin/env python3
# Patch the pinned fido2-tests credMgmt random stress test to model WebAuthn
# resident-key overwrite semantics in its local oracle.

from pathlib import Path
import sys


path = Path(sys.argv[1])
text = path.read_text()
if "user_keys = {}" in text:
    raise SystemExit(0)

replacements = [
    (
        "        reg = None\n"
        "        regs = {}\n",
        "        reg = None\n"
        "        user_keys = {}\n"
        "        regs = {}\n",
    ),
    (
        "                    reg = device.sendMC(*req.toMC())\n"
        "                    regs[reg.auth_data.credential_data.credential_id] = req.user['id']\n"
        "                    print(\"CREATE: \", hexlify(reg.auth_data.credential_data.credential_id))\n",
        "                    reg = device.sendMC(*req.toMC())\n"
        "                    cred_id = reg.auth_data.credential_data.credential_id\n"
        "                    rp_user = (bytes(reg.auth_data.rp_id_hash), bytes(req.user['id']))\n"
        "                    old_cred_id = user_keys.get(rp_user)\n"
        "                    if old_cred_id is not None:\n"
        "                        # WebAuthn requires a new resident credential for the\n"
        "                        # same RP and account ID to overwrite the old one.\n"
        "                        # Keep the test oracle aligned with that device state.\n"
        "                        regs.pop(old_cred_id, None)\n"
        "                    user_keys[rp_user] = cred_id\n"
        "                    regs[cred_id] = rp_user\n"
        "                    print(\"CREATE: \", hexlify(cred_id))\n",
    ),
    (
        "                CredMgmt.pin_uv_token = _get_pin_token_with_CM_permission(device)\n"
        "                CredMgmt.delete_cred(cred)\n"
        "                del regs[to_be_del]\n",
        "                CredMgmt.pin_uv_token = _get_pin_token_with_CM_permission(device)\n"
        "                rp_user = regs[to_be_del]\n"
        "                CredMgmt.delete_cred(cred)\n"
        "                user_keys.pop(rp_user, None)\n"
        "                del regs[to_be_del]\n",
    ),
    (
        "                assert cred_id in regs\n"
        "                assert user_id == regs[cred_id]\n"
        "                del regs[cred_id]\n",
        "                assert cred_id in regs\n"
        "                rp_user = regs[cred_id]\n"
        "                assert user_id == rp_user[1]\n"
        "                del regs[cred_id]\n"
        "                user_keys.pop(rp_user, None)\n",
    ),
]

for old, new in replacements:
    if old not in text:
        raise SystemExit(f"expected fido2 credMgmt test snippet not found in {path}")
    text = text.replace(old, new, 1)

path.write_text(text)
