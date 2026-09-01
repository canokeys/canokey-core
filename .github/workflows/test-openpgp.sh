#!/bin/bash
# OpenPGP applet integration tests
# Called from tests.yml with `script -e -c` for TTY support
set -e
set -o xtrace

echo "=== Phase: Go unit tests ==="
go test -v test-via-pcsc/openpgp_test.go

echo "=== Phase: Setup GPG environment ==="
pkill gpg-agent || true
export SSH_AUTH_SOCK=$(gpgconf --list-dirs agent-ssh-socket)
mkdir -p ~/.ssh /tmp/mock
python3 -c "import string;import random;print(''.join([random.choice(string.ascii_letters + string.digits) for n in range(1152)]),end='')" > /tmp/random.txt
echo 9876543210 >"/tmp/mock/Reset Code"
echo 12345678 >"/tmp/mock/Passphrase:"
echo 12345678 >"/tmp/mock/Admin PIN"
echo 123456 >"/tmp/mock/PIN"

echo "=== Phase: Generate master key ==="
echo -e 'Key-Type: 1\nKey-Length: 2048\nSubkey-Type: 1\nSubkey-Length: 2048\nName-Real: Someone\nName-Email: foo@example.com\nPassphrase: 12345678\n%commit\n%echo done' | gpg --batch --gen-key
KEYID=$(gpg -K --with-colons | grep -P '^sec' | grep -oP '\w{16}')

# Helper functions
gpg_alias () { gpg --yes --expert --command-fd 0 --status-fd 1 "$@"; }
gpg_auth_alias () { gpg --yes --expert --pinentry-mode loopback --passphrase 12345678 --command-fd 0 --status-fd 1 "$@"; }
Addkey() { echo -e "addkey\n$1\n$2\n0\nsave" | gpg_alias --edit-key $KEYID; }
AddECCAuthKey() { printf 'addkey\n11\nS\nA\nQ\n%s\n0\nsave\n' "$1" | gpg_auth_alias --edit-key "$KEYID"; }
AddRSAAuthKey() { printf 'addkey\n8\nS\nE\nA\nQ\n%s\n0\nsave\n' "$1" | gpg_auth_alias --edit-key "$KEYID"; }
Key2card() { echo -e "key $1\nkeytocard\n$2\nsave" | gpg_alias --edit-key $KEYID; gpg --card-status; }
Addcardkey() { echo -e "addcardkey\n$1\n0\nsave\n" | gpg_alias --edit-key $KEYID; }
GPGSign() { date -Iseconds | gpg --armor --default-key $(gpg -K --with-colons | awk -F: '$1~/ssb/ && $12~/s|a/ {print $5}' | tail -n 1)! -s | gpg; }
GPGEnc()  { date -Iseconds | gpg --yes --armor --recipient $(gpg -K --with-colons | awk -F: '$1~/ssb/ && $12~/e/ {print $5}' | tail -n 1) --encrypt | gpg; }
LatestSubkeyGrip() {
  local cap=$1
  local grip
  grip=$(gpg -K --with-colons --with-keygrip |
    awk -F: -v cap="$cap" '
      $1=="ssb" {want=($12 ~ cap)}
      want && $1=="grp" {grip=$10; want=0}
      END {if (grip != "") print grip}
    ')
  [ -n "$grip" ]
  printf '%s\n' "$grip"
}
GPGAuthList() {
  LatestSubkeyGrip 'a' >~/.gnupg/sshcontrol
  ssh-add -L >~/.ssh/authorized_keys
}
GPGAuth() {
  GPGAuthList
  ssh-add -T ~/.ssh/authorized_keys
}
SetUIF() { echo -e "admin\nuif $1 $2\nq" | gpg_alias --edit-card; }
UserChecked() { cnt=$((`cat /tmp/canokey-test-up`)); echo 0 >/tmp/canokey-test-up; [ $1 == $cnt ]; }
GPGReset() { echo -e 'admin\nfactory-reset\ny\nyes' | gpg_alias --edit-card; }

echo "=== Phase: Initial card setup (PIN change, ECC P-256 key import) ==="
echo 0 >/tmp/canokey-test-up && echo 0 >/tmp/canokey-test-nfc
gpg --card-status | grep -E 'UIF setting.+Sign=off Decrypt=off Auth=off'
echo -e 'admin\npasswd\n1\n3\n4\nq\nforcesig\nq' | gpg_alias --edit-card
Key2card 1 1
echo 0 >/tmp/canokey-test-up
GPGSign
UserChecked 0

echo "=== Phase: UIF tests ==="
SetUIF 1 on
gpg --card-status | grep -E 'UIF setting.+Sign=on Decrypt=off Auth=off'
GPGSign
UserChecked 1
Addkey 12 3
AddECCAuthKey 3
Key2card 2 2
Key2card 3 3
echo 0 >/tmp/canokey-test-up
GPGAuth
UserChecked 0
GPGEnc
UserChecked 0
SetUIF 2 on
gpg --card-status | grep -E 'UIF setting.+Sign=on Decrypt=on Auth=off'
GPGEnc
UserChecked 1
SetUIF 3 on
gpg --card-status | grep -E 'UIF setting.+Sign=on Decrypt=on Auth=on'
GPGAuth
UserChecked 1
SetUIF 1 off
gpg --card-status | grep -E 'UIF setting.+Sign=off Decrypt=on Auth=on'
SetUIF 2 off
gpg --card-status | grep -E 'UIF setting.+Sign=off Decrypt=off Auth=on'
SetUIF 3 off
gpg --card-status | grep -E 'UIF setting.+Sign=off Decrypt=off Auth=off'
echo 0 >/tmp/canokey-test-up
GPGEnc
UserChecked 0
SetUIF 1 permanent
gpg --card-status | grep -E 'UIF setting.+Sign=on Decrypt=off Auth=off'
SetUIF 2 permanent
gpg --card-status | grep -E 'UIF setting.+Sign=on Decrypt=on Auth=off'
SetUIF 3 permanent
gpg --card-status | grep -E 'UIF setting.+Sign=on Decrypt=on Auth=on'
SetUIF 3 off || true
SetUIF 2 off || true
SetUIF 1 off || true
gpg --card-status | grep -E 'UIF setting.+Sign=on Decrypt=on Auth=on'
GPGEnc
UserChecked 1
echo 1 >/tmp/canokey-test-nfc

echo "=== Phase: RSA-2048 key import ==="
GPGReset
gpg --card-status | grep -E 'Signature key.+none'
AddRSAAuthKey 2048
Key2card 4 3
Addkey 6 2048
Key2card 5 2
GPGAuth
GPGEnc
Addkey 10 3
Key2card 6 1
GPGSign

echo "=== Phase: ED25519/CV25519 key import ==="
GPGReset
Addkey 12 1
AddECCAuthKey 1
Key2card 7 2
Key2card 8 3
# GnuPG 2.4.4 rejects PureEdDSA smartcard SSH signing before PKAUTH.
# RSA/ECDSA scenarios still exercise authentication with ssh-add -T.
GPGAuthList
GPGEnc
Addkey 10 1
Key2card 9 1
GPGSign

echo "=== Phase: RSA-4096 key import ==="
GPGReset
AddRSAAuthKey 4096
Key2card 10 3
Addkey 6 4096
Key2card 11 2
GPGAuth
GPGEnc
Addkey 4 4096
Key2card 12 1
GPGSign

echo "=== Phase: RSA-2048 on-card generation ==="
GPGReset
echo -e 'admin\nkey-attr\n2\n1\n2\n1\n2\n1\n' | gpg_alias --edit-card
echo -e 'admin\nkey-attr\n1\n2048\n1\n2048\n1\n2048\n' | gpg_alias --edit-card
Addcardkey 1
Addcardkey 2
GPGEnc
GPGSign
Addcardkey 3
GPGAuth

echo "=== Phase: ED25519 on-card generation ==="
GPGReset
echo -e 'admin\nkey-attr\n2\n1\n2\n1\n2\n1\n' | gpg_alias --edit-card
Addcardkey 1
Addcardkey 2
GPGEnc
GPGSign
Addcardkey 3
GPGAuthList

echo "=== Phase: NIST P-256 on-card generation + cert write/read ==="
GPGReset
echo -e 'admin\nkey-attr\n2\n3\n2\n3\n2\n3\n' | gpg_alias --edit-card
Addcardkey 1
Addcardkey 2
GPGEnc
GPGSign
Addcardkey 3
GPGAuth
echo -e 'admin\nwritecert 3 </tmp/random.txt\nquit' | gpg_alias --edit-card
gpgconf --kill gpg-agent
echo -e 'readcert 3 >/tmp/random-read.txt\nquit' | gpg_alias --edit-card
diff /tmp/random-read.txt /tmp/random.txt

echo "=== Phase: NIST P-384 on-card generation + cert write/read ==="
GPGReset
echo -e 'admin\nkey-attr\n2\n4\n2\n4\n2\n4\n' | gpg_alias --edit-card
Addcardkey 1
Addcardkey 2
GPGEnc
GPGSign
Addcardkey 3
GPGAuth
echo -e 'admin\nwritecert 3 </tmp/random.txt\nquit' | gpg_alias --edit-card
gpgconf --kill gpg-agent
echo -e 'readcert 3 >/tmp/random-read.txt\nquit' | gpg_alias --edit-card
diff /tmp/random-read.txt /tmp/random.txt

echo "=== Phase: NIST P-521 on-card generation + cert write/read ==="
GPGReset
echo -e 'admin\nkey-attr\n2\n5\n2\n5\n2\n5\n' | gpg_alias --edit-card
Addcardkey 1
Addcardkey 2
GPGEnc
GPGSign
Addcardkey 3
GPGAuth
echo -e 'admin\nwritecert 3 </tmp/random.txt\nquit' | gpg_alias --edit-card
gpgconf --kill gpg-agent
echo -e 'readcert 3 >/tmp/random-read.txt\nquit' | gpg_alias --edit-card
diff /tmp/random-read.txt /tmp/random.txt

echo "=== Phase: secp256k1 on-card generation + cert write/read ==="
GPGReset
echo -e 'admin\nkey-attr\n2\n9\n2\n9\n2\n9\n' | gpg_alias --edit-card
Addcardkey 1
Addcardkey 2
GPGEnc
GPGSign
Addcardkey 3
echo -e 'admin\nwritecert 3 </tmp/random.txt\nquit' | gpg_alias --edit-card
gpgconf --kill gpg-agent
echo -e 'readcert 3 >/tmp/random-read.txt\nquit' | gpg_alias --edit-card
diff /tmp/random-read.txt /tmp/random.txt

echo "=== Phase: Fill card with data ==="
GPGReset
echo -e 'admin\nname\nTheFirstNameQQQQQQ\nTheLastNamePPPPPPPP\nlang\nlanguage\nsex\nm\nquit' | gpg_alias --edit-card
echo -e 'admin\nurl\nexample.com/111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111\nquit' | gpg_alias --edit-card
echo -e 'admin\nlogin\naaaaaaaaaaaa000000000000000000000001111111111111111122222222222\nquit' | gpg_alias --edit-card
echo -e 'admin\ncafpr 2\n9914 B3B0 BF7E 3B12 DB72  8AC7 3695 10EC DF14 672E\ncafpr 1\nEC17 49B4 C512 6CD3 080C  85CA 0088 068F 1016 5897\ncafpr 3\nAC4D DD51 6C35 D8E2 7153  BB3B 4BD8 4023 BC79 46F0\nquit' | gpg_alias --edit-card
gpgconf --kill gpg-agent

echo "=== Phase: OpenPGP cert Go tests ==="
go test -v test-via-pcsc/openpgp_test.go -run TestOpenPGPCerts

echo "=== All OpenPGP tests passed ==="
