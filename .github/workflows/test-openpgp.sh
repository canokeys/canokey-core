#!/bin/bash
# OpenPGP applet integration tests
# Called from tests.yml with `script -e -c` for TTY support
set -e
set -o pipefail
set -o xtrace

dump_gpg_diagnostics() {
  local rc=$?
  trap - ERR
  set +e
  set +x
  echo "=== OpenPGP CI diagnostics (exit=${rc}) ==="
  echo "--- gpgconf --list-dirs ---"
  gpgconf --list-dirs || true
  echo "--- gpg --version ---"
  gpg --version || true
  echo "--- gpg-connect-agent: serialno ---"
  gpg-connect-agent 'SCD GETATTR SERIALNO' /bye || true
  echo "--- gpg-connect-agent: learn ---"
  gpg-connect-agent 'SCD LEARN --force' /bye || true
  echo "--- gpg --card-status ---"
  gpg --card-status || true
  echo "--- gpg -K --with-colons ---"
  gpg -K --with-colons || true
  echo "--- gpg -K --with-keygrip ---"
  gpg -K --with-keygrip || true
  echo "--- ~/.gnupg/gpg-agent.conf ---"
  cat ~/.gnupg/gpg-agent.conf || true
  echo "--- ~/.gnupg/scdaemon.conf ---"
  cat ~/.gnupg/scdaemon.conf || true
  echo "--- /tmp/canokey-test-gpg-agent.log ---"
  tail -n 200 /tmp/canokey-test-gpg-agent.log || true
  echo "--- /tmp/canokey-test-scd.log ---"
  tail -n 200 /tmp/canokey-test-scd.log || true
  echo "--- /tmp/pcscd.log ---"
  tail -n 200 /tmp/pcscd.log || true
  exit "${rc}"
}

trap 'dump_gpg_diagnostics' ERR

CardRefresh() {
  gpg-connect-agent 'SCD LEARN --force' /bye >/dev/null || true
  gpg --card-status >/dev/null || true
}

echo "=== Phase: Go unit tests ==="
go test -v test-via-pcsc/openpgp_test.go

echo "=== Phase: Setup GPG environment ==="
pkill gpg-agent || true
pkill scdaemon || true
mkdir -p ~/.gnupg
chmod 700 ~/.gnupg
cat >~/.gnupg/gpg-agent.conf <<'EOF'
enable-ssh-support
debug 1031
debug-level 8
log-file /tmp/canokey-test-gpg-agent.log
EOF
cat >~/.gnupg/scdaemon.conf <<'EOF'
pcsc-driver /usr/lib/x86_64-linux-gnu/libpcsclite.so.1
disable-ccid
debug 6145
log-file /tmp/canokey-test-scd.log
EOF
gpgconf --kill gpg-agent || true
gpgconf --kill scdaemon || true
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
Addkey() { echo -e "addkey\n$1\n$2\n0\nsave" | gpg_alias --edit-key $KEYID; }
LatestSubkey() {
  local cap=$1
  gpg -K --with-colons | awk -F: -v cap="$cap" '$1=="ssb" && $12 ~ cap {id=$5} END {if (id != "") print id}'
}
LatestAddedSubkey() {
  gpg -K --with-colons | awk -F: '$1=="ssb" {id=$5} END {if (id != "") print id}'
}
LatestSubkeyGrip() {
  local cap=$1
  gpg -K --with-colons | awk -F: -v cap="$cap" '$1=="ssb" && $12 ~ cap {want=NR+2} NR==want {grip=$10} END {if (grip != "") print grip}'
}
Key2card() {
  local subkey=$1
  local slot=$2
  [ -n "$subkey" ]
  echo -e "key $subkey\nkeytocard\n$slot\nsave" | gpg_alias --edit-key $KEYID
  CardRefresh
}
Key2cardLatest() { Key2card "$(LatestSubkey "$1")" "$2"; }
Addcardkey() { echo -e "addcardkey\n$1\n0\nsave\n" | gpg_alias --edit-key $KEYID; }
ChangeUsage() {
  SUBKEY=$(LatestSubkey 'a')
  echo -e "key $SUBKEY\nchange-usage\nS\nQ\ncross-certify\nsave" | gpg_alias --edit-key $KEYID
}
GPGSign() { CardRefresh; date -Iseconds | gpg --armor --default-key "$(LatestSubkey 's')"! -s | gpg; }
GPGEnc()  { CardRefresh; date -Iseconds | gpg --yes --armor --recipient "$(LatestSubkey 'e')" --encrypt | gpg; }
GPGAuth() {
  CardRefresh
  LatestSubkeyGrip 'a' >~/.gnupg/sshcontrol
  ssh-add -L >~/.ssh/authorized_keys
}
SetUIF() { echo -e "admin\nuif $1 $2\nq" | gpg_alias --edit-card; }
UserChecked() { cnt=$((`cat /tmp/canokey-test-up`)); echo 0 >/tmp/canokey-test-up; [ $1 == $cnt ]; }
GPGReset() { echo -e 'admin\nfactory-reset\ny\nyes' | gpg_alias --edit-card; CardRefresh; }

echo "=== Phase: Initial card setup (PIN change, ECC P-256 key import) ==="
echo 0 >/tmp/canokey-test-up && echo 0 >/tmp/canokey-test-nfc
gpg --card-status | grep -E 'UIF setting.+Sign=off Decrypt=off Auth=off'
echo -e 'admin\npasswd\n1\n3\n4\nq\nforcesig\nq' | gpg_alias --edit-card
Key2cardLatest 's' 1
echo 0 >/tmp/canokey-test-up
GPGSign
UserChecked 0

echo "=== Phase: UIF tests ==="
SetUIF 1 on
gpg --card-status | grep -E 'UIF setting.+Sign=on Decrypt=off Auth=off'
GPGSign
UserChecked 1
Addkey 12 3
Key2card "$(LatestAddedSubkey)" 2
Addkey 10 3
Key2card "$(LatestAddedSubkey)" 3
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
Addkey 4 2048
Key2card "$(LatestAddedSubkey)" 3
Addkey 6 2048
Key2card "$(LatestAddedSubkey)" 2
GPGAuth
GPGEnc
Addkey 10 3
Key2card "$(LatestAddedSubkey)" 1
GPGSign

echo "=== Phase: ED25519/CV25519 key import ==="
GPGReset
Addkey 12 1
Key2card "$(LatestAddedSubkey)" 2
Addkey 10 1
Key2card "$(LatestAddedSubkey)" 3
GPGAuth
GPGEnc
Addkey 10 1
Key2card "$(LatestAddedSubkey)" 1
GPGSign

echo "=== Phase: RSA-4096 key import ==="
GPGReset
Addkey 4 4096
Key2card "$(LatestAddedSubkey)" 3
Addkey 6 4096
Key2card "$(LatestAddedSubkey)" 2
GPGAuth
GPGEnc
Addkey 4 4096
Key2card "$(LatestAddedSubkey)" 1
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
ChangeUsage
GPGAuth

echo "=== Phase: ED25519 on-card generation ==="
GPGReset
echo -e 'admin\nkey-attr\n2\n1\n2\n1\n2\n1\n' | gpg_alias --edit-card
Addcardkey 1
Addcardkey 2
GPGEnc
GPGSign
Addcardkey 3
ChangeUsage
GPGAuth

echo "=== Phase: NIST P-256 on-card generation + cert write/read ==="
GPGReset
echo -e 'admin\nkey-attr\n2\n3\n2\n3\n2\n3\n' | gpg_alias --edit-card
Addcardkey 1
Addcardkey 2
GPGEnc
GPGSign
Addcardkey 3
ChangeUsage
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
ChangeUsage
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
ChangeUsage
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
ChangeUsage
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
