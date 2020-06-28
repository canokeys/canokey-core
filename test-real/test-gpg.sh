#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
export LANGUAGE=en_US
export LANG=en_US.UTF8
export GNUPGHOME="$(pwd)/temp_gnupg"
export SSHDIR="$(pwd)/temp_ssh"
GPG="gpg --command-fd 0 --yes --expert"
kEYID=""

oneTimeSetUp(){
    gpg --version
    rm -rf "$GNUPGHOME" "$SSHDIR"
    mkdir -p "$GNUPGHOME" "$SSHDIR"
    > "$SSHDIR/authorized_keys"
    chmod 700 "$GNUPGHOME" "$SSHDIR" "$SSHDIR/authorized_keys"

    ssh-keygen -t ecdsa -f "$SSHDIR/hostkey" -N ''
    cat >"$SSHDIR/sshd_config" <<EOF
StrictModes no
UsePAM no
UsePrivilegeSeparation no
HostKey $SSHDIR/hostkey
AuthorizedKeysFile $SSHDIR/authorized_keys
Port 22022
EOF

    cp pinentry-mock "$GNUPGHOME/"
    cat >"${GNUPGHOME}/gpg-agent.conf" <<EOF
pinentry-program ${GNUPGHOME}/pinentry-mock
enable-ssh-support
debug 1031
debug-level 8
log-file /tmp/canokey-test-gpg-agent.log
EOF
    echo "debug 6145" > "${GNUPGHOME}/scdaemon.conf"
    echo "log-file /tmp/canokey-test-scd.log" >> "${GNUPGHOME}/scdaemon.conf"
    # begin testing
    killall -u $USER sshd || true
    killall -u $USER -9 gpg-agent || true
    /usr/sbin/sshd -f "$SSHDIR/sshd_config" -E /tmp/canokey-test-sshd.log
    gpg --card-status # The first try may fail
    gpg --card-status || exit 1
    echo -e 'Key-Type: 1\nKey-Length: 2048\nSubkey-Type: 1\nSubkey-Length: 2048\nName-Real: Someone\nName-Email: foo@example.com\nPassphrase: 12345678\n%commit\n%echo done' | gpg --batch --gen-key -v
    export KEYID=$(gpg -K --with-colons |egrep '^sec'|egrep -o '\w{16}')
    echo 'Key Id is:' $KEYID
}

# utility functions

# generate key in gpg
Addkey() {
    echo -e "addkey\n$1\n$2\n0\nsave" | $GPG --edit-key $KEYID; 
    assertEquals 'Addkey failed' 0 $?
}

# generate key in card
Addcardkey() {
    echo -e "addcardkey\n$1\n0\nsave\n" | $GPG --edit-key $KEYID;
    assertEquals 'Addcardkey failed' 0 $?
}

# move key from gpg to card
Key2card() { 
    echo -e "key $1\nkeytocard\n$2\nsave" | $GPG --edit-key $KEYID;
    assertEquals 'Key2card failed' 0 $?
    gpg --card-status; 
}

# reset card
GPGReset() {
    echo -e 'admin\nfactory-reset\ny\nyes' | $GPG --edit-card;
    assertEquals 'GPG reset failed' 0 $?
}

# test signing
GPGSign() { 
    date -Iseconds | gpg --armor --default-key $(gpg -K --with-colons|awk -F: '$1~/ssb/ && $12~/s|a/ {print $5}'|tail -n 1)! -s|gpg; 
    assertEquals 'GPG sign failed' 0 $?
}

# test encryption
GPGEnc()  {
    date -Iseconds | gpg --yes --armor --recipient $(gpg -K --with-colons | awk -F: '$1~/ssb/ && $12~/e/ {print $5}'|tail -n 1) --encrypt|gpg; 
    assertEquals 'GPG encrypt failed' 0 $?
}

# test authentication
GPGAuth() {
    export SSH_AUTH_SOCK=`gpgconf --list-dirs agent-ssh-socket`
    gpg -K --with-colons | awk -F: '$1~/ssb/ && $12~/s/{lg=NR+2} NR==lg{grip=$10} END{print grip}' >"$GNUPGHOME/sshcontrol"
    ssh-add -L >"$SSHDIR/authorized_keys"
    ssh -p 22022 -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o PasswordAuthentication=no localhost "echo +++ Passed GPG Auth Key Test +++"
    assertEquals 'SSH failed' 0 $?
}

GenerateKey() {
    GPGReset
    echo -e "admin\nkey-attr\n$1\n$2\n$1\n$2\n$1\n$2\n" | $GPG --edit-card
    Addcardkey 1
    Addcardkey 2
    GPGEnc
    GPGSign
}


test_ImportP256() {
    # import ecc p-256 keys
    GPGReset
    Addkey 10 3 # Key 2 gen ECDSA P-256
    Key2card 2 1 # Key 2 to Signature
    Addkey 12 3 # Key 3 gen ECDH P-256
    Key2card 3 2 # Key 3 to Encryption
    GPGSign
    GPGEnc
    Addkey 10 3 # Key 4 gen ECDSA P-256
    Key2card 4 3 # Key 4 to Authentication
    GPGAuth
}
test_ImportRsa2048(){
    # import rsa2048 keys
    GPGReset
    Addkey 4 2048 # Key 5 gen RSA2048
    Key2card 5 1 # Key 5 to Signature
    Addkey 6 2048 # Key 6 gen RSA2048
    Key2card 6 2 # Key 6 to Encryption
    GPGSign
    GPGEnc
    Addkey 4 2048 # Key 7 gen RSA2048
    Key2card 7 3 # Key 7 to Authentication
    GPGAuth
}
test_Import25519(){

    # import 25519 keys
    GPGReset
    Addkey 10 1 # Key 8 gen ed25519
    Key2card 8 1 # Key 8 to Signature
    Addkey 12 1 # Key 9 gen cv25519
    Key2card 9 2 # Key 9 to Encryption
    GPGSign
    GPGEnc
    Addkey 10 1 # Key 10 gen ed25519
    Key2card 10 3 # Key 10 to Authentication
    GPGAuth
}
test_ImportP384(){

    # import ecc p-384 keys
    GPGReset
    Addkey 10 4 # Key 11 gen ECDSA P-384
    Key2card 11 1 # Key 11 to Signature
    Addkey 12 4 # Key 12 gen ECDH P-384
    Key2card 12 2 # Key 12 to Encryption
    GPGSign
    GPGEnc
    Addkey 10 4 # Key 13 gen ECDSA P-384
    Key2card 13 3 # Key 13 to Authentication
    GPGAuth
}
test_ImportSecp256k1(){

    # import ecc secp256k1 keys
    GPGReset
    Addkey 10 9 # Key 14 gen ECDSA secp256k1
    Key2card 14 1 # Key 14 to Signature
    Addkey 12 9 # Key 15 gen ECDH secp256k1
    Key2card 15 2 # Key 15 to Encryption
    GPGSign
    GPGEnc
    Addkey 10 9 # Key 16 gen ECDSA secp256k1
    Key2card 16 3 # Key 16 to Authentication
    # GPGAuth # not supported by ssh
}
test_ImportRsa4096(){

    # import rsa4096 keys
    GPGReset
    Addkey 4 4096 # Key 17 gen RSA4096
    Key2card 17 1 # Key 17 to Signature
    Addkey 6 4096 # Key 18 gen RSA4096
    Key2card 18 2 # Key 18 to Encryption
    GPGSign
    GPGEnc
    Addkey 4 4096 # Key 19 gen RSA4096
    Key2card 19 3 # Key 19 to Authentication
    GPGAuth
}

test_GenerateRsa2048() {
    # generate rsa2048 keys
    GenerateKey 1 2048
}

#test_GenerateRsa4096() {
    # generate rsa4096 keys
#    startSkipping
#    GenerateKey 1 4096
#}

test_Generate25519() {
    # generate 25519 keys
    GenerateKey 2 1
}

test_GenerateP256() {
    # generate p-256 keys
    GenerateKey 2 3
}

test_GenerateP384() {
    # generate p-384 keys
    GenerateKey 2 4
}

test_GenerateSecp256K1() {
    # generate secp256k1 keys
    GenerateKey 2 9
}

. ./shunit2/shunit2
