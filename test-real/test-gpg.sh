#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
export LANGUAGE=en_US
export LANG=en_US.UTF8
export USER=`id -nu`
export GNUPGHOME="$(pwd)/temp_gnupg"
export SSHDIR="$(pwd)/temp_ssh"
GPG="gpg --command-fd 0 --yes --expert"

# utility functions

# generate key in gpg
Addkey() {
    [[ -z "$1" || -z "$2" ]] && echo "Wrong arguments!" && exit 1
    echo -e "addkey\n$1\n$2\n0\nsave" | $GPG --edit-key $KEYID; 
    assertEquals 'Addkey failed' 0 $?
}

KeyUsageS2A() {
    echo -e "key $1\nchange-usage\nS\nA\nQ\nsave" | $GPG --edit-key $KEYID; 
    assertEquals 'KeyUsageS2A failed' 0 $?
}

# generate key in card
Addcardkey() {
    echo -e "addcardkey\n$1\n0\nsave\n" | $GPG --edit-key $KEYID;
    assertEquals 'Addcardkey failed' 0 $?
}

# delete keys from GPG DB
Delkey() {
    keys=""
    nl=$'\n'
    for k in "$@"; do
        keys="${keys}key $k$nl"
    done
    echo -e "${keys}delkey\ny\nsave\n" | $GPG --edit-key $KEYID;
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
    k=$(gpg -K --with-colons|awk -F: '$1~/ssb/ && $12~/s/ {print $5}'|tail -n 1)
    echo "========================== Test Signing with $k =========================="
    [[ -z "$k" ]] && echo "Key not found!" && exit 1
    date -Iseconds | gpg --armor --default-key ${k}! -s|gpg; 
    assertEquals 'GPG sign failed' 0 $?
}

# test encryption
GPGEnc()  {
    k=$(gpg -K --with-colons | awk -F: '$1~/ssb/ && $12~/e/ {print $5}'|tail -n 1)
    echo "========================== Test Encryption with $k =========================="
    [[ -z "$k" ]] && echo "Key not found!" && exit 1
    date -Iseconds | gpg --yes --armor --recipient $k --encrypt|gpg; 
    assertEquals 'GPG encrypt failed' 0 $?
}

# test authentication
GPGAuth() {
    export SSH_AUTH_SOCK=`gpgconf --list-dirs agent-ssh-socket`
    algo=$(gpg -K --with-colons | awk -F: '$1~/ssb/ && $12~/a/ {print $17}'|tail -n 1)
    if [[ "$algo" == secp256k1 ]]; then
        echo "SSH doesn't support secp256k1"
        return
    fi
    # k=$(gpg -K --with-colons | awk -F: '$1~/ssb/ && $12~/a/ {print $5}'|tail -n 1)
    # echo "========================== Test Authentication with $k =========================="
    # [[ -z "$k" ]] && echo "Key not found!" && exit 1
    # date -Iseconds | gpg --armor --default-key ${k}! -s|gpg; 
    # assertEquals 'GPG sign failed' 0 $?
    k=$(gpg -K --with-colons | awk -F: '$1~/ssb/ && $12~/a/{lg=NR+2} NR==lg{grip=$10} END{print grip}')
    echo "========================== Test Authentication with $k =========================="
    [[ -z "$k" ]] && echo "Key not found!" && exit 1
    echo "$k" >"$GNUPGHOME/sshcontrol"
    ssh-add -L >"$SSHDIR/authorized_keys"
    ssh -p 22022 -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o PasswordAuthentication=no localhost "echo +++ Passed GPG Auth Key Test +++"
    assertEquals 'SSH failed' 0 $?
}

GenerateKeyOnCard() {
    # GPGReset
    echo -e "admin\nkey-attr\n$1\n$2\n$1\n$2\n$1\n$2\n" | $GPG --edit-card
    Addcardkey 1
    Addcardkey 2
    Addcardkey 3
}


oneTimeSetUp(){
    killall -u $USER -9 gpg-agent sshd scdaemon|| true
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
    mkdir /run/sshd

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
    /usr/sbin/sshd -f "$SSHDIR/sshd_config" -E /tmp/canokey-test-sshd.log
    gpg --version
    gpg --card-status # The first try may fail
    gpg --card-status || exit 1
    echo -e 'Key-Type: 1\nKey-Length: 2048\nSubkey-Type: 1\nSubkey-Length: 2048\nName-Real: Someone\nName-Email: foo@example.com\nPassphrase: 12345678\n%commit\n%echo done' | gpg --batch --gen-key -v
    export KEYID=$(gpg -K --with-colons |egrep '^sec'|egrep -o '\w{16}')
    echo 'Key Id is:' $KEYID
    GPGReset
    Delkey 1
}

test_Sanity() {
    # Addkey 10 9
    # Key2card 1 3
    # KeyUsageS2A 1
    # gpg -K --with-colons
    # GPGAuth
    # Delkey 1
    Addkey 10 3
    Key2card 1 1
    GPGSign
    Delkey 1
    Addkey 12 3
    Key2card 1 2
    GPGEnc
    Delkey 1
}

test_ImportedKeys() {
    ALGO_PAIRS=("10 3,12 3" #ECC p-256
                "10 4,12 4" #ECC p-384
                "10 9,12 9" #secp256k1
                "10 1,12 1" #25519
                "4 2048,6 2048" #RSA2048
                "4 4096,6 4096" #RSA4096
                )
    for ((i = 0; i < ${#ALGO_PAIRS[@]}; i++)); do
        pair="${ALGO_PAIRS[$i]}"
        echo "------------------- <$pair> -------------------"
        param_enc="${pair##*,}"
        param_sig="${pair%%,*}"
        echo "========================== Signature<$param_sig> =========================="
        Addkey $param_sig # Key 1
        Key2card 1 1 # Key 1 to Signature
        echo "========================== Encryption<$param_enc> =========================="
        Addkey $param_enc # Key 2
        Key2card 2 2 # Key 2 to Encryption
        echo "========================== Authentication<$param_sig> =========================="
        Addkey $param_sig # Key 3
        KeyUsageS2A 3
        Key2card 3 3 # Key 3 to Authentication
        GPGAuth
        GPGSign
        GPGEnc
        Delkey 1 2 3
        GPGReset
    done
}

test_GeneratedKeys() {
    ALGO_PAIRS=("2 3" #ECC p-256
                "2 4" #ECC p-384
                "2 9" #secp256k1
                "1 2048" #RSA2048
                "2 1" #25519
                )
    for ((i = 0; i < ${#ALGO_PAIRS[@]}; i++)); do
        pair="${ALGO_PAIRS[$i]}"
        echo "------------------- <$pair> -------------------"
        GenerateKeyOnCard $pair
        GPGSign
        GPGEnc
        GPGAuth
        Delkey 1 2 3
        GPGReset
    done
}

. ./shunit2/shunit2
