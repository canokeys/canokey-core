#!/bin/bash
rm -rf ./temp_gnupg
mkdir -p ./temp_gnupg
chmod 700 ./temp_gnupg
export GNUPGHOME=$(pwd)/temp_gnupg
cp pinentry-mock ./temp_gnupg/
echo "pinentry-program $(pwd)/pinentry-mock" > ${GNUPGHOME}/gpg-agent.conf
gpg --list-keys

set -e
set -x
GPG="gpg --command-fd 0 --yes --expert"

# utility functions

# generate key in gpg
Addkey() {
    echo -e "addkey\n$1\n$2\n0\nsave" | $GPG --edit-key $KEYID; 
}

# generate key in card
Addcardkey() {
    echo -e "addcardkey\n$1\n0\nsave\n" | $GPG --edit-key $KEYID;
}

# move key from gpg to card
Key2card() { 
    echo -e "key $1\nkeytocard\n$2\nsave" | $GPG --edit-key $KEYID;
    gpg --card-status; 
}

# reset card
GPGReset() {
    echo -e 'admin\nfactory-reset\ny\nyes' | $GPG --edit-card;
}

# begin testing
killall gpg-agent || true
echo -e 'Key-Type: 1\nKey-Length: 2048\nSubkey-Type: 1\nSubkey-Length: 2048\nName-Real: Someone\nName-Email: foo@example.com\nPassphrase: 12345678\n%commit\n%echo done' | gpg --batch --gen-key -v
KEYID=$(gpg -K --with-colons |egrep '^sec'|egrep -o '\w{16}')
echo 'Key Id is:' $KEYID

TestImport() {
    # import ecc p-256 keys
    GPGReset
    Addkey 10 3 # Key 2 gen ECDSA P-256
    Key2card 2 1 # Key 2 to Signature
    Addkey 12 3 # Key 3 gen ECDH P-256
    Key2card 3 2 # Key 3 to Encryption
    Addkey 10 3 # Key 4 gen ECDSA P-256
    Key2card 4 3 # Key 4 to Authentication

    # import rsa2048 keys
    GPGReset
    Addkey 4 2048 # Key 5 gen RSA2048
    Key2card 5 2 # Key 5 to Signature
    Addkey 6 2048 # Key 6 gen RSA2048
    Key2card 6 2 # Key 6 to Encryption
    Addkey 4 2048 # Key 7 gen RSA2048
    Key2card 7 3 # Key 7 to Authentication

    # import 25519 keys
    GPGReset
    Addkey 10 1 # Key 8 gen ed25519
    Key2card 8 1 # Key 8 to Signature
    Addkey 12 1 # Key 9 gen cv25519
    Key2card 9 2 # Key 9 to Encryption
    Addkey 10 1 # Key 10 gen ed25519
    Key2card 10 3 # Key 10 to Authentication
}

TestGenerate() {
    # generate rsa2048 keys
    GPGReset
    echo -e 'admin\nkey-attr\n1\n2048\n1\n2048\n1\n2048\n' | $GPG --edit-card # key-attr set to RSA2048
    Addcardkey 1
}

TestImport
