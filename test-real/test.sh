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

# test signing
GPGSign() { 
    date -Iseconds | gpg --armor --default-key $(gpg -K --with-colons|awk -F: '$1~/ssb/ && $12~/s|a/ {print $5}'|tail -n 1)! -s|gpg; 
}

# test encryption
GPGEnc()  {
    date -Iseconds | gpg --yes --armor --recipient $(gpg -K --with-colons | awk -F: '$1~/ssb/ && $12~/e/ {print $5}'|tail -n 1) --encrypt|gpg; 
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
    GPGSign
    GPGEnc

    # import rsa2048 keys
    GPGReset
    Addkey 4 2048 # Key 5 gen RSA2048
    Key2card 5 1 # Key 5 to Signature
    Addkey 6 2048 # Key 6 gen RSA2048
    Key2card 6 2 # Key 6 to Encryption
    Addkey 4 2048 # Key 7 gen RSA2048
    Key2card 7 3 # Key 7 to Authentication
    GPGSign
    GPGEnc

    # import 25519 keys
    GPGReset
    Addkey 10 1 # Key 8 gen ed25519
    Key2card 8 1 # Key 8 to Signature
    Addkey 12 1 # Key 9 gen cv25519
    Key2card 9 2 # Key 9 to Encryption
    Addkey 10 1 # Key 10 gen ed25519
    Key2card 10 3 # Key 10 to Authentication
    GPGSign
    GPGEnc

    # import ecc p-384 keys
    GPGReset
    Addkey 10 4 # Key 11 gen ECDSA P-384
    Key2card 11 1 # Key 11 to Signature
    Addkey 12 4 # Key 12 gen ECDH P-384
    Key2card 12 2 # Key 12 to Encryption
    Addkey 10 4 # Key 13 gen ECDSA P-384
    Key2card 13 3 # Key 13 to Authentication
    GPGSign
    GPGEnc

    # import ecc secp256k1 keys
    GPGReset
    Addkey 10 9 # Key 11 gen ECDSA secp256k1
    Key2card 14 1 # Key 14 to Signature
    Addkey 12 9 # Key 12 gen ECDH secp256k1
    Key2card 15 2 # Key 15 to Encryption
    Addkey 10 9 # Key 13 gen ECDSA secp256k1
    Key2card 16 3 # Key 16 to Authentication
    GPGSign
    GPGEnc
}

TestGenerateRsa2048() {
    # generate rsa2048 keys
    GPGReset
    echo -e 'admin\nkey-attr\n1\n2048\n1\n2048\n1\n2048\n' | $GPG --edit-card # key-attr set to RSA2048
    Addcardkey 1
    Addcardkey 2
    GPGEnc
    GPGSign
}

TestGenerate25519() {
    # generate 25519 keys
    GPGReset
    echo -e 'admin\nkey-attr\n2\n1\n2\n1\n2\n1\n' | gpg --command-fd 0 --yes --expert --edit-card # key-attr set to 25519
    Addcardkey 1
    Addcardkey 2
    GPGEnc
    GPGSign
}

TestGenerateP256() {
    # generate 25519 keys
    GPGReset
    echo -e 'admin\nkey-attr\n2\n3\n2\n3\n2\n3\n' | gpg --command-fd 0 --yes --expert --edit-card # key-attr set to ECC P-256
    Addcardkey 1
    Addcardkey 2
    GPGEnc
    GPGSign
}

TestGenerate() {
    TestGenerateRsa2048
    TestGenerate25519
}

#TestImport
#TestGenerate
