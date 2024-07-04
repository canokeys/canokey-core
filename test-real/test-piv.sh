#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
export LANGUAGE=en_US
export LANG=en_US.UTF8
export TEST_TMP_DIR=/tmp/canokey-piv
export USER=`id -nu`

YPT() {
    yubico-piv-tool -r "$RDID" $@
}

PIVGenKeyCert() {
    key=$1
    subject="$2"
    algo="$3"
    YPT -a generate -A $algo -s $key >$TEST_TMP_DIR/pubkey-$key.pem # generate key at $key
    assertEquals 'yubico-piv-tool generate' 0 $?
    if [[ $algo == "X25519" ]]; then return; fi
    YPT -P 654321 -a verify-pin -a selfsign-certificate -s $key -S "$subject" < $TEST_TMP_DIR/pubkey-$key.pem >$TEST_TMP_DIR/cert-$key.pem
    assertEquals 'yubico-piv-tool selfsign-certificate' 0 $?
    YPT -a import-certificate -s $key < $TEST_TMP_DIR/cert-$key.pem
    assertEquals 'yubico-piv-tool import-certificate' 0 $?
}

PIVImportKeyCert() {
    key=$1
    priv_pem="$2"
    cert_pem="$3"
    YPT -a import-key -s $key -i "$priv_pem"
    assertEquals 'import-key' 0 $?
    YPT -a import-certificate -s $key -i "$cert_pem"
    assertEquals 'import-certificate' 0 $?
    cp "$cert_pem" "$TEST_TMP_DIR/cert-$key.pem"
}

PIVSignDec() {
    key=$1
    pinArgs=
    op=$3
    inp_file=$TEST_TMP_DIR/cert-$key.pem
    if [[ $key == X25519 ]]; then inp_file=$TEST_TMP_DIR/pubkey-$key.pem; fi
    if [[ -n "$2" ]]; then pinArgs="-P 654321 -a verify-pin"; fi
    if [[ -z "$op" || s = "$op" ]]; then 
        YPT $pinArgs -a test-signature -s $key < $inp_file;
        assertEquals 'yubico-piv-tool test-signature' 0 $?
    fi
    if [[ -z "$op" || d = "$op" ]]; then 
        YPT $pinArgs -a test-decipher -s $key < $inp_file;
        assertEquals 'yubico-piv-tool test-decipher' 0 $?
    fi
}

oneTimeSetUp() {
    rm -rf "$TEST_TMP_DIR"
    mkdir "$TEST_TMP_DIR"
    killall -u $USER -9 gpg-agent || true
    sleep 2
    export RDID=$(yubico-piv-tool -r '' -a list-readers | head -n 1)
}

test_PivInfo() {
    echo "Reader: {$RDID}"
    YPT -v -a set-ccc -a set-chuid -a status
    assertEquals 'yubico-piv-tool status' 0 $?

    out=$(opensc-tool -s '00 F8 00 00') # PIV_INS_GET_SERIAL, Yubico
    assertContains 'PIV_INS_GET_SERIAL' "$out" 'SW1=0x90, SW2=0x00'

    out=$(opensc-tool -s '00 FD 00 00') # PIV_INS_GET_VERSION, Yubico
    assertContains 'PIV_INS_GET_VERSION' "$out" 'SW1=0x90, SW2=0x00'

    pkcs15-tool --reader "$RDID" -D
    assertEquals 'pkcs15-tool dump' 0 $?
}

test_ChangePin() {
    YPT -a verify-pin -P 123456
    YPT -a change-pin -P 123456 -N 654321
    YPT -a verify-pin -P 654321
    out=$(YPT -a verify-pin -P 123456 2>&1)
    assertContains 'verify-pin' "$out" '2 tries left before pin is blocked.'
    out=$(YPT -a verify-pin -P 123456 2>&1)
    assertContains 'verify-pin' "$out" '1 tries left before pin is blocked.'
    YPT -a verify-pin -P 654321
    assertEquals 'verify-pin' 0 $?
    YPT -a set-mgm-key -n F1F2F3F4F5F6F7F8F1F2F3F4F5F6F7F8F1F2F3F4F5F6F7F8
    assertEquals 'set-mgm-key' 0 $?
    YPT -a set-mgm-key --key=F1F2F3F4F5F6F7F8F1F2F3F4F5F6F7F8F1F2F3F4F5F6F7F8 -n 010203040506070801020304050607080102030405060708
    assertEquals 'set-mgm-key' 0 $?
}

rsa_tests() {
    for s in 9a 9c 9d 9e; do PIVGenKeyCert $s "/CN=CertAtSlot$s/" $1; done
    YPT -a status
    PIVSignDec 9e # PIN not required for key 9e
    for s in 9a 9c 9d; do PIVSignDec $s 1; done

    out=$(pkcs15-tool --reader "$RDID" --read-certificate 04 | openssl x509 -text)
    assertContains 'CERT' "$out" 'CN = CertAtSlot9e'
    echo -n hello >$TEST_TMP_DIR/hello.txt
    pkcs11-tool --slot "$RDID" -d 04 -s -m SHA256-RSA-PKCS -i $TEST_TMP_DIR/hello.txt -o $TEST_TMP_DIR/hello-signed --pin 654321
    assertEquals 'pkcs11-tool sign' 0 $?
    openssl dgst -sha256 -verify $TEST_TMP_DIR/pubkey-9e.pem -signature $TEST_TMP_DIR/hello-signed $TEST_TMP_DIR/hello.txt
    assertEquals 'openssl dgst verify' 0 $?
}

test_RSA2048() {
    rsa_tests RSA2048
}

test_RSA3072() {
    rsa_tests RSA3072
}

test_RSA4096() {
    rsa_tests RSA4096
}

ec_tests() {
    for s in 9a 9c 9d 9e; do PIVGenKeyCert $s "/CN=CertAtSlot$s/" $1; done
    YPT -a status
    for s in 9a 9c 9d 9e; do
        if [[ $1 != "X25519" ]]; then PIVSignDec $s 1 s; fi
        if [[ $1 != "ED25519" ]]; then PIVSignDec $s 1 d; fi
    done
    if [[ $1 != *25519 ]]; then
        out=$(pkcs15-tool --reader "$RDID" --read-certificate 01 | openssl x509 -text)
        assertContains 'CERT' "$out" 'CN = CertAtSlot9a'
        out=$(pkcs15-tool --reader "$RDID" --read-certificate 02 | openssl x509 -text)
        assertContains 'CERT' "$out" 'CN = CertAtSlot9c'
    fi
}

test_ECC256() {
    ec_tests ECCP256
}

test_ECC384() {
    ec_tests ECCP384
}

test_25519() {
    ec_tests ED25519
    ec_tests X25519
}

test_PinBlock() {
    out=$(YPT -a verify-pin -P 222222 2>&1)
    assertContains 'verify-pin' "$out" '2 tries left before pin is blocked.'
    out=$(YPT -a verify-pin -P 222222 2>&1)
    assertContains 'verify-pin' "$out" '1 tries left before pin is blocked.'
    out=$(YPT -a verify-pin -P 222222 2>&1)
    assertContains 'verify-pin' "$out" 'Pin code blocked'
    out=$(YPT -a verify-pin -P 654321 2>&1)
    assertContains 'verify-pin' "$out" 'Pin code blocked'
    out=$(YPT -a unblock-pin -P 12345678 -N 999999 2>&1)
    assertContains 'verify-pin' "$out" 'Successfully unblocked the pin code'
    out=$(YPT -a change-puk -P 12345678 -N 87654321 2>&1)
    assertContains 'verify-pin' "$out" 'Successfully changed the puk code'
    out=$(YPT -a unblock-pin -P 87654321 -N 654321 2>&1)
    assertContains 'verify-pin' "$out" 'Successfully unblocked the pin code'
}

test_P256KeyImport() {
    openssl ecparam -name prime256v1 -out $TEST_TMP_DIR/p256.pem
    openssl req -x509 -newkey ec:$TEST_TMP_DIR/p256.pem -keyout $TEST_TMP_DIR/key.pem -out $TEST_TMP_DIR/cert.pem -days 365 -nodes -subj "/CN=www.example.com"
    
    for s in 9a 9c 9d 9e; do PIVImportKeyCert $s $TEST_TMP_DIR/key.pem $TEST_TMP_DIR/cert.pem; done
    YPT -a status
    for s in 9a 9c 9e; do PIVSignDec $s 1 s; done # 9a/9c/9e only do the ECDSA
    PIVSignDec 9d 1 d # 9d only do the ECDH
}

test_P384KeyImport() {
    openssl ecparam -name secp384r1 -out $TEST_TMP_DIR/p384.pem
    openssl req -x509 -newkey ec:$TEST_TMP_DIR/p384.pem -keyout $TEST_TMP_DIR/key.pem -out $TEST_TMP_DIR/cert.pem -days 365 -nodes -subj "/CN=www.example.com"
    
    for s in 9a 9c 9d 9e; do PIVImportKeyCert $s $TEST_TMP_DIR/key.pem $TEST_TMP_DIR/cert.pem; done
    YPT -a status
    for s in 9a 9c 9e; do PIVSignDec $s 1 s; done # 9a/9c/9e only do the ECDSA
    PIVSignDec 9d 1 d # 9d only do the ECDH
}

test_RSAKeyImport() {
    openssl req -x509 -newkey rsa:2048 -keyout $TEST_TMP_DIR/key.pem -out $TEST_TMP_DIR/cert.pem -days 365 -nodes -subj "/CN=www.example.com"
    
    for s in 9a 9c 9d 9e; do PIVImportKeyCert $s $TEST_TMP_DIR/key.pem $TEST_TMP_DIR/cert.pem; done
    YPT -a status
    PIVSignDec 9e # PIN not required for key 9e
    for s in 9a 9c 9d; do PIVSignDec $s 1; done 
}

test_FactoryReset() {
    out=$(YPT -a change-puk -P 12345678 -N 11111111 2>&1)
    assertContains "change-puk" "$out" 'Failed verifying puk code, now 2 tries left before blocked'
    out=$(YPT -a change-puk -P 12345678 -N 11111111 2>&1)
    assertContains "change-puk" "$out" 'Failed verifying puk code, now 1 tries left before blocked'
    out=$(YPT -a change-puk -P 12345678 -N 11111111 2>&1)
    assertContains "change-puk" "$out" 'The puk code is blocked'
    out=$(YPT -a change-puk -P 87654321 -N 11111111 2>&1)
    assertContains "change-puk" "$out" 'The puk code is blocked'
    out=$(YPT -a verify-pin -P 222222 2>&1)
    assertContains "verify-pin" "$out" '2 tries left before pin is blocked.'
    out=$(YPT -a verify-pin -P 222222 2>&1)
    assertContains "verify-pin" "$out" '1 tries left before pin is blocked.'
    out=$(YPT -a verify-pin -P 222222 2>&1)
    assertContains "verify-pin" "$out" 'Pin code blocked'
    YPT -a reset
    assertEquals 'reset' 0 $?
    out=$(YPT -a unblock-pin -P 12345678 -N 654321 2>&1)
    assertContains "unblock-pin" "$out" 'Successfully unblocked the pin code'
}

test_FillData() {
    openssl req -x509 -newkey rsa:2048 -keyout $TEST_TMP_DIR/key.pem -out $TEST_TMP_DIR/cert.pem -days 365 -nodes -subj "/CN=www.example.com"
    assertEquals 'openssl gen key' 0 $?
    for s in 9a 9c 9d 9e 82 83; do
        PIVImportKeyCert $s $TEST_TMP_DIR/key.pem ../test-via-pcsc/long-cert.pem
        assertEquals 'import-key' 0 $?
    done
    YPT -a status
}

. ./shunit2/shunit2
