#!/bin/bash
export LANGUAGE=en_US
export LANG=en_US.UTF8

YPT() {
    sleep 0.8
    yubico-piv-tool $@
}

PIVGenKeyCert() {
    key=$1
    subject="$2"
    algo="$3"
    YPT -r "$RDID" -a generate -A $algo -s $key >/tmp/pubkey-$key.pem # generate key at $key
    assertEquals 'yubico-piv-tool generate' 0 $?
    YPT -r "$RDID" -P 654321 -a verify-pin -a selfsign-certificate -s $key -S "$subject" < /tmp/pubkey-$key.pem >/tmp/cert-$key.pem
    assertEquals 'yubico-piv-tool selfsign-certificate' 0 $?
    YPT -r "$RDID" -a import-certificate -s $key < /tmp/cert-$key.pem
    assertEquals 'yubico-piv-tool import-certificate' 0 $?
}

PIVSignDec() {
    key=$1
    pinArgs=
    op=$3
    if [[ -n "$2" ]]; then pinArgs="-P 654321 -a verify-pin"; fi
    if [[ -z "$op" || s = "$op" ]]; then 
        YPT -r "$RDID" $pinArgs -a test-signature -s $key < /tmp/cert-$key.pem;
        assertEquals 'yubico-piv-tool test-signature' 0 $?
    fi
    if [[ -z "$op" || d = "$op" ]]; then 
        YPT -r "$RDID" $pinArgs -a test-decipher -s $key < /tmp/cert-$key.pem;
        assertEquals 'yubico-piv-tool test-decipher' 0 $?
    fi
}

oneTimeSetUp() {
    killall -u $USER -9 gpg-agent || true
    export RDID=$(yubico-piv-tool -r '' -a list-readers | head -n 1)
}

test_PivInfo() {
    echo "Reader: {$RDID}"
    YPT -r "$RDID" -v -a set-ccc -a set-chuid -a status
    assertEquals 'yubico-piv-tool status' 0 $?

    out=$(opensc-tool -r "$RDID" -s '00 F8 00 00') # PIV_INS_GET_SERIAL, Yubico
    assertContains 'PIV_INS_GET_SERIAL' "$out" 'SW1=0x90, SW2=0x00'

    out=$(opensc-tool -r "$RDID" -s '00 FD 00 00') # PIV_INS_GET_VERSION, Yubico
    assertContains 'PIV_INS_GET_VERSION' "$out" 'SW1=0x90, SW2=0x00'

    pkcs15-tool --reader "$RDID" -D
    assertEquals 'pkcs15-tool dump' 0 $?
}

test_ChangePin() {
    YPT -r "$RDID" -a verify-pin -P 123456
    YPT -r "$RDID" -a change-pin -P 123456 -N 654321
    YPT -r "$RDID" -a verify-pin -P 654321
    out=$(YPT -r "$RDID" -a verify-pin -P 123456 2>&1)
    assertContains 'verify-pin' "$out" '2 tries left before pin is blocked.'
    out=$(YPT -r "$RDID" -a verify-pin -P 123456 2>&1)
    assertContains 'verify-pin' "$out" '1 tries left before pin is blocked.'
    YPT -r "$RDID" -a verify-pin -P 654321
    assertEquals 'verify-pin' 0 $?
    YPT -r "$RDID" -a set-mgm-key -n F1F2F3F4F5F6F7F8F1F2F3F4F5F6F7F8F1F2F3F4F5F6F7F8
    assertEquals 'set-mgm-key' 0 $?
    YPT -r "$RDID" -a set-mgm-key --key=F1F2F3F4F5F6F7F8F1F2F3F4F5F6F7F8F1F2F3F4F5F6F7F8 -n 010203040506070801020304050607080102030405060708
    assertEquals 'set-mgm-key' 0 $?
}

test_RSA2048() {
    for s in 9a 9c 9d 9e; do PIVGenKeyCert $s "/CN=CertAtSlot$s" RSA2048; done
    YPT -r "$RDID" -a status
    PIVSignDec 9e # PIN not required for key 9e
    for s in 9a 9c 9d; do PIVSignDec $s 1; done

    pkcs15-tool --reader "$RDID" -r 04 | openssl x509 -text | grep 'CN = CertAtSlot9e'
    echo -n hello >/tmp/hello.txt
    pkcs11-tool --slot "$RDID" -d 04 -s -m SHA256-RSA-PKCS -i /tmp/hello.txt -o /tmp/hello-signed --pin 654321
    assertEquals 'pkcs11-tool sign' 0 $?
    openssl dgst -sha256 -verify /tmp/pubkey-9e.pem -signature /tmp/hello-signed /tmp/hello.txt
    assertEquals 'openssl dgst verify' 0 $?
}

test_ECC256() {
    for s in 9a 9c 9d 9e; do PIVGenKeyCert $s "/CN=CertAtSlot$s" ECCP256; done
    YPT -r "$RDID" -a status
    for s in 9a 9c 9e; do PIVSignDec $s 1 s; done # 9a/9c/9e only do the ECDSA
    PIVSignDec 9d 1 d # 9d only do the ECDH
}

test_ECC384() {
    for s in 9a 9c 9d 9e; do PIVGenKeyCert $s "/CN=CertAtSlot$s" ECCP384; done
    YPT -r "$RDID" -a status
    for s in 9a 9c 9e; do PIVSignDec $s 1 s; done # 9a/9c/9e only do the ECDSA
    PIVSignDec 9d 1 d # 9d only do the ECDH
}

test_PinBlock() {
    out=$(YPT -r "$RDID" -a verify-pin -P 222222 2>&1)
    assertContains 'verify-pin' "$out" '2 tries left before pin is blocked.'
    out=$(YPT -r "$RDID" -a verify-pin -P 222222 2>&1)
    assertContains 'verify-pin' "$out" '1 tries left before pin is blocked.'
    out=$(YPT -r "$RDID" -a verify-pin -P 222222 2>&1)
    assertContains 'verify-pin' "$out" 'Pin code blocked'
    out=$(YPT -r "$RDID" -a verify-pin -P 654321 2>&1)
    assertContains 'verify-pin' "$out" 'Pin code blocked'
    out=$(YPT -r "$RDID" -a unblock-pin -P 12345678 -N 999999 2>&1)
    assertContains 'verify-pin' "$out" 'Successfully unblocked the pin code'
    out=$(YPT -r "$RDID" -a change-puk -P 12345678 -N 87654321 2>&1)
    assertContains 'verify-pin' "$out" 'Successfully changed the puk code'
    out=$(YPT -r "$RDID" -a unblock-pin -P 87654321 -N 654321 2>&1)
    assertContains 'verify-pin' "$out" 'Successfully unblocked the pin code'
}

test_ECCKeyImport() {
    openssl ecparam -name prime256v1 -out p256.pem
    openssl req -x509 -newkey ec:p256.pem -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=www.example.com"
    YPT -r "$RDID" -a import-key -s 9a -i key.pem
    assertEquals 'import-key' 0 $?
    YPT -r "$RDID" -a import-certificate -s 9a -i cert.pem
    assertEquals 'import-certificate' 0 $?
    YPT -r "$RDID" -P 654321 -a verify-pin -a test-signature -s 9a <cert.pem
    assertEquals 'test-signature' 0 $?
}

test_RSAKeyImport() {
    openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=www.example.com"
    YPT -r "$RDID" -a import-key -s 9c -i key.pem
    assertEquals 'import-key' 0 $?
    YPT -r "$RDID" -a import-certificate -s 9c -i cert.pem
    assertEquals 'import-certificate' 0 $?
    YPT -r "$RDID" -P 654321 -a verify-pin -a test-signature -s 9c <cert.pem
    assertEquals 'test-signature' 0 $?
}

test_FactoryReset() {
    out=$(YPT -r "$RDID" -a change-puk -P 12345678 -N 11111111 2>&1)
    assertContains "change-puk" "$out" 'Failed verifying puk code, now 2 tries left before blocked'
    out=$(YPT -r "$RDID" -a change-puk -P 12345678 -N 11111111 2>&1)
    assertContains "change-puk" "$out" 'Failed verifying puk code, now 1 tries left before blocked'
    out=$(YPT -r "$RDID" -a change-puk -P 12345678 -N 11111111 2>&1)
    assertContains "change-puk" "$out" 'The puk code is blocked'
    out=$(YPT -r "$RDID" -a change-puk -P 87654321 -N 11111111 2>&1)
    assertContains "change-puk" "$out" 'The puk code is blocked'
    out=$(YPT -r "$RDID" -a verify-pin -P 222222 2>&1)
    assertContains "verify-pin" "$out" '2 tries left before pin is blocked.'
    out=$(YPT -r "$RDID" -a verify-pin -P 222222 2>&1)
    assertContains "verify-pin" "$out" '1 tries left before pin is blocked.'
    out=$(YPT -r "$RDID" -a verify-pin -P 222222 2>&1)
    assertContains "verify-pin" "$out" 'Pin code blocked'
    YPT -r "$RDID" -a reset
    assertEquals 'reset' 0 $?
    out=$(YPT -r "$RDID" -a unblock-pin -P 12345678 -N 654321 2>&1)
    assertContains "unblock-pin" "$out" 'Successfully unblocked the pin code'
}

test_FillData() {
    YPT -r "$RDID" -a set-ccc -a set-chuid -a status
    longName=OU=ThisIsAVeryLongNameThisIsAVeryLongNameThisIsAVeryLongName/O=ThisIsAVeryLongNameThisIsAVeryLongNameThisIsAVeryLongName/L=ThisIsAVeryLongNameThisIsAVeryLongNameThisIsAVeryLongName/ST=ThisIsAVeryLongName/C=CN
    openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=CertAtSlot$s/$longName"
    assertEquals 'openssl gen key' 0 $?
    for s in 9a 9c 9d 9e; do
        YPT -r "$RDID" -a import-key -s $s -i key.pem
        assertEquals 'import-key' 0 $?
        YPT -r "$RDID" -a import-certificate -s $s -i cert.pem
        assertEquals 'import-certificate' 0 $?
    done
}

. ./shunit2/shunit2
