#!/bin/bash
# PIV applet integration tests
# Called from tests.yml
set -e
set -o xtrace

echo "=== Phase: Go unit tests ==="
go test -v test-via-pcsc/piv_test.go

RDID="Canokey [OpenPGP PIV OATH] 00 00"
export PIV_EXT_AUTH_KEY=$PWD/test-via-pcsc/PIV_EXT_AUTH_KEY.txt

echo "=== Phase: Basic PIV status and CHUID ==="
yubico-piv-tool -r "$RDID" -a status -a set-ccc -a set-chuid -a status
opensc-tool -r "$RDID" -s '00 F8 00 00' | grep 'SW1=0x90, SW2=0x00' # PIV_INS_GET_SERIAL
opensc-tool -r "$RDID" -s '00 FD 00 00' | grep 'SW1=0x90, SW2=0x00' # PIV_INS_GET_VERSION
pkcs15-tool --reader "$RDID" -D

echo "=== Phase: Algorithm extension (ED25519) ==="
piv-tool --admin M:9B:03 -s '00 EE 02 00 08 01 22 05 51 52 53 15 54' | grep 'SW1=0x90, SW2=0x00'
piv-tool --admin M:9B:03 -s '00 EE 01 00 10' | grep '01 22 05 51 52 53 15 54'
perl -0pi -e 's/\{slot: 0x90, alg: AlgorithmEC256\}/\{slot: 0x96, alg: AlgorithmEC256\}/ or die "piv-go invalid slot test not found\n"' piv-go/piv/key_test.go
cd piv-go; go test -v ./piv --wipe-yubikey; cd -
piv-tool --admin M:9B:03 -s '00 EE 02 00 08 01 E0 05 16 E1 53 15 54' | grep 'SW1=0x90, SW2=0x00'

echo "=== Phase: PIN management ==="
yubico-piv-tool -r "$RDID" -a verify-pin -P 123456
yubico-piv-tool -r "$RDID" -a change-pin -P 123456 -N 654321
yubico-piv-tool -r "$RDID" -a verify-pin -P 654321
yubico-piv-tool -r "$RDID" -a verify-pin -P 123456 2>&1 | grep '2 tries left before pin is blocked.'
yubico-piv-tool -r "$RDID" -a verify-pin -P 123456 2>&1 | grep '1 tries left before pin is blocked.'
yubico-piv-tool -r "$RDID" -a verify-pin -P 654321
yubico-piv-tool -r "$RDID" -a set-mgm-key -n F1F2F3F4F5F6F7F8F1F2F3F4F5F6F7F8F1F2F3F4F5F6F7F8
yubico-piv-tool -r "$RDID" -a set-mgm-key --key=F1F2F3F4F5F6F7F8F1F2F3F4F5F6F7F8F1F2F3F4F5F6F7F8 -n 010203040506070801020304050607080102030405060708
piv-tool --reader "$RDID" --admin A:9B:03
piv-tool --reader "$RDID" --admin M:9B:03

# Helper functions
PIVGenKeyCert() {
  key=$1; subject="$2"; algo="$3"
  yubico-piv-tool -r "$RDID" -a generate -A $algo -s $key >/tmp/pubkey-$key.pem
  if [[ "$algo" == "X25519" ]]; then return; fi
  yubico-piv-tool -r "$RDID" -P 654321 -a verify-pin -a selfsign-certificate -s $key -S "$subject" < /tmp/pubkey-$key.pem >/tmp/cert-$key.pem
  yubico-piv-tool -r "$RDID" -a import-certificate -s $key < /tmp/cert-$key.pem
}
PIVSignDec() {
  key=$1; pinArgs=; op=$3; algoArgs=; inp_file=/tmp/cert-$key.pem
  if [[ -n "$2" ]]; then pinArgs="-P 654321 -a verify-pin"; fi
  if [[ -n "$4" ]]; then algoArgs="-A $4"; fi
  if [[ "$4" == X25519 ]]; then inp_file=/tmp/pubkey-$key.pem; fi
  if [[ -z "$op" || s = "$op" ]]; then yubico-piv-tool -r "$RDID" $pinArgs -a test-signature -s $key < /tmp/cert-$key.pem; fi
  if [[ -z "$op" || d = "$op" ]]; then yubico-piv-tool -r "$RDID" $pinArgs -a test-decipher -s $key $algoArgs < $inp_file; fi
}

echo "=== Phase: ED25519 tests ==="
for s in 9a 9c 9d 9e 82 83; do PIVGenKeyCert $s "/CN=CertAtSlot$s/" ED25519; done
yubico-piv-tool -r "$RDID" -a status
for s in 9a 9c 9d 9e 82 83; do PIVSignDec $s 1 s; done

echo "=== Phase: X25519 tests ==="
for s in 9a 9c 9d 9e 82 83; do PIVGenKeyCert $s "/CN=CertAtSlot$s/" X25519; done
yubico-piv-tool -r "$RDID" -a status
for s in 9a 9c 9d 9e 82 83; do PIVSignDec $s 1 d X25519; done

echo "=== Phase: Error handling tests ==="
piv-tool --admin M:9B:03 -s '00 47 00 96 05 AC 03 80 01 11' | grep 'SW1=0x6A, SW2=0x86'
yubico-piv-tool -r "$RDID" -a generate -A ECCP256 -s 9e
yubico-piv-tool -r "$RDID" -a generate -A X25519 -s 82 > /tmp/pubkey-9e.pem
yubico-piv-tool -r "$RDID" -a test-decipher -s 9e -A X25519 </tmp/pubkey-9e.pem 2>&1 | grep "Failed ECDH exchange"
yubico-piv-tool -r "$RDID" -a test-decipher -s 84 -A X25519 </tmp/pubkey-9e.pem 2>&1 | grep "Failed ECDH exchange"
opensc-tool -r "$RDID" -s '00 24 00 01 02 00 00' | grep 'SW1=0x6A, SW2=0x88'
opensc-tool -r "$RDID" -s '00 87 FF 9B 02 00 00' | grep 'SW1=0x6A, SW2=0x80'
opensc-tool -r "$RDID" -s '00 87 FF 9B 02 7C 00' | grep 'SW1=0x6A, SW2=0x86'

echo "=== Phase: RSA-3072 tests ==="
for s in 9a 9c 9d 9e 82 83; do PIVGenKeyCert $s "/CN=CertAtSlot$s/" RSA3072; done
yubico-piv-tool -r "$RDID" -a status
for s in 9a 9c 9d 9e 82 83; do PIVSignDec $s 1; done

echo "=== Phase: RSA-4096 tests ==="
for s in 9a 9c 9d 9e 82 83; do PIVGenKeyCert $s "/CN=CertAtSlot$s/" RSA4096; done
yubico-piv-tool -r "$RDID" -a status
for s in 9a 9c 9d 9e 82 83; do PIVSignDec $s 1; done

echo "=== Phase: RSA-2048 tests ==="
for s in 9a 9c 9d 9e 82 83; do PIVGenKeyCert $s "/CN=CertAtSlot$s/" RSA2048; done
yubico-piv-tool -r "$RDID" -a status
PIVSignDec 9e
for s in 9a 9c 9d 82 83; do PIVSignDec $s 1; done
pkcs15-tool --reader "$RDID" --read-certificate 04 | openssl x509 -text | grep 'CN = CertAtSlot9e'
echo -n hello >/tmp/hello.txt
pkcs11-tool --slot "$RDID" -d 04 -s -m SHA256-RSA-PKCS -i /tmp/hello.txt -o /tmp/hello-signed --pin 654321
openssl dgst -sha256 -verify /tmp/pubkey-9e.pem -signature /tmp/hello-signed /tmp/hello.txt

echo "=== Phase: ECC P-256 tests ==="
for s in 9a 9c 9d 9e 82 83; do PIVGenKeyCert $s "/CN=CertAtSlot$s/" ECCP256; done
yubico-piv-tool -r "$RDID" -a status
for s in 9a 9c 9d 9e 82 83; do PIVSignDec $s 1 s; PIVSignDec $s 1 d; done

echo "=== Phase: ECC P-384 tests ==="
for s in 9a 9c 9d 9e; do PIVGenKeyCert $s "/CN=CertAtSlot$s/" ECCP384; done
yubico-piv-tool -r "$RDID" -a status
for s in 9a 9c 9d 9e 82 83; do PIVSignDec $s 1 s; PIVSignDec $s 1 d; done

echo "=== Phase: PIN unblock ==="
yubico-piv-tool -r "$RDID" -P 654321 -a verify-pin -a test-signature -s 9a < /tmp/cert-9a.pem
yubico-piv-tool -r "$RDID" -P 654321 -a verify-pin -a test-signature -s 9c < /tmp/cert-9c.pem
yubico-piv-tool -r "$RDID" -P 654321 -a verify-pin -a test-decipher -s 9d < /tmp/cert-9d.pem
yubico-piv-tool -r "$RDID" -a verify-pin -P 222222 2>&1 | grep '2 tries left before pin is blocked.'
yubico-piv-tool -r "$RDID" -a verify-pin -P 222222 2>&1 | grep '1 tries left before pin is blocked.'
yubico-piv-tool -r "$RDID" -a verify-pin -P 222222 2>&1 | grep 'Pin code blocked'
yubico-piv-tool -r "$RDID" -a verify-pin -P 654321 2>&1 | grep 'Pin code blocked'
yubico-piv-tool -r "$RDID" -a unblock-pin -P 12345678 -N 999999 2>&1 | grep 'Successfully unblocked the pin code'
yubico-piv-tool -r "$RDID" -a change-puk -P 12345678 -N 87654321 2>&1 | grep 'Successfully changed the puk code'
yubico-piv-tool -r "$RDID" -a unblock-pin -P 87654321 -N 654321 2>&1 | grep 'Successfully unblocked the pin code'

echo "=== Phase: Key import ==="
openssl ecparam -name prime256v1 -out p256.pem
openssl req -x509 -newkey ec:p256.pem -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=www.example.com"

echo "=== Phase: ECC key import (openssl) ==="
for s in 9a 9d 82 83; do
    yubico-piv-tool -r "$RDID" -a import-key -s $s -i key.pem
    yubico-piv-tool -r "$RDID" -a import-certificate -s $s -i cert.pem
    yubico-piv-tool -r "$RDID" -P 654321 -a verify-pin -a test-signature -s $s <cert.pem
done

echo "=== Phase: RSA-2048 key import (openssl) ==="
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=www.example.com"
for s in 9c 9d 82 83; do
    yubico-piv-tool -r "$RDID" -a import-key -s $s -i key.pem
    yubico-piv-tool -r "$RDID" -a import-certificate -s $s -i cert.pem
    yubico-piv-tool -r "$RDID" -P 654321 -a verify-pin -a test-signature -s $s <cert.pem
done

echo "=== Phase: ED25519 key import (openssl) ==="
openssl genpkey -algorithm ED25519 -out key.pem
openssl req -x509 -key key.pem -out cert.pem -days 365 -nodes -subj "/CN=www.example.com"
for s in 9a 9e; do
  yubico-piv-tool -r "$RDID" -a import-key -s $s -i key.pem
  yubico-piv-tool -r "$RDID" -a import-certificate -s $s -i cert.pem
  yubico-piv-tool -r "$RDID" -P 654321 -a verify-pin -a test-signature -s $s <cert.pem
done

echo "=== Phase: X25519 key import (openssl) ==="
openssl genpkey -algorithm X25519 -out key.pem
openssl pkey -in key.pem -pubout -out pubkey.pem
for s in 9d 83; do
  yubico-piv-tool -r "$RDID" -a import-key -s $s -i key.pem
  yubico-piv-tool -r "$RDID" -P 654321 -a verify-pin -a test-decipher -A X25519 -s $s <pubkey.pem
done

echo "=== Phase: Factory reset ==="
yubico-piv-tool -r "$RDID" -a change-puk -P 12345678 -N 11111111 2>&1 | grep 'Failed verifying puk code, now 2 tries left before blocked'
yubico-piv-tool -r "$RDID" -a change-puk -P 12345678 -N 11111111 2>&1 | grep 'Failed verifying puk code, now 1 tries left before blocked'
yubico-piv-tool -r "$RDID" -a change-puk -P 12345678 -N 11111111 2>&1 | grep 'The puk code is blocked'
yubico-piv-tool -r "$RDID" -a change-puk -P 87654321 -N 11111111 2>&1 | grep 'The puk code is blocked'
yubico-piv-tool -r "$RDID" -a verify-pin -P 222222 2>&1 | grep '2 tries left before pin is blocked.'
yubico-piv-tool -r "$RDID" -a verify-pin -P 222222 2>&1 | grep '1 tries left before pin is blocked.'
yubico-piv-tool -r "$RDID" -a verify-pin -P 222222 2>&1 | grep 'Pin code blocked'
yubico-piv-tool -r "$RDID" -a reset
yubico-piv-tool -r "$RDID" -a unblock-pin -P 12345678 -N 654321 2>&1 | grep 'Successfully unblocked the pin code'

echo "=== Phase: Long data objects ==="
yubico-piv-tool -r "$RDID" -a set-ccc -a set-chuid -a status
for s in 9a 9c 9d 9e 82 83; do
  PIVGenKeyCert $s "/CN=CertAtSlot$s/" RSA4096
  yubico-piv-tool -r "$RDID" -a import-certificate -s $s -i test-via-pcsc/long-cert.pem
done
openssl rand -base64 -out /tmp/rand-pi 242
openssl rand -base64 -out /tmp/rand-fig 508
openssl rand -base64 -out /tmp/rand-face 508
yubico-piv-tool -r "$RDID" -a write-object --id 0x5fc109 -i /tmp/rand-pi -f base64
yubico-piv-tool -r "$RDID" -a read-object --id 0x5fc109 -o /tmp/read-pi 2>&1 | grep 'Failed fetching'
yubico-piv-tool -r "$RDID" -a write-object --id 0x5fc108 -i /tmp/rand-face -f base64
yubico-piv-tool -r "$RDID" -a write-object --id 0x5fc103 -i /tmp/rand-fig -f base64
yubico-piv-tool -r "$RDID" -a verify-pin -P 654321 -a read-object --id 0x5fc103 -o /tmp/read-fig -f base64
yubico-piv-tool -r "$RDID" -a verify-pin -P 654321 -a read-object --id 0x5fc109 -o /tmp/read-pi -f base64
yubico-piv-tool -r "$RDID" -a verify-pin -P 654321 -a read-object --id 0x5fc108 -o /tmp/read-face -f base64
diff -s /tmp/rand-pi   /tmp/read-pi
diff -s /tmp/rand-face /tmp/read-face
diff -s /tmp/rand-fig  /tmp/read-fig
yubico-piv-tool -r "$RDID" -a change-pin -N 123456 -P 654321

echo "=== All PIV tests passed ==="
