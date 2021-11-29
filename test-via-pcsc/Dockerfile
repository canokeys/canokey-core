FROM ubuntu:20.04


ARG UBUNTU_MIRROR
RUN [ -z "${UBUNTU_MIRROR}" ] || sed -i.bak s/archive.ubuntu.com/${UBUNTU_MIRROR}/g /etc/apt/sources.list

RUN apt update && DEBIAN_FRONTEND=noninteractive apt install -y -q software-properties-common golang-go gcc g++ cmake swig psmisc procps pcscd pcsc-tools yubico-piv-tool libassuan-dev libgcrypt20-dev libksba-dev libnpth0-dev opensc openssl openssh-server libpcsclite-dev libcmocka-dev python3-pip python3-setuptools python3-wheel lcov &&\
    apt-add-repository -y ppa:yubico/stable && DEBIAN_FRONTEND=noninteractive apt install -y -q yubikey-manager
RUN pip3 install --upgrade pip
RUN ./test-via-pcsc/build_gpg.sh && gpg --version
RUN git clone --depth 1 https://github.com/google/u2f-ref-code.git && \
        pushd u2f-ref-code/u2f-tests/HID && \
        git clone --depth 1 -b lollipop-release https://android.googlesource.com/platform/system/core && \
        cd ../NFC; make && \
        popd && \
        git clone --depth 1 https://github.com/canokeys/fido2-tests.git && \
        pushd fido2-tests; pip3 install --user -r requirements.txt; popd

RUN echo -e '\
StrictModes no \n\
UsePAM no \n\
Port 2200 \n\
' >/etc/sshd_config

RUN go test -v test-via-pcsc/admin_test.go &&\
    go test -v test-via-pcsc/ndef_test.go &&\
    go test -v test-via-pcsc/openpgp_test.go &&\
    go test -v test-via-pcsc/oath_test.go # build tests
