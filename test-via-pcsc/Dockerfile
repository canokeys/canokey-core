FROM ubuntu:20.04


ARG UBUNTU_MIRROR
RUN [ -z "${UBUNTU_MIRROR}" ] || sed -i.bak s/archive.ubuntu.com/${UBUNTU_MIRROR}/g /etc/apt/sources.list

RUN apt update && DEBIAN_FRONTEND=noninteractive apt-get install -y -q sudo software-properties-common golang-go git gcc g++ cmake swig psmisc procps pcscd pcsc-tools yubico-piv-tool libassuan-dev libgcrypt20-dev libksba-dev libnpth0-dev opensc openssl openssh-server libpcsclite-dev libcmocka-dev python3-pip python3-setuptools python3-wheel lcov &&\
    apt-add-repository -y ppa:yubico/stable && DEBIAN_FRONTEND=noninteractive apt-get install -y -q yubikey-manager
RUN pip3 install --upgrade pip

COPY go.mod go.sum /root/
COPY test-via-pcsc /root/test-via-pcsc
COPY test-real /root/test-real
RUN ls -la /root

RUN cd /root && ./test-via-pcsc/build_gpg.sh && gpg --version
RUN cd /root && ./test-via-pcsc/build_fido_tests.sh
RUN cp /root/test-real/libccid_Info.plist /etc/libccid_Info.plist && echo -e '\
StrictModes no \n\
UsePAM no \n\
Port 2200 \n\
' >/etc/sshd_config

RUN cd /root &&\
    go test -v test-via-pcsc/admin_test.go ;\
    go test -v test-via-pcsc/ndef_test.go ;\
    go test -v test-via-pcsc/openpgp_test.go ;\
    go test -v test-via-pcsc/oath_test.go ;\
    true # build tests

WORKDIR /root
USER root
