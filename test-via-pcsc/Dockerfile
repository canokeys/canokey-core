FROM ubuntu:24.04

ARG UBUNTU_MIRROR
RUN if [ -n "${UBUNTU_MIRROR}" ]; then \
        if [ -s /etc/apt/sources.list ]; then \
            sed -i.bak "s|http://archive.ubuntu.com/ubuntu|${UBUNTU_MIRROR}|g" /etc/apt/sources.list; \
        elif [ -f /etc/apt/sources.list.d/ubuntu.sources ]; then \
            sed -i.bak "s|http://archive.ubuntu.com/ubuntu|${UBUNTU_MIRROR}|g" /etc/apt/sources.list.d/ubuntu.sources; \
        fi; \
    fi

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y -q \
    sudo software-properties-common git gcc g++ cmake swig psmisc procps \
    pcscd pcsc-tools yubico-piv-tool libhidapi-dev libassuan-dev \
    libgcrypt20-dev libksba-dev libnpth0-dev opensc openssl openssh-server \
    libssl-dev libpcsclite-dev libudev-dev libusb-1.0-0-dev libcmocka-dev libcbor-dev \
    python3-pip python3-setuptools python3-wheel lcov wget golang-go \
    yubikey-manager

COPY go.mod go.sum /root/
COPY test-via-pcsc /root/test-via-pcsc
COPY test-real /root/test-real
RUN ls -la /root

RUN cd /root && ./test-via-pcsc/build_fido_tests.sh && ./test-via-pcsc/install_fido_tests.sh
RUN cd /root && ./test-via-pcsc/build_gpg.sh && ./test-via-pcsc/install_gpg.sh && gpg --version
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
