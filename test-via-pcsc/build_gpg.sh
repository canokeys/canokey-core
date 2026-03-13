#!/bin/bash
# Build patched pinentry-tty (only runs on cache miss)
set -e

sudo tee /etc/apt/sources.list <<EOF
deb http://archive.ubuntu.com/ubuntu/ noble main restricted universe multiverse
deb-src http://archive.ubuntu.com/ubuntu/ noble main restricted universe multiverse

deb http://archive.ubuntu.com/ubuntu/ noble-updates main restricted universe multiverse
deb-src http://archive.ubuntu.com/ubuntu/ noble-updates main restricted universe multiverse
EOF

sudo apt-get update
sudo apt-get build-dep -q -y pinentry-tty

mkdir -p gnupg
pushd gnupg

if [ ! -d pinentry-1.2.1 ]; then
    wget https://gnupg.org/ftp/gcrypt/pinentry/pinentry-1.2.1.tar.bz2
    tar -xf pinentry-1.2.1.tar.bz2
    rm -f pinentry-1.2.1.tar.bz2
fi

pushd pinentry-1.2.1
patch -p1 --forward < ../../test-via-pcsc/pinentry-mock.patch || true
./configure --disable-pinentry-qt --enable-pinentry-tty --disable-pinentry-curses --disable-pinentry-gtk2
make -j2
popd

popd
