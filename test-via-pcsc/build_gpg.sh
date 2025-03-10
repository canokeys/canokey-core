#!/bin/bash

set -e
mkdir -m 700 ~/.gnupg || true
echo -e 'pinentry-program /usr/local/bin/pinentry-tty\ndebug-pinentry\ndebug 1024\nlog-file /tmp/agent.log\n' >~/.gnupg/gpg-agent.conf
cat >~/.gnupg/scdaemon.conf <<EOF
pcsc-driver /usr/lib/x86_64-linux-gnu/libpcsclite.so.1
disable-ccid
EOF

sudo tee /etc/apt/sources.list <<EOF
deb http://archive.ubuntu.com/ubuntu/ noble main restricted universe multiverse
deb-src http://archive.ubuntu.com/ubuntu/ noble main restricted universe multiverse

deb http://archive.ubuntu.com/ubuntu/ noble-updates main restricted universe multiverse
deb-src http://archive.ubuntu.com/ubuntu/ noble-updates main restricted universe multiverse
EOF

gpg-connect-agent reloadagent /bye
gpgconf --list-components
 
sudo apt-get update
sudo apt-get build-dep -q -y pinentry-tty

mkdir gnupg || true
pushd gnupg

if [ ! -d pinentry-1.2.1 ];then
    wget https://gnupg.org/ftp/gcrypt/pinentry/pinentry-1.2.1.tar.bz2
    tar -xf pinentry-1.2.1.tar.bz2

    pushd pinentry-1.2.1
    patch -p1 < ../../test-via-pcsc/pinentry-mock.patch
    ./configure --disable-pinentry-qt --enable-pinentry-tty --disable-pinentry-curses --disable-pinentry-gtk2
    make -j2
else
    pushd pinentry-1.2.1
fi
sudo make install
popd

sudo ln -sf  /usr/local/bin/pinentry-tty  /usr/bin/pinentry

popd
