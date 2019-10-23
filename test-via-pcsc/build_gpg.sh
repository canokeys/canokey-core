#!/bin/bash
set -e
mkdir ~/.gnupg || true
echo "pinentry-program /usr/local/bin/pinentry-tty" >~/.gnupg/gpg-agent.conf
mkdir gnupg
pushd gnupg
if [ ! -d pinentry-1.1.0 ];then
    wget https://gnupg.org/ftp/gcrypt/pinentry/pinentry-1.1.0.tar.bz2
    tar -xf pinentry-1.1.0.tar.bz2
    patch -p1 <../test-via-pcsc/pinentry-mock.patch
    pushd pinentry-1.1.0
    ./configure --disable-pinentry-qt --enable-pinentry-tty --disable-pinentry-curses --disable-pinentry-gtk2
    make -j2
else
    pushd pinentry-1.1.0
fi
sudo make install
popd
if [ ! -d gnupg-2.2.17 ];then
    wget https://gnupg.org/ftp/gcrypt/gnupg/gnupg-2.2.17.tar.bz2
    tar -xf gnupg-2.2.17.tar.bz2
    pushd gnupg-2.2.17
    ./configure --prefix=/usr --disable-doc --disable-wks-tools --disable-gpgtar --disable-photo-viewers --disable-ldap
    make -j2
else
    pushd gnupg-2.2.17
fi
sudo make install
popd
popd
