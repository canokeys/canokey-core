#!/bin/bash
set -e
GPG_VER=2.2.12
mkdir ~/.gnupg || true
echo "pinentry-program /usr/local/bin/pinentry-tty" >~/.gnupg/gpg-agent.conf
mkdir gnupg || true
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
if [ ! -d gnupg-$GPG_VER ];then
    wget https://gnupg.org/ftp/gcrypt/gnupg/gnupg-$GPG_VER.tar.bz2
    tar -xf gnupg-$GPG_VER.tar.bz2
    pushd gnupg-$GPG_VER
    ./configure --prefix=/usr --disable-doc --disable-wks-tools --disable-gpgtar --disable-photo-viewers --disable-ldap
    make -j2
else
    pushd gnupg-$GPG_VER
fi
sudo make install
popd
popd
