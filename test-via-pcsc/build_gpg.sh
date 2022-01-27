#!/bin/bash
set -e
mkdir ~/.gnupg || true
echo "pinentry-program /usr/local/bin/pinentry-tty" >~/.gnupg/gpg-agent.conf
mkdir gnupg || true
pushd gnupg
# Remove old versions on system
sudo rm /usr/lib/x86_64-linux-gnu/pkgconfig/gpg-error.pc
sudo rm /usr/lib/x86_64-linux-gnu/pkgconfig/libgcrypt.pc
sudo rm /usr/include/x86_64-linux-gnu/gpg*
sudo rm /usr/lib/x86_64-linux-gnu/libgpg-error.*
sudo rm /usr/lib/x86_64-linux-gnu/libgcrypt.*
if [ ! -d libgpg-error-1.42 ];then
    wget https://gnupg.org/ftp/gcrypt/libgpg-error/libgpg-error-1.42.tar.bz2
    tar -xf libgpg-error-1.42.tar.bz2
    pushd libgpg-error-1.42
    ./configure --prefix=/usr
    make -j2
else
    pushd libgpg-error-1.42
fi
sudo make install
popd
if [ ! -d libgcrypt-1.9.4 ];then
    wget https://gnupg.org/ftp/gcrypt/libgcrypt/libgcrypt-1.9.4.tar.bz2
    tar -xf libgcrypt-1.9.4.tar.bz2
    pushd libgcrypt-1.9.4
    ./configure --prefix=/usr
    make -j2
else
    pushd libgcrypt-1.9.4
fi
sudo make install
popd
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
if [ ! -d gnupg-2.3.4 ];then
    wget https://gnupg.org/ftp/gcrypt/gnupg/gnupg-2.3.4.tar.bz2
    tar -xf gnupg-2.3.4.tar.bz2
    pushd gnupg-2.3.4
    ./configure --prefix=/usr --disable-doc --disable-wks-tools --disable-gpgtar --disable-photo-viewers --disable-ldap
    make -j2
else
    pushd gnupg-2.3.4
fi
sudo make install
popd
popd
