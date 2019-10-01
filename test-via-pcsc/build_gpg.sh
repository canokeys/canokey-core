#!/bin/bash
set -e
mkdir gnupg
pushd gnupg
wget https://gnupg.org/ftp/gcrypt/pinentry/pinentry-1.1.0.tar.bz2
tar -xf pinentry-1.1.0.tar.bz2
patch -p1 <../test-via-pcsc/pinentry-mock.patch
pushd pinentry-1.1.0
./configure --disable-pinentry-qt --enable-pinentry-tty --disable-pinentry-curses --disable-pinentry-gtk2
make -j2
sudo make install
popd
wget https://gnupg.org/ftp/gcrypt/gnupg/gnupg-2.2.17.tar.bz2
tar -xf gnupg-2.2.17.tar.bz2
pushd gnupg-2.2.17
./configure --disable-doc --disable-wks-tools --disable-gpgtar --enable-gpg-is-gpg2 --disable-photo-viewers --disable-ldap
make -j2
sudo make install
popd
popd
