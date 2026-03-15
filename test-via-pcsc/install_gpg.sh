#!/bin/bash
# Install patched pinentry-tty + configure gpg-agent (runs every time)
set -e

# install then remove, only for its dependencies
sudo apt-get install -q -y pinentry-tty libsecret-1-0
sudo apt-get remove -q -y pinentry-tty

mkdir -m 700 ~/.gnupg || true
cat >~/.gnupg/gpg-agent.conf <<EOF
pinentry-program /usr/local/bin/pinentry-tty
debug-pinentry
debug 1024
log-file /tmp/agent.log
EOF
cat >~/.gnupg/scdaemon.conf <<EOF
pcsc-driver /usr/lib/x86_64-linux-gnu/libpcsclite.so.1
disable-ccid
EOF

# Copy the pre-built binary directly — avoid `make install` which
# recurses into all subdirs (gnome3, etc.) and triggers recompilation.
sudo install -m 755 gnupg/pinentry-1.2.1/tty/pinentry-tty /usr/local/bin/pinentry-tty
/usr/local/bin/pinentry-tty --version

sudo ln -sf /usr/local/bin/pinentry-tty /usr/bin/pinentry
gpg-connect-agent reloadagent /bye || true
