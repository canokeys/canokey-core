#!/bin/bash
# Install patched pinentry-tty + configure gpg-agent (runs every time)
set -e

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

pushd gnupg/pinentry-1.2.1
sudo make install
popd

sudo ln -sf /usr/local/bin/pinentry-tty /usr/bin/pinentry
gpg-connect-agent reloadagent /bye || true
