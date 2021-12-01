#!/bin/bash
if [ -z "$1" ]; then
    exit 1
fi
echo "Reader name: $1"
TS=$(printf %08x $(date +%s))
(cat <<-EOF
00A4040005F000000000
00500000055245534554
EOF
) | scriptor -r "$1"
