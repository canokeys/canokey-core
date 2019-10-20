#!/bin/bash
HONGGFUZZ="$1"
INDEX="$2"
DATA_DIR="fuzzing/applet$INDEX/data"
WORK_DIR="fuzzing/applet$INDEX/working"
mkdir -p "$DATA_DIR"
mkdir -p "$WORK_DIR"
echo '00 01 00 00' > "$DATA_DIR/initial"
"$HONGGFUZZ" -Q --exit_upon_crash  -n 1 -P -f "$DATA_DIR" -W "$WORK_DIR" -- build/honggfuzz-fuzzer "$INDEX"
