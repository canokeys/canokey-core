#!/bin/bash
HONGGFUZZ="$1"
INDEX="$2"
DATA_DIR="fuzzing/applet$INDEX/data"
WORK_DIR="fuzzing/applet$INDEX/working"
mkdir -p "$DATA_DIR"
mkdir -p "$WORK_DIR"
echo '00 01 00 00' > "$DATA_DIR/initial"
"$HONGGFUZZ" -Q --linux_perf_ipt_block --exit_upon_crash -T -t 10 -n 1 -P -f "$DATA_DIR" -W "$WORK_DIR" -- build/honggfuzz-fuzzer "$INDEX"
# --linux_perf_branch

# build `honggfuzz-fuzzer` in `build/` with: env CC=/opt/honggfuzz-2.4/usr/local/bin/hfuzz-cc cmake ..  -DENABLE_FUZZING=ON -DENABLE_TESTS=OFF -DENABLE_DEBUG_OUTPUT=OFF -DCMAKE_BUILD_TYPE=Debug
# run: ./fuzzer/run-fuzzer.sh /opt/honggfuzz-2.4/usr/local/bin/honggfuzz 4
# show converage: lcov --gcov-tool $PWD/llvm-gcov.sh  -d build -b . --no-external -c -o coverage.info;genhtml coverage.info  --output-directory CoverageReport/