#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
export LANGUAGE=en_US
export LANG=en_US.UTF8
export TEST_TMP_DIR=/tmp/canokey-libfido2
export USER=`id -nu`
PIN=123456
NON_TTY="setsid -w"

oneTimeSetUp() {
    rm -rf "$TEST_TMP_DIR"
    mkdir "$TEST_TMP_DIR"
    killall -u $USER -9 gpg-agent && sleep 2 || true
    export RDID=$(fido2-token -L | grep -Po '^pcsc:.*(?=: )' | tail -n 1)
}

ToolHelper() {
    # echo "PIN is $PIN"
    echo $PIN | $NON_TTY $* "$RDID" #2>/dev/null
    echo "" 1>&2
}

FIDO2MakeCred() {
    rpid=$1
    username=$2
    openssl rand -base64 32 >"$TEST_TMP_DIR/cred_param" # client data hash
    echo "$rpid" >>"$TEST_TMP_DIR/cred_param"
    echo "$username" >>"$TEST_TMP_DIR/cred_param"
    openssl rand -base64 64 >>"$TEST_TMP_DIR/cred_param" # user id
    ToolHelper fido2-cred -M -r -i "$TEST_TMP_DIR/cred_param" | fido2-cred -V -o "$TEST_TMP_DIR/cred"
}

FIDO2ListRP() {
    nrRk=$(ToolHelper fido2-token -I -c | grep 'existing rk')
    echo "$nrRk"
    if [[ $nrRk != *" 0" ]]; then
        ToolHelper fido2-token -L -r
    fi
}

makeRPID() {
    # MAX_STORED_RPID_LENGTH=32
    printf "RPID_aaaaaaaaaaaaabbbbbbbbbbbb%02x" $1
}

makeUserName() {
    # USER_NAME_LIMIT=65
    printf "USERNAME_aaaaaaaaaaaaabbbbbbbbbbbb_ccccccccccccccdddddddddddddd%02x" $1
}

test_Reset() {
    fido2-token -R "$RDID"
    # Set PIN
    PIN=$'123456\r123456\r'
    ToolHelper fido2-token -S
    PIN=123456
}

test_ListRK() {
    FIDO2ListRP
}

test_MC() {
    for((i=1;i<=64;i++)); do
        FIDO2MakeCred $(makeRPID $i) $(makeUserName $i)
    done
    nline=0
    while IFS= read -r line
    do
        if [[ $nline == 0 ]]; then
            assertEquals 'existing rk(s): 64' "$line"
        else
            fields=($line)
            assertEquals $(makeRPID $nline) ${fields[2]}
        fi
        ((nline++))
    done < <(FIDO2ListRP)
}

. ./shunit2/shunit2
