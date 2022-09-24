#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
export LANGUAGE=en_US
export LANG=en_US.UTF8
export TEST_TMP_DIR=/tmp/canokey-libfido2
export USER=`id -nu`
PIN=123456
NON_TTY="setsid -w"

oneTimeSetUp() {
    # rm -rf "$TEST_TMP_DIR"
    mkdir -p "$TEST_TMP_DIR"
    killall -u $USER -9 gpg-agent && sleep 2 || true
    export RDID=$(fido2-token -L | grep -Po '^pcsc:.*(?=: )' | tail -n 1)
}

ToolHelper() {
    # echo "PIN is $PIN"
    echo $PIN | $NON_TTY $* "$RDID" 2>"$TEST_TMP_DIR/stderr"
    grep -v "Enter PIN " "$TEST_TMP_DIR/stderr" 1>&2
}

FIDO2MakeCred() {
    rpid=$1
    username=$2
    userid=$(openssl rand -base64 64)
    openssl rand -base64 32 >"$TEST_TMP_DIR/cred_param" # client data hash
    echo "$rpid" >>"$TEST_TMP_DIR/cred_param"
    echo "$username" >>"$TEST_TMP_DIR/cred_param"
    echo "$userid" >>"$TEST_TMP_DIR/cred_param" # user id
    ToolHelper fido2-cred -M -r -i "$TEST_TMP_DIR/cred_param" | fido2-cred -V -o "$TEST_TMP_DIR/cred"
    credid=$(head -n 1 "$TEST_TMP_DIR/cred")
    echo $userid $credid
}

FIDO2ListRP() {
    nrRk=$(ToolHelper fido2-token -I -c | grep 'existing rk')
    echo "$nrRk"
    if [[ $nrRk != *" 0" ]]; then
        ToolHelper fido2-token -L -r
    fi
}

FIDO2SetName() {
    cred_id="$1"
    user_id="$2"
    name="$3"
    display_name="$4"
    ToolHelper fido2-token -S -c -i "$cred_id" -k "$user_id" -n "$name" -p "$display_name"
}

FIDO2GetRkByRp() {
    ToolHelper fido2-token -L -k "$1"
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
    echo $'RelyingPartyID                   UserID                                                           UserName                                                          CredID'
    >"$TEST_TMP_DIR/rks"
    for((i=1;i<=64;i++)); do
        rpid=$(makeRPID $i)
        uname=$(makeUserName $i)
        fields=($(FIDO2MakeCred $rpid $uname))
        userid=${fields[0]}
        credid=${fields[1]}
        echo $rpid $userid $uname $credid | tee -a "$TEST_TMP_DIR/rks"
    done
    nline=0
    while IFS= read -r line
    do
        if [[ $nline == 0 ]]; then
            assertEquals 'existing rk(s): 64' "$line"
        else
            fields=($line)
            rpid=$(makeRPID $nline)
            assertEquals $rpid ${fields[2]}
        fi
        ((nline++))
    done < <(FIDO2ListRP)
}

test_DispName() {
    for nline in 1 ;do #32 64
        golden=($(sed -ne "${line}p" "$TEST_TMP_DIR/rks"))
        rpid=${golden[0]}
        userid=${golden[1]}
        credid=${golden[3]}
        display_name=DISP_NAME
        FIDO2SetName "$credid" "$userid" myasdf "$display_name"
        fields=($(FIDO2GetRkByRp $rpid))
        assertEquals "$display_name" "${fields[2]}"
        assertEquals "$userid"       "${fields[3]}"
        assertEquals es256           "${fields[4]}"
    done

}

. ./shunit2/shunit2
