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
    grep -v "Enter PIN " "$TEST_TMP_DIR/stderr" 1>&2 || true
}

FIDO2MakeCred() {
    rpid=$1
    username=$2
    userid=$(dd status=none if=/dev/urandom bs=64 count=1 | base64 -w 0)
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
    echo "$nrRk" # existing rk(s): 64
    if [[ $nrRk != *" 0" ]]; then
        # Idx Credential                                   RpID
        # 00: NBuC7jAK2Ty/3ileQvETIZ8BUQ+93GoraEm3Su3KvC0= RPID_aaaaaaaaaaaaabbbbbbbbbbbb01
        ToolHelper fido2-token -L -r
    fi
}

FIDO2SetName() {
    credid="$1"
    userid="$2"
    name="$3"
    display_name="$4"
    echo "Set Cred[$credid] User[$userid] to $name $display_name"
    ToolHelper fido2-token -S -c -i "$credid" -k "$userid" -n "$name" -p "$display_name"
}

FIDO2GetRkByRp() {
    # Idx: CredID DispName UserID Algo Prot
    # 00: +CSO/Hjxmj8YJ0Iv+TQw018+a+8y+AE36XlODTT6vhUBADQbgu4wCtk8v94pXkLxEyGfAVEPvdxqK2hJt0rtyrwtd+Az/H8AABB24DP8fwAA/7CVQft/AAAAAAAAAAAAACB1+f///w== DispName E+It8WJq4TJbPzfjSqeJDPpP+XkKVMBzIAk0sKAVu8IaZDhG2vOEH4rqw0eP6yWg es256 unknown
    ToolHelper fido2-token -L -k "$1"
}

FIDO2DelRkByID() {
    ToolHelper fido2-token -D -i "$1" -n "$2"
}

makeRPID() {
    # MAX_STORED_RPID_LENGTH=32
    printf "RPID_aaaaaaaaaaaaabbbbbbbbbbbb%02x" $1
}

makeUserName() {
    # USER_NAME_LIMIT=65-1
    printf "USERNAME_aaaaaaaaaaaabbbbbbbbbbbb_ccccccccccccccdddddddddddddd%02x" $1
}

makeDispName() {
    # USER_NAME_LIMIT=65-1
    printf "DisplayName_AAAAAAAAAAAAAAAAA_XXXXXXXXXX_YYYYYYYYYYYYYYYYYYYYY%02x" $1
}

makeCredAndStore() {
    fields=($(FIDO2MakeCred $1 $2))
    userid=${fields[0]}
    credid=${fields[1]}
    echo $1 $userid $2 $credid | tee -a "$TEST_TMP_DIR/rks"
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
    echo $'RelyingPartyID                   UserID                                                                                UserName                                                          CredID'
    >"$TEST_TMP_DIR/rks"
    for((i=1;i<=64;i++)); do
        rpid=$(makeRPID $i)
        uname=$(makeUserName $i)
        makeCredAndStore "$rpid" "$uname"
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
    randSeq=$(seq 1 64 | shuf)
    for i in $randSeq; do
        rpid=$(makeRPID $i)
        fields=($(grep $rpid "$TEST_TMP_DIR/rks"))
        userid=${fields[1]}
        credid=${fields[3]}
        display_name=$(makeDispName $i)
        user_name="new_username$i"
        FIDO2SetName "$credid" "$userid" "$user_name" "$display_name"
        fields=($(FIDO2GetRkByRp $rpid))
        assertEquals "$credid"       "${fields[1]}"
        assertEquals "$display_name" "${fields[2]}"
        assertEquals "$userid"       "${fields[3]}"
        assertEquals es256           "${fields[4]}"
    done

}

test_DelRk() {
    randSeq=$(seq 1 64 | shuf)
    for i in $randSeq; do
        rpid=$(makeRPID $i)
        fields=($(grep $rpid "$TEST_TMP_DIR/rks"))
        credid=${fields[3]}
        FIDO2DelRkByID $credid $rpid
        sed -i "/$rpid/d" "$TEST_TMP_DIR/rks"
    done
}

# test_Debug() {
#     FIDO2MakeCred rp1 un2
#     FIDO2GetRkByRp RPID_aaaaaaaaaaaaabbbbbbbbbbbb01
#     FIDO2DelRkByID "6AwF68LTVupyLx5ddpFRQiPS9+UmkSktTXYWREijOjIBAGO0QIKafRKTv8hiGj4aZxPQSQbfySYyH7CGSbLfBM8/d+Az/H8AABB24DP8fwAA/7CVQft/AAAAAAAAAAAAACB1+f///w==" RPID_aaaaaaaaaaaaabbbbbbbbbbbb40
# }

. ./shunit2/shunit2
