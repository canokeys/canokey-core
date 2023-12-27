#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
export LANGUAGE=en_US
export LANG=en_US.UTF8
export TEST_TMP_DIR=/tmp/canokey-libfido2
export USER=`id -nu`
PIN=123456
NUMBER_OF_KEYS=8
NON_TTY="setsid -w"
ALGO_LIST=(es256 eddsa rs256)

oneTimeSetUp() {
    # rm -rf "$TEST_TMP_DIR"
    mkdir -p "$TEST_TMP_DIR"
    killall -u $USER -9 gpg-agent && sleep 2 || true
    export RDID=$(fido2-token -L | grep -Po '^(pcsc:|/dev).*(?=: )' | tail -n 1)
}

ToolHelper() {
    # echo "PIN is $PIN"
    echo $PIN | $NON_TTY $* "$RDID" 2>"$TEST_TMP_DIR/stderr"
    local res=$?
    sed -i -E 's/Enter.*PIN for \S+ *//g' "$TEST_TMP_DIR/stderr"
    cat "$TEST_TMP_DIR/stderr" 1>&2
    return $res
}

FIDO2MakeCred() {
    local rpid=$1
    local username=$2
    local userid=$(dd status=none if=/dev/urandom bs=64 count=1 | base64 -w 0)
    local algo=${ALGO_LIST[$(($RANDOM%3))]}
    openssl rand -base64 32 >"$TEST_TMP_DIR/cred_param" # client data hash
    assertTrue "openssl failed" $?
    echo "$rpid" >>"$TEST_TMP_DIR/cred_param"
    echo "$username" >>"$TEST_TMP_DIR/cred_param"
    echo "$userid" >>"$TEST_TMP_DIR/cred_param" # user id
    ToolHelper fido2-cred -M -r -b -i "$TEST_TMP_DIR/cred_param" $algo >"$TEST_TMP_DIR/mc"
    assertTrue "fido2-cred -M failed" $?
    local largeBlobKey=$(tail -n 1 "$TEST_TMP_DIR/mc")
    head -n -1 "$TEST_TMP_DIR/mc" | fido2-cred -V -o "$TEST_TMP_DIR/verified" $algo
    local ret=$?
    assertTrue "fido2-cred -V failed" $ret
    if [[ $ret != 0 ]];then
        return 1
    fi
    local credid=$(head -n 1 "$TEST_TMP_DIR/verified")
    echo $userid $credid $largeBlobKey $algo
}

FIDO2GetAssert() {
    local rpid=$1
    local credid=$2
    local algo=$3
    local userid=$(dd status=none if=/dev/urandom bs=64 count=1 | base64 -w 0)
    openssl rand -base64 32 >"$TEST_TMP_DIR/assert_param" # client data hash
    echo "$rpid" >>"$TEST_TMP_DIR/assert_param"
    echo "$credid" >>"$TEST_TMP_DIR/assert_param"
    ToolHelper fido2-assert -G -b -i "$TEST_TMP_DIR/assert_param" $algo >"$TEST_TMP_DIR/assert"
    assertTrue "fido2-assert -G failed" $?
    local largeBlobKey=$(tail -n 1 "$TEST_TMP_DIR/assert")
    echo $largeBlobKey
}

FIDO2ListRP() {
    local nrRk=$(ToolHelper fido2-token -I -c | grep 'existing rk')
    echo "$nrRk" # existing rk(s): 64
    if [[ $nrRk != *" 0" ]]; then
        # Idx Credential                                   RpID
        # 00: NBuC7jAK2Ty/3ileQvETIZ8BUQ+93GoraEm3Su3KvC0= RPID_aaaaaaaaaaaaabbbbbbbbbbbb01
        ToolHelper fido2-token -L -r
        assertTrue "FIDO2ListRP failed" $?
    fi
}

FIDO2GetRkByRp() {
    # Idx: CredID DispName UserID Algo Prot
    # 00: +CSO/Hjxmj8YJ0Iv+TQw018+a+8y+AE36XlODTT6vhUBADQbgu4wCtk8v94pXkLxEyGfAVEPvdxqK2hJt0rtyrwtd+Az/H8AABB24DP8fwAA/7CVQft/AAAAAAAAAAAAACB1+f///w== DispName E+It8WJq4TJbPzfjSqeJDPpP+XkKVMBzIAk0sKAVu8IaZDhG2vOEH4rqw0eP6yWg es256 unknown
    ToolHelper fido2-token -L -k "$1"
    assertTrue "FIDO2GetRkByRp failed" $?
}

FIDO2ListRK() {
    local rps=$(FIDO2ListRP)
    while IFS= read -r rp_line
    do
        local fields=($rp_line)
        if [[ ${fields[0]} == [0-9][0-9]: ]]; then
            rpid=${fields[2]}
            FIDO2GetRkByRp $rpid
        fi
    done <<< "$rps"
}

FIDO2SetName() {
    local credid="$1"
    local userid="$2"
    local name="$3"
    local display_name="$4"
    echo "Set Cred[$credid] User[$userid] to $name $display_name"
    ToolHelper fido2-token -S -c -i "$credid" -k "$userid" -n "$name" -p "$display_name"
    assertTrue "FIDO2SetName failed" $?
}

FIDO2SetBlob() {
    local rpid="$1"
    local credid="$2"
    local blobPath="$TEST_TMP_DIR/blob"
    echo "Set LB of RP[$rpid] Cred[$credid] to $blobPath"
    echo "  with Key:" $(cat "$TEST_TMP_DIR/blobkey")
    ToolHelper fido2-token -Sb -k "$TEST_TMP_DIR/blobkey" "$blobPath"
    # 
    # ToolHelper fido2-token -Sb -n "$rpid" -i "$credid" "$blobPath"
    local ret=$?
    assertTrue "FIDO2SetBlob failed" $ret
    return $ret
}

FIDO2DelBlob() {
    local rpid="$1"
    local credid="$2"
    echo "Del LB of RP[$rpid] Cred[$credid]"
    # echo "With Key:" $(cat "$TEST_TMP_DIR/blobkey")
    # -k "$TEST_TMP_DIR/blobkey"
    ToolHelper fido2-token -Db -n "$rpid" -i "$credid"
    local ret=$?
    assertTrue "FIDO2DelBlob failed" $ret
    return $ret
}

FIDO2GetBlob() {
    local rpid="$1"
    local credid="$2"
    local blobPath="$TEST_TMP_DIR/blob_read"
    echo "Get LB of RP[$rpid] Cred[$credid]"
    # echo "With Key:" $(cat "$TEST_TMP_DIR/blobkey")
    # ToolHelper fido2-token -Gb -k "$TEST_TMP_DIR/blobkey" "$blobPath"
    >"$blobPath"
    ToolHelper fido2-token -Gb -n "$rpid" -i "$credid" "$blobPath"
    local ret=$?
    assertTrue "FIDO2GetBlob failed" $ret
    return $ret
}

FIDO2DelRkByID() {
    echo "Deleting cred: $1"
    ToolHelper fido2-token -D -i "$1"
    assertTrue "FIDO2DelRkByID failed" $?
}

compareAllRk() {
    local allRk=""
    local rps=$(FIDO2ListRP)
    while IFS= read -r rp_line
    do
        local fields=($rp_line)
        if [[ ${fields[0]} == [0-9][0-9]: ]]; then
            local rpid=${fields[2]}
            local rks=$(FIDO2GetRkByRp $rpid)
            while IFS= read -r rk_line
            do
                fields=($rk_line)
                # RpID UserID CredID
                allRk+="$rpid ${fields[3]} ${fields[1]}"
                allRk+=$'\n'
            done <<< "$rks"
        fi
    done <<< "$rps"
    echo -n "$allRk" | sort > "$TEST_TMP_DIR/sorted_allRk"
    awk '{print $1,$2,$4}' "$TEST_TMP_DIR/rks" | sort | diff -w "$TEST_TMP_DIR/sorted_allRk" -
}

makeRPID() {
    # MAX_STORED_RPID_LENGTH=32
    printf "RPID_aaaaaaaaaaaaabbbbbbbbbbbb%02x" $1
}

makeBlob() {
    # Length = 64
    printf "LargeBlob_aaaaaaaaaaaabbbbbbbbbbb_ccccccccccccccdddddddddddddd%02x" $1
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
    local fields
    # "$1=rpid" "$2=uname"
    fields=($(FIDO2MakeCred $1 $2))
    if [[ $? != 0 ]]; then
        return 1
    fi
    local userid=${fields[0]}
    local credid=${fields[1]}
    local algo=${fields[3]}
    # RpID UserID UserName CredID Algorithm
    echo $1 $userid $2 $credid $algo | tee -a "$TEST_TMP_DIR/rks"
}

setPINforTest() {
    # Set PIN
    local origPin=$PIN
    PIN=$origPin$'\r'$origPin$'\r'
    ToolHelper fido2-token -S
    PIN=$origPin
}

test_Reset() {
    fido2-token -R "$RDID"
    if [[ $? != 0 ]];then
        echo "Cannot reset the key"
    fi
    setPINforTest
}

test_List() {
    FIDO2ListRP
    FIDO2ListRK
}

test_DelAllRk() {
    local rps=$(FIDO2ListRK)
    while IFS= read -r rp_line
    do
        local fields=($rp_line)
        if [[ ${fields[0]} == [0-9][0-9]: ]]; then
            local credid=${fields[1]}
            FIDO2DelRkByID $credid
        fi
    done <<< "$rps"
}

test_MC() {
    echo $'RelyingPartyID                   UserID                                                                                UserName                                                          CredID'
    >"$TEST_TMP_DIR/rks"
    for((i=1;i<=$NUMBER_OF_KEYS;i++)); do
        local rpid=$(makeRPID $i)
        local uname=$(makeUserName $i)
        makeCredAndStore "$rpid" "$uname" || return 1
    done
    local nline=0
    while IFS= read -r line
    do
        if [[ $nline == 0 ]]; then
            assertEquals "existing rk(s): $NUMBER_OF_KEYS" "$line"
        else
            local fields=($line)
            rpid=$(makeRPID $nline)
            assertEquals $rpid ${fields[2]}
        fi
        ((nline++))
    done < <(FIDO2ListRP)
}

test_DispName() {
    local randSeq=$(seq 1 $NUMBER_OF_KEYS | shuf)
    for i in $randSeq; do
        local rpid=$(makeRPID $i)
        local fields=($(grep $rpid "$TEST_TMP_DIR/rks"))
        if [[ ${#fields[@]} != 4 ]];then
            break;
        fi
        local userid=${fields[1]}
        local credid=${fields[3]}
        local display_name=$(makeDispName $i)
        local user_name="new_username$i"
        FIDO2SetName "$credid" "$userid" "$user_name" "$display_name"
        fields=($(FIDO2GetRkByRp $rpid))
        assertEquals "$credid"       "${fields[1]}"
        assertEquals "$display_name" "${fields[2]}"
        assertEquals "$userid"       "${fields[3]}"
        assertEquals es256           "${fields[4]}"
    done

}

test_LargeBlob() {
    ToolHelper fido2-token -L -b
    local nrLB=8
    local randSeq=$(seq 1 $nrLB | shuf)
    for i in $randSeq; do
        local rpid=$(makeRPID $i)
        local fields=($(grep $rpid "$TEST_TMP_DIR/rks"))
        if [[ ${#fields[@]} < 5 ]];then
            break;
        fi
        local credid=${fields[3]}
        local algo=${fields[4]}
        fields=($(FIDO2GetAssert "$rpid" "$credid" $algo))
        echo ${fields[0]} > "$TEST_TMP_DIR/blobkey"
        makeBlob $i > "$TEST_TMP_DIR/blob"
        FIDO2SetBlob "$rpid" "$credid" || return 1
    done
    randSeq=$(seq 1 $nrLB | shuf)
    for i in $randSeq; do
        rpid=$(makeRPID $i)
        fields=($(grep "$rpid" "$TEST_TMP_DIR/rks"))
        if [[ ${#fields[@]} < 4 ]];then
            break;
        fi
        credid=${fields[3]}
        FIDO2GetBlob "$rpid" "$credid" || return 1
        echo "$rpid: $(cat $TEST_TMP_DIR/blob_read)"
        makeBlob $i | diff "$TEST_TMP_DIR/blob_read" -
        if [[ $? != 0 ]]; then
            return 1
        fi
        FIDO2DelBlob "$rpid" "$credid"
    done
}

test_DelRk() {
    local randSeq=$(seq 1 $NUMBER_OF_KEYS | shuf)
    local nrDel=0
    for i in $randSeq; do
        local rpid=$(makeRPID $i)
        local fields=($(grep $rpid "$TEST_TMP_DIR/rks"))
        if [[ ${#fields[@]} < 4 ]];then
            break;
        fi
        local credid=${fields[3]}
        echo "[$nrDel]" Deleting $credid of $rpid
        FIDO2DelRkByID $credid
        sed -i "/$rpid/d" "$TEST_TMP_DIR/rks"
        ((nrDel++))
        if [[ $nrDel == 1 || $nrDel == 2 || $nrDel == 10 || $nrDel == $NUMBER_OF_KEYS ]];then
            compareAllRk || return 1
        fi
    done
}

skip_test_Debug() {
    setPINforTest
    echo "For debug only"
    local rpid=thisRP
    makeCredAndStore $rpid thisUser
    local fields=($(grep $rpid "$TEST_TMP_DIR/rks"))
    local credid=${fields[3]}
    local algo=${fields[4]}
    fields=($(FIDO2GetAssert "$rpid" "$credid" $algo))
    # echo "$TEST_TMP_DIR/assert"
    # cat "$TEST_TMP_DIR/assert"
    echo "Blob key is ${fields[0]}"
    echo ${fields[0]} > "$TEST_TMP_DIR/blobkey"
    makeBlob $i > "$TEST_TMP_DIR/blob"
    FIDO2SetBlob "$rpid" "$credid" || return 1
    FIDO2GetBlob "$rpid" "$credid"
    FIDO2DelBlob "$rpid" "$credid"
    # FIDO2GetRkByRp rp1
    # FIDO2DelRkByID "6AwF68LTVupyLx5ddpFRQiPS9+UmkSktTXYWREijOjIBAGO0QIKafRKTv8hiGj4aZxPQSQbfySYyH7CGSbLfBM8/d+Az/H8AABB24DP8fwAA/7CVQft/AAAAAAAAAAAAACB1+f///w==" RPID_aaaaaaaaaaaaabbbbbbbbbbbb40
    # compareAllRk
    # FIDO2GetAssert RPID_aaaaaaaaaaaaabbbbbbbbbbbb01 pE23+fIh21aLmVNPJ+HVRnepBYZq+NzYwcz7jCw/prcBADQbgu4wCtk8v94pXkLxEyGfAVEPvdxqK2hJt0rtyrwt6gNn/38AACDpA2f/fwAA/+CkegR/AAAAAAAAAAAAADDo+f///w==
}

. ./shunit2/shunit2
