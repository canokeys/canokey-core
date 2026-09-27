#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
export LANGUAGE=en_US
export LANG=en_US.UTF8
export TEST_TMP_DIR=/tmp/canokey-pass
export USER=`id -nu`
SHORT_TOUCH_TEXT=
LONG_TOUCH_TEXT=

SC() {
    # opensc-tool -r "$RDID" $@
    echo $@ | sed 's/ /\n/g' | scriptor -r "$RDID"
}

PassSetStatic() {
    local slot=$1
    local passwd=$2
    local len=$(printf %02x ${#passwd})
    local hexPwd=$(echo -n "$passwd"|xxd -p -c 256)
    local data="02${len}${hexPwd}01"
    len=$(printf %02x $((${#data}/2)))
    local apdu="00440${slot}00${len}${data}"
    # SC -a 00A4040005F000000000 -a 0020000006313233343536 -a $apdu;
    SC 00A4040005F000000000  0020000006313233343536 $apdu
    assertEquals 'PassSetStatic' 0 $?
    if [[ $slot == 1 ]]; then
        SHORT_TOUCH_TEXT="$passwd"
    else
        LONG_TOUCH_TEXT="$passwd"
    fi
}

CheckTouch() {
    local slot=$1
    local text=
    local type=
    if [[ $slot == 1 ]]; then
        text="$SHORT_TOUCH_TEXT"
        type=short
    else
        text="$LONG_TOUCH_TEXT"
        type=long
    fi
    IFS="" read -r -p "Make a $type touch: " from_key
    assertEquals 'CheckInput' "$text" "$from_key"
}

oneTimeSetUp() {
    rm -rf "$TEST_TMP_DIR"
    mkdir "$TEST_TMP_DIR"
    killall -u $USER -9 gpg-agent || true
    sleep 2
    export RDID=$(pcsc_scan -r | grep -oi 'canokey.*$')
    echo "RDID=$RDID"
}

test_static_passwd() {
    PassSetStatic 1 '019azZA-= _+{}/|":<>~`!@#$%^&*Uu'
    PassSetStatic 2 "BCDbcdxXYy?'\\;([])345678,.poO"

    CheckTouch 1
    CheckTouch 2
 
    PassSetStatic 1 ' '
    PassSetStatic 2 "qazwsx edc rfv tgb yhn ujm ikl ."
    CheckTouch 1
    CheckTouch 2
}

. ./shunit2/shunit2
