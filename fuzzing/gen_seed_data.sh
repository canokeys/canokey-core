#!/bin/bash
FILE_IN="$1" # path to pcscd.log
file_index=1

grep -P -o '(?<=\d{8} APDU:)( \w\w)+' "$FILE_IN" | sed "s/ /\\\\x/g" | sort | uniq | \
while read -r line; do 
    # echo $line
    echo -ne "$line" >"seed$file_index.bin"
    ((file_index++))
done
