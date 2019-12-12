#!/bin/bash
FILE_IN="$1"
file_index=1

while read -r line; do 
    grep -Po '( \w\w)+ *$' <<<"$line" |xxd -r -p >"${FILE_IN%txt}$file_index.txt"
    ((file_index++))
done < "$FILE_IN"
