#!/bin/bash

function get_folders {
    local INDECES=()
    AVOID="utils|deprecated"
    for folder in $(ls -d */ | grep -vE $AVOID); do
        INDECES+="$folder "
    done
    INDECES+=". "
    echo "$INDECES"
}

function gen_index {
    IDX_NAME=$1
    BASE=$2
    INC_MOBILE=$3
    > $IDX_NAME
    if [ x"$4" != x ]; then
        echo -e "/*$4*/" > $IDX_NAME
    fi
    OS=$(uname)
    AVOID="_?index.yara?|index_|utils|deprecated"
    if [ x"$BASE" == x"." ]; then
        if [ $INC_MOBILE == false ]; then
            AVOID+="|Mobile"
        fi
        if [ $OS == "Darwin" ]; then
            find -E $BASE -regex ".*\.yara?" | grep -vE "$AVOID" | sort | awk '{print "include \"" $0 "\""}' >> $IDX_NAME
        else
            # Linux version and potentialy Cygwin
            find $BASE -regex ".*\.yara?" | grep -vE "$AVOID" | sort | awk '{print "include \"" $0 "\""}' >> $IDX_NAME
        fi
    else
        if [ $OS == "Darwin" ]; then
            find -E $BASE -regex ".*\.yara?" | grep -vE "$AVOID" | sort | awk '{print "include \"./" $0 "\""}' >> $IDX_NAME
        else
            # Linux version and potentialy Cygwin
            find $BASE -regex ".*\.yara?" | grep -vE "$AVOID" | sort | awk '{print "include \"./" $0 "\""}' >> $IDX_NAME
        fi
    fi
}

## Main

echo "   **************************"
echo "          Yara-Rules"
echo "        Index generator"
echo "   **************************"

INC_MOBILE=true

for folder in $(get_folders)
do
    if [ x"$folder" == x"." ]; then
        BASE="."
        IDX_NAME="index_w_mobile.yar"
        echo "[+] Generating index_w_mobile..."
    else
        BASE=$(echo $folder | rev | cut -c 2- | rev)
        IDX_NAME="$BASE"_index.yar
        echo "[+] Generating $BASE index..."
    fi

    gen_index $IDX_NAME $BASE $INC_MOBILE "\nGenerated by Yara-Rules\nOn $(date +%d-%m-%Y)\n"

    if [ x"$folder" == x"." ]; then
        INC_MOBILE=false
        IDX_NAME="index.yar"
        gen_index $IDX_NAME $BASE $INC_MOBILE "\nGenerated by Yara-Rules\nOn $(date +%d-%m-%Y)\n"
        echo "[+] Generating index..."
    fi
done
