#!/bin/bash
if [$# -ne 1];then
    echo 'Please point out one directory' 1>&2
    exit 1
else
    inotifywait -e CREATE -m -r $1 | while read line
    do
        event=${line}
        /usr/bin/python3 hash.py f --STRING $event
    done
fi