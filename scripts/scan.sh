#!/bin/bash
if [ $# -ne 1 ];then
    echo 'Please point out one directory' 1>&2
    exit 1
else
    previous_value = ""
    inotifywait -e create,attrib,close_write -m -r $1 | while read line
    do
        declare -a eventData=(${line})
        if [ ${eventData[1]} = "CREATE" ]; then
            echo "action create"
            /usr/bin/python3 ~/hash-check/scripts/hash.py w --string "${line}" 
            previous_value="CREATE" 
        elif [ ${eventData[1]} = "ATTRIB" ] && [ $previous_value!="ATTRIB" ]; then
            echo 'action attribute'
            /usr/bin/python3 ~/hash-check/scripts/hash.py w --string "${line}"
            previous_value="ATTRIB"
        elif [ ${eventData[1]} = "CLOSE_WRITE,CLOSE" ] && [ $previous_value!="CLOSE_WRITE,CLOSE" ]; then
            /usr/bin/python3 ~/hash-check/scripts/hash.py w --string "${line}"
            previous_value="CLOSE_WRITE,CLOSE"
        fi

    done
fi