#!/bin/bash
if [ $# -ne 1 ]; then
    echo "directory is mandatory in first option" 1>&2
    #echo "p or P : Choose python script option" 1>&2
    exit 1
else
    if [$2 = "p" -o $2="P" -o $2=""]; then
        inotifywatch -e create -mq $1 | /usr/bin/python3 ./scripts/hash.py 
    fi
fi

#elif [ $1 = "p" -o $1 = "P" ]; then
#    cd scripts
#    /usr/bin/python3 hash.py
#fi
	
