#!/bin/bash
    if [$# -ne 1]; then
	    echo "p : python での実行を指定" 1>&2
		exit 1
	fi
	
	if [$1 -eq "p" || $1 -eq "P" ]; then
	    cd scripts
	    /usr/bin/python3 hash.py
	fi
	