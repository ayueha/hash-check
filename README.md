## Environment
inotifywait and python script  
OS:raspberry pi 3  
DB:sqlite3  

## Not yet functioned

Recrusive directory search  
SAVAPI query process  
Automatic scan based on inotifywait  


## Functioned

Initial hash creation  
single file hash conformation  
Option parser

## Option Parser

Mandatory : process letter [i / f / d]  
i : initial creation  
f : single file hash creation  
f : direcrory recrusive hash creation  
Optional : --PATH  
###Example
hash.py f --PATH /home/username/test.txt  --- single file hash creation  

