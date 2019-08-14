## Environment
inotifywait and python script  
OS:raspberry pi 3  
DB:sqlite3  

## Not yet functioned
SAVAPI query process  



## Functioned
Recrusive directory search  
Initial hash creation  
single file hash conformation  
Option parser
Automatic scan based on inotifywait  

## Option Parser

Mandatory : process letter [i / f / d]  
i : initial creation  
f : single file hash creation  
d : direcrory recrusive hash creation  
Optional : --PATH  

### Example
hash.py i                                 : initial database creatuion  
hash.py f --PATH /home/username/test.txt  : single file hash creation  
hash.py d --PATH /home/username/          : directory file hash creation  

