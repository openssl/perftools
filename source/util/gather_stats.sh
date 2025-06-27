#!/bin/bash
COMMAND=$1
LIB=$2
shift
shift
MYARGS=$*

ISTHANDSHAKE="no"
echo $COMMAND | grep -q "handshake"
if [ $? -eq 0  ]
then
    ISHANDSHAKE="yes"
else
    MYARGS="$MYARGS -t"
fi
for i in 1 2 4 8 16 32 64 
do
    for j in $(seq 1 1 10)
    do
        LD_LIBRARY_PATH=$LIB $COMMAND $MYARGS $i > ./capture.txt
        if [ "$ISHANDSHAKE" == "yes" ]
        then
            TPH=$(cat ./capture.txt | awk '/Average time per handshake/ {print $5}' | sed -e"s/us//")
            HPS=$(cat ./capture.txt | awk '/Handshakes per second/ {print $4}')
            echo "$i $TPH $HPS"
        else
            RUNTIME=$(cat ./capture.txt)
            echo "$i $RUNTIME"
        fi
    done
   
done
