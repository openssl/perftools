#!/bin/bash
for i in 1 2 4 8 16 32 64 
do
    let TOTALUS=0
    declare -a US_VALS
    let idx=0
    let MEANUS=0
    let VARUS=0
    while read THREADS US
    do
        if [ $THREADS != $i ]
        then
            continue
        fi
        US_VALS[$idx]=$US
        TOTALUS=$(dc -e"6 k $US $TOTALUS + p")
        let idx=$idx+1
    done < ./$1
    MEANUS=$(dc -e"6 k $TOTALUS ${#US_VALS[@]} / p")
    let US_MAX=${#US_VALS[@]}-1
    for k in $(seq 0 1 $US_MAX)
    do
        # delta to mean for each value
        US_VALS[$k]=$(dc -e "6 k $MEANUS ${US_VALS[$k]} - p" | sed -e"s/-/_/")
        # square it
        US_VALS[$k]=$(dc -e "6 k ${US_VALS[$k]} 2 ^ p")
        VARUS=$(dc -e"6 k ${US_VALS[$k]} $VARUS + p")
    done
    VARUS=$(dc -e"6 k $VARUS ${#US_VALS[@]} / p")
    VARUS=$(dc -e"6 k $VARUS v p")
    echo "$i $MEANTPH $MEANUS $VARUS"
done
