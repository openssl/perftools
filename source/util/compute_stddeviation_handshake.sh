#!/bin/bash
for i in 1 2 4 8 16 32 64 
do
    let TOTALHPS=0
    let TOTALTPH=0
    declare -a TPH_VALS
    declare -a HPS_VALS
    let idx=0
    let MEANHPS=0
    let MEANTPH=0
    let VARHPS=0
    let VARTPH=0
    while read THREADS TPH HPS
    do
        if [ $THREADS != $i ]
        then
            continue
        fi
        TPH_VALS[$idx]=$TPH
        HPS_VALS[$idx]=$HPS
        TOTALTPH=$(dc -e"6 k $TPH $TOTALTPH + p")
        TOTALHPS=$(dc -e"6 k $HPS $TOTALHPS + p")
        let idx=$idx+1
    done < ./$1
    MEANHPS=$(dc -e"6 k $TOTALHPS ${#HPS_VALS[@]} / p")
    MEANTPH=$(dc -e"6 k $TOTALTPH ${#TPH_VALS[@]} / p")
    let HPS_MAX=${#HPS_VALS[@]}-1
    for k in $(seq 0 1 $HPS_MAX)
    do
        # delta to mean for each value
        HPS_VALS[$k]=$(dc -e "6 k $MEANHPS ${HPS_VALS[$k]} - p" | sed -e"s/-/_/")
        # square it
        HPS_VALS[$k]=$(dc -e "6 k ${HPS_VALS[$k]} 2 ^ p")
        VARHPS=$(dc -e"6 k ${HPS_VALS[$k]} $VARHPS + p")
    done
    let TPH_MAX=${#TPH_VALS[@]}-1
    for k in $(seq 0 1 $TPH_MAX)
    do
        # delta to mean for each value
        TPH_VALS[$k]=$(dc -e "6 k $MEANTPH ${TPH_VALS[$k]} - p" | sed -e"s/-/_/")
        # square it
        TPH_VALS[$k]=$(dc -e "6 k ${TPH_VALS[$k]} 2 ^ p")
        VARTPH=$(dc -e"6 k ${TPH_VALS[$k]} $VARTPH + p")
    done
    VARHPS=$(dc -e"6 k $VARHPS ${#HPS_VALS[@]} / p")
    VARHPS=$(dc -e"6 k $VARHPS v p")
    VARTPH=$(dc -e"6 k $VARTPH ${#TPH_VALS[@]} / p")
    VARTPH=$(dc -e"6 k $VARTPH v p")
    echo "$i $MEANTPH $VARTPH $MEANHPS $VARHPS"
done
