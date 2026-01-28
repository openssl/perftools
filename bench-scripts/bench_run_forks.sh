#!/usr/bin/env ksh
#
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html
#

set -x

. ./common_util.sh

INSTALL_ROOT=${BENCH_INSTALL_ROOT:-"/tmp/bench.binaries"}
RESULT_DIR=${BENCH_RESULTS:-"${INSTALL_ROOT}/results"}
WORKSPACE_ROOT=${BENCH_WORKSPACE_ROOT:-"/tmp/bench.workspace"}
MAKE_OPTS=${BENCH_MAKE_OPTS}
CFLAGS_SAVE=${CFLAGS}
CERTDIR=${WORKSPACE_ROOT}/openssl-master/test/certs

function run_randbytes {
    typeset FORKDIR=${1}
    typeset THREAD_COUNT=${2}
    typeset RANDBYTES=${FORKDIR}/randbytes
    typeset FORKNAME=`basename ${FORKDIR} | sed -e 's/build\.//g'`
    typeset RESULT=${RESULT_DIR}/${FORKNAME}-randbytes-${THREAD_COUNT}.out

    ${RANDBYTES} ${THREAD_COUNT} > ${RESULT}
}

function run_rsasign {
    typeset FORKDIR=${1}
    typeset THREAD_COUNT=${2}
    typeset RANDBYTES=${FORKDIR}/rsasign
    typeset FORKNAME=`basename ${FORKDIR} | sed -e 's/build\.//g'`
    typeset RESULT=${RESULT_DIR}/${FORKNAME}-rsasign-${THREAD_COUNT}.out

    ${RANDBYTES} ${THREAD_COUNT} > ${RESULT}
}

function run_handshake {
    typeset FORKDIR=${1}
    typeset THREAD_COUNT=${2}
    typeset HANDSHAKE=${FORKDIR}/handshake
    typeset FORKNAME=`basename ${FORKDIR} | sed -e 's/build\.//g'`
    typeset RESULT=${RESULT_DIR}/${FORKNAME}-handshake-${THREAD_COUNT}.out

    case ${FORKDIR} in
    boringssl)
           echo -n 'handshake does not work on boring: ?' > ${RESULT}
        ;;
    aws-lc)
           echo -n 'handshake does not work on aws: ?' > ${RESULT}
        ;;
    *)
        ${HANDSHAKE} ${CERTDIR} ${THREAD_COUNT} > ${RESULT}
        ;;
    esac
}

function run_sslnew {
    typeset FORKDIR=${1}
    typeset THREAD_COUNT=${2}
    typeset SSLNEW=${FORKDIR}/sslnew
    typeset FORKNAME=`basename ${FORKDIR} | sed -e 's/build\.//g'`
    typeset RESULT=${RESULT_DIR}/${FORKNAME}-sslnew-${THREAD_COUNT}.out

    ${SSLNEW} ${THREAD_COUNT} > ${RESULT}
}

function run_x509storeissuer {
    typeset FORKDIR=${1}
    typeset THREAD_COUNT=${2}
    typeset X509STOREISSUER=${FORKDIR}/x509storeissuer
    typeset FORKNAME=`basename ${FORKDIR} | sed -e 's/build\.//g'`
    typeset RESULT=${RESULT_DIR}/${FORKNAME}-x509storeissuer-${THREAD_COUNT}.out

    ${X509STOREISSUER} ${CERTDIR} ${THREAD_COUNT} > ${RESULT}
}

function run_evp_setpeer {
    typeset FORKDIR=${1}
    typeset THREAD_COUNT=${2}
    typeset EVP_SETPEER=${FORKDIR}/evp_setpeer
    typeset FORKNAME=`basename ${FORKDIR} | sed -e 's/build\.//g'`
    typeset RESULT_BASE=${RESULT_DIR}/${FORKNAME}-evp_setpeer
    typeset KEY=''
    typeset RESULT=''

    for KEY in dh ec256 ec521 x25519 ; do
        RESULT=${RESULT_BASE}-${KEY}-${THREAD_COUNT}.out
        ${EVP_SETPEER} -k ${KEY} ${THREAD_COUNT} > ${RESULT}
    done
}

function run_writeread {
    typeset FORKDIR=${1}
    typeset THREAD_COUNT=${2}
    typeset WRITEREAD=${FORKDIR}/writeread
    typeset FORKNAME=`basename ${FORKDIR} | sed -e 's/build\.//g'`
    typeset RESULT=${RESULT_DIR}/${FORKNAME}-writeread-${THREAD_COUNT}.out

    ${WRITEREAD} ${CERTDIR} ${THREAD_COUNT} > ${RESULT}
}

function yield_tests {
    echo -n 'randbytes '
    echo -n 'rsasign '
    echo -n 'handshake '
    echo -n 'sslnew '
    echo -n 'x509storeissuer '
    echo -n 'evp_setpeer-dh '
    echo -n 'evp_setpeer-ec256 '
    echo -n 'evp_setpeer-ec521 '
    echo -n 'evp_setpeer-x25519 '
    echo 'writeread'
}

function get_description {
    typeset TEST=${1}
    typeset SELECT_LINE=${2}
    #
    # tools work reliably for openssl master tests, some tests
    # fail (are not implemented) for 3rd party libraries.
    # therefore the function uses openssl-master to read
    # bench mark description from result file.
    #
    typeset OPENSSL_RESULT=${RESULT_DIR}/openssl-master-${TEST}-1.out

    #
    # result for handshake test contains two lines:
    #    Average time per handshake: ....
    #    Handshakes per second: ...
    # depending on LINE the function returns either the first (1)
    # or the last (2)
    #
    if [[ ${SELECT_LINE} -eq 1 ]] ; then
        head -n 1 ${OPENSSL_RESULT} | sed -e 's/:.*$//g'
    else
        tail -n 1 ${OPENSSL_RESULT} | sed -e 's/:.*$//g'
    fi
}

function get_value {
    typeset RESULT_FILE=${1}
    typeset SELECT_LINE=${2}

    if [[ -s ${RESULT_FILE} ]] ; then
        #
        # handshake test for boringssl drops 'Unexpected error...'
        # message to result file.
        #
        grep -e 'Unexpected error' ${RESULT_FILE} > /dev/null
        if [[ $? -eq 0 ]] ; then
            echo -n '?'
        else
            #
	    # chop off description and 'us' time unit so the only thing which
            # remains is decimal number.
            #
            if [[ ${SELECT_LINE} -eq 1 ]] ; then
                head -n 1 ${RESULT_FILE} | sed -e 's/^.*://g' -e 's/us$//g'
            else
                tail -n 1 ${RESULT_FILE} | sed -e 's/^.*://g' -e 's/us$//g'
            fi
        fi
    else
        #
        # if file is empty, then method/cipher is not implemented
        # by 3rd party library
        #
        echo -n '?'
    fi
}

#
# Test produces file which naming convention
# reads as follows:
#	fork-test-threads.out
# the 'fork' component is determined from install root
# where each tool set is installed as build.${fork}.
# Using sed the function can safely determined fork name
# even if the name reads as libressl-4.2.1.
#
# the test component also may contain '-', however script
# keeps test names in `yield_tests` function. The thread
# count is also determined taking the similar approach.
# 
# all result files report an average time single benchmark
# operation takes. Time is reported in uSec.
#
# The only exception here is handshake test which reports
# two numbers:
#    average handshake duration (line 1)
#    number of handshake per second (line 2)
#
function merge_result {
    typeset TEST=${1}
    typeset SELECT_LINE=${2}
    typeset THREAD_COUNT=''
    typeset FORK=''
    typeset LINE=''
    typeset OUTPUT_FILE=''
    typeset INPUT_FILE=''

    if [[ ${TEST} = 'handshake' ]] ; then
        OUTPUT_FILE=${RESULT_DIR}/${TEST}-${SELECT_LINE}.merged
    else
        OUTPUT_FILE=${RESULT_DIR}/${TEST}.merged
    fi
    get_description ${TEST} ${SELECT_LINE} > ${OUTPUT_FILE}
    printf 'line-no.\tThreads' >> ${OUTPUT_FILE}
    for FORK in ${INSTALL_ROOT}/build.* ; do
        FORK=`basename ${FORK} | sed -e 's/build\.//g'`
        printf "\t${FORK}" >> ${OUTPUT_FILE}
    done
    printf '\n' >> ${OUTPUT_FILE}
    LINE=1
    for THREAD_COUNT in `procs` ; do
        printf "${LINE}\t${THREAD_COUNT}" >> ${OUTPUT_FILE}
        for FORK in ${INSTALL_ROOT}/build.* ; do
            FORK=`basename ${FORK} | sed -e 's/build\.//g'`
            INPUT_FILE=${RESULT_DIR}/${FORK}-${TEST}-${THREAD_COUNT}.out
            printf "\t`get_value ${INPUT_FILE} ${SELECT_LINE}`" >> ${OUTPUT_FILE}
        done
        printf '\n' >> ${OUTPUT_FILE}
        LINE=$(( ${LINE} + 1))
    done
}

#
# the results for handshake test contain
# two numbers:
#     average number of handshakes per second
#     handshakes per sec
# hence there is extra call outside of loop to call
# to merge results for completed handshakes.
#
function merge_results {
    typeset TEST=''

    for TEST in `yield_tests` ; do
        merge_result ${TEST} 1
    done

    merge_result 'handshake' 2
}

function plot_result {
    typeset DATA_FILE=${1}.data
    typeset OUT_FILE=${2}
    typeset YLABEL=${3}
    typeset TITLE=`head -n 1 ${1}`

    #
    # chop off the fist line (title)
    #
    tail -n +2 ${1} > ${DATA_FILE}
    gnuplot << EOF
set title "${TITLE}"
set grid lt 0 lw 1 ls 1 lc rgb "#d7d7d7"
set xlabel "Number of threads"
set ylabel "${YLABEL}"
set terminal pngcairo size 800,400 background rgb "#f8f8f8"
set output "${OUT_FILE}"
set key autotitle columnhead outside
set auto x
set style data histogram
set style histogram cluster gap 1
set style fill solid border -1
set datafile missing '?'
set title noenhanced
set boxwidth 0.9
plot \
    "${DATA_FILE}" using 3:xticlabels(2) ti col, \
    "${DATA_FILE}" using 4 ti col, \
    "${DATA_FILE}" using 5 ti col, \
    "${DATA_FILE}" using 6 ti col, \
    "${DATA_FILE}" using 7 ti col
EOF
    rm ${DATA_FILE}
}

function plot_results {
    typeset RESULT=''
    typeset RESULT_BASENAME
    typeset OUTFILE=''
    typeset YLABEL=''

    for RESULT in ${RESULT_DIR}/*.merged ; do
        RESULT_BASENAME=`basename ${RESULT}`
        if [[ ${RESULT_BASENAME} = 'handshake-2.merged' ]] ; then
            YLABEL='ops per sec.'
        else
            YLABEL='single op. in uSec'
        fi
        OUTFILE=`echo ${RESULT} | sed -e 's/merged/png/g'`
        plot_result ${RESULT} ${OUTFILE} "${YLABEL}"
        echo ${OUTFILE}
    done
}

mkdir -p ${RESULT_DIR}

for THREAD_COUNT in `procs` ; do
    for FORK in ${INSTALL_ROOT}/build.* ; do
        run_randbytes ${FORK} ${THREAD_COUNT}
        run_rsasign ${FORK} ${THREAD_COUNT}
        run_handshake ${FORK} ${THREAD_COUNT}
        run_sslnew ${FORK} ${THREAD_COUNT}
        run_x509storeissuer ${FORK} ${THREAD_COUNT}
        run_evp_setpeer ${FORK} ${THREAD_COUNT}
        run_writeread ${FORK} ${THREAD_COUNT}
    done
done

merge_results
plot_results
