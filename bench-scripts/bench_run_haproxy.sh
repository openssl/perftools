#!/usr/bin/env ksh
#
# Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
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
PORT_RSA_REUSE=${BENCH_PORT_RSA_REUSE:-10000}
PORT_RSA=${BENCH_PORT_RSA:-10100}
PORT_EC_REUSE=${BENCH_PORT_EC_REUSE:-10200}
PORT_EC=${BENCH_PORT_EC:-10300}
HOST=${BENCH_HOST:-'127.0.0.1'}
CERT_SUBJ=${BENCH_CERT_SUBJ:-'/CN=localhost'}
CERT_ALT_SUBJ=${BENCH_CERT_ALT_SUBJ:-'subjectAltName=DNS:localhost,IP:127.0.0.1'}
HTTPTERM_HOST=${BENCH_HTTPTERM_HOST:-${HOST}}
HTTPTERM_PORT=${BENCH_HTTPTERM_PORT:-9999}
PROXY_CHAIN=${BENCH_PROXY_CHAIN:-21}
HAPROXY_VERSION='v3.2.0'
TEST_TIME=${BENCH_TEST_TIME:-'10'}

#
# Starts haproxy based on the configuration that was done beforehand calling
# install_haproxy.
#
function run_haproxy {
    typeset SSL_LIB=$1
    typeset HAPPIDFILE=$2
    if [[ -z "${SSL_LIB}" ]] ; then
        SSL_LIB="openssl-master"
    fi
    typeset OPENSSL_DIR="${INSTALL_ROOT}/${SSL_LIB}"
    typeset HAPROXY="${OPENSSL_DIR}"/sbin/haproxy

    LD_LIBRARY_PATH="${OPENSSL_DIR}/lib" "${HAPROXY}" \
        -f "${OPENSSL_DIR}/etc/haproxy.conf" \
    -p ${HAPPIDFILE} \
        -D
    if [[ $? -ne 0 ]] ; then
        echo "could not start haproxy"
        exit 1
    fi
}

function run_httpterm {
    typeset SSL_LIB=$1
    typeset HTTPTERMPIDFILE=$2
    if [[ -z "${SSL_LIB}" ]] ; then
        SSL_LIB="openssl-master"
    fi
    typeset OPENSSL_DIR="${INSTALL_ROOT}/${SSL_LIB}"
    typeset HTTPTERM="${OPENSSL_DIR}"/bin/httpterm

    LD_LIBRARY_PATH="${OPENSSL_DIR}/lib" "${HTTPTERM}" \
    -p ${HTTPTERMPIDFILE} \
        -L ${HTTPTERM_HOST}:${HTTPTERM_PORT} \
        -D
    if [[ $? -ne 0 ]] ; then
        echo "could not start httpterm"
        exit 1
    fi
}

function kill_daemon {
    typeset PIDFILE=$1

    kill -TERM `cat ${PIDFILE}`
    rm -f ${PIDFILE}
}

function run_test {
    typeset SSL_LIB=$1
    typeset THREAD_COUNT=$2
    typeset OPENSSL_DIR=${INSTALL_ROOT}/${SSL_LIB}
    typeset H1LOAD=${OPENSSL_DIR}/bin/h1load
    #
    # siege does not build with aws-lc currently,
    # therefore test uses siege as http-client only.
    # the client connects to haproxy with http and
    # the proxy opens https.
    #
    typeset SIEGE=${INSTALL_ROOT}/openssl-master/bin/siege
    typeset BASE_URL="https://${HOST}:"
    typeset BASE_URL_SIEGE="http://${HOST}:"
    typeset RESULT=''
    typeset HAPPIDFILE=${OPENSSL_DIR}/haproxy.pid
    typeset HTTPTERMPIDFILE=${OPENSSL_DIR}/httpterm.pid
    typeset PORT=''
    typeset TEST_NAME=''

    run_haproxy ${SSL_LIB} ${HAPPIDFILE}
    run_httpterm ${SSL_LIB} ${HTTPTERMPIDFILE}

    echo "proxy running for ${SSL_LIB} ${THREAD_COUNT}"

    for TEST_NAME in dh-rsa-reuse dh-rsa-noreuse ec-dsa-reuse ec-dsa-noreuse ; do
        case ${TEST_NAME} in
            dh-rsa-reuse)
                    PORT=$(( ${PORT_RSA_REUSE} + ${PROXY_CHAIN} ))
                ;;
            dh-rsa-noreuse)
                    PORT=$(( ${PORT_RSA} + ${PROXY_CHAIN} ))
                ;;
            ec-dsa-reuse)
                    PORT=$(( ${PORT_EC_REUSE} + ${PROXY_CHAIN} ))
                ;;
            ec-dsa-noreuse)
                    PORT=$(( ${PORT_EC} + ${PROXY_CHAIN} ))
                ;;
            *)
                echo "Warning unknown mod ${TEST_NAME}"
                break #for loop
                ;;
        esac
        RESULT=${RESULT_DIR}/h1load-${TEST_NAME}-${THREAD_COUNT}-${SSL_LIB}.out
        LD_LIBRARY_PATH=${OPENSSL_DIR}/lib ${H1LOAD} \
            -l \
            -P \
            -d ${TEST_TIME} \
            -c 500 \
            -t ${THREAD_COUNT} \
            ${BASE_URL}${PORT} > ${RESULT} || exit 1
    done

    if [[ -x ${SIEGE} ]] ; then
        for TEST_NAME in dh-rsa-noreuse ec-dsa-noreuse ; do
            RESULT=${RESULT_DIR}/siege-${TEST_NAME}-${THREAD_COUNT}-${SSL_LIB}.out
            if [[ ${TEST_NAME} = "ec-dsa-noreuse" ]] ; then
                #
                # port for http siege client:
                #    {EC,RSA} port + chain + httpterm offset (1000) + http port offset (1)
                #
                PORT=$(( ${PORT_EC} + ${PROXY_CHAIN} + 1000 + 1))
                LD_LIBRARY_PATH=${INSTALL_ROOT}/openssl-master/lib ${SIEGE} \
                    -b \
                    -c ${THREAD_COUNT} \
                    -t ${TEST_TIME}S \
                    "${BASE_URL_SIEGE}${PORT}/?s=1k" 2> ${RESULT} 1> /dev/null || exit 1
            else
                PORT=$(( ${PORT_RSA} + ${PROXY_CHAIN} + 1000 + 1))
                LD_LIBRARY_PATH=${INSTALL_ROOT}/openssl-master/lib ${SIEGE} \
                    -b \
                    -c ${THREAD_COUNT} \
                    -t ${TEST_TIME}S \
                    "${BASE_URL_SIEGE}${PORT}/?s=1k" 2> ${RESULT} 1> /dev/null || exit 1
            fi
        done
    fi

    kill_daemon ${HAPPIDFILE}
    kill_daemon ${HTTPTERMPIDFILE}
}

function run_tests {
    typeset i=''
    typeset t=''

    for t in 1 2 4 8 16 32 64 ; do
        for i in 3.0 3.1 3.2 3.3 3.4 3.5 3.6 master ; do
            run_test openssl-${i} ${t}
        done
        run_test OpenSSL_1_1_1-stable ${t}
        run_test libressl-4.1.0 ${t}
        run_test wolfssl-5.8.2 ${t}
        run_test aws-lc ${t}
        #
        # could not get haproxy working with boringssl
        #
    done
}

#
# function merges siege tests to tables so results
# can be compared plotted. The tests collect data
# to files. Each file contains a combination of:
#    - ha-proxy configuration
#    - ssl library
#    - number of processes used
# the list of files looks then as follows:
#   h1load-dh-rsa-noreuse-1-openssl-3.4.out
#   ...
#   h1load-dh-rsa-noreuse-2-wolfssl-5.8.2.out
#   ...
#   h1load-dh-rsa-noreuse-64-openssl-master.out
#
# the h1load-dh-rsa-noreuse- identifies ha-proxy configuration
# used for testing.
#
# the next -1, -3, ..., -64 infix represents number of threads/cpus
# used for test.
#
# openss-3.4, weolfssl-5.8.2, ... is the ssl library used
# for testing
#
# this function merges collected data to tables so we can
# plot/compare results for particular rows provided by siege.
# The result of merge is 24 files (12 siege rows multiplied
# by 2 ha-proxy configurations used for testing)
# The columns in merged file holds benchmark results for
# particular library (ssl_libs_haproxy), while rows hold
# the result for number of procs
#
function merge_siege {
    typeset RESULT_DIR=${1:-'.'}
    typeset HANDSHAKE=''
    typeset PROCS=''
    typeset SSL_LIB=''
    typeset ROW=''
    typeset VALUE=''
    typeset INPUT_FILE=''
    typeset OUTPUT_FILE=''
    typeset SAVE_IFS=''

    for HANDSHAKE in siege-dh-rsa-noreuse siege-ec-dsa-noreuse ; do
        SAVE_IFS=${IFS}
            IFS=':'
        for ROW in `siege_rows` ; do
            IFS=${SAVE_IFS}
            OUTPUT_FILE=${RESULT_DIR}/${HANDSHAKE}-${ROW}.merged
            #
            # turn spaces to _ in filename
            #
            OUTPUT_FILE=`echo ${OUTPUT_FILE} |sed -e 's/ /_/g'`
            rm -f ${OUTPUT_FILE}
            #
            # print header with column labels
            #
            for SSL_LIB in `ssl_libs_haproxy` ; do
                printf "\t${SSL_LIB}" >> ${OUTPUT_FILE}
            done
            printf '\n' >> ${OUTPUT_FILE}
            for PROCS in `procs` ; do
                #
                # row header with number CPUs used for test
                #
                printf "${PROCS}" >> ${OUTPUT_FILE}
                for SSL_LIB in `ssl_libs_haproxy` ; do
                    INPUT_FILE=${HANDSHAKE}-${PROCS}-${SSL_LIB}.out
                    INPUT_FILE=${RESULT_DIR}/${INPUT_FILE}
                    if [[ -f ${INPUT_FILE} ]] ; then
                        #
                        # find desired row in siege output file,
                        # keep the value that follows ':'
                        #
                        VALUE=$(grep "^${ROW}:" ${INPUT_FILE} | cut -d ':' -f 2 )
                        #
                        # chop off what ever follows (siege prints units)
                        #
                        VALUE=$(echo ${VALUE} | awk '{ print($1); }')
                    else
                        #
                        # placeholder if input file is missing
                        #
                        VALUE="?"
                    fi
                    printf "\t${VALUE}\t" >> ${OUTPUT_FILE}
                done
                #
                # new line
                #
                printf "\n" >> ${OUTPUT_FILE}
            done
        done
    done
}

run_tests
merge_siege ${RESULT_DIR}
