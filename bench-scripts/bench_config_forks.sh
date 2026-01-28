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

WOLFSSL_VERSION=5.8.2
LIBRESSL_VERSION=4.2.1
OPENSSL_VERSION=master

function build_perftools {
    #
    # when testing changes for C-code or CMakeFileList.txt
    # you must change link to repository, so script pulls
    # modified sources
    #
    typeset PERFTOOLS='https://github.com/openssl/perftools'

    cd ${WORKSPACE_ROOT} || exit 1
    #
    # you may also need to change clone command to
    # checkout correct branch.
    #
    git clone ${PERFTOOLS} || exit 1
    cd perftools/source || exit 1

    cmake -S ${WORKSPACE_ROOT}/perftools/source \
        -B ${INSTALL_ROOT}/build.openssl-${OPENSSL_VERSION} \
        -DOPENSSL_CONFIG_MODE=1 \
        -DCMAKE_PREFIX_PATH=${INSTALL_ROOT}/openssl-${OPENSSL_VERSION} \
        -DCMAKE_PREFIX_PATH=${INSTALL_ROOT}/openssl-${OPENSSL_VERSION} || exit 1
    cmake --build ${INSTALL_ROOT}/build.openssl-${OPENSSL_VERSION} || exit 1

    cmake -S ${WORKSPACE_ROOT}/perftools/source \
        -B ${INSTALL_ROOT}/build.wolfssl-${WOLFSSL_VERSION} \
        -DWITH_OPENSSL_FORK=1 \
        -DCMAKE_PREFIX_PATH=${INSTALL_ROOT}/wolfssl-${WOLFSSL_VERSION} || exit 1
    cmake --build ${INSTALL_ROOT}/build.wolfssl-${WOLFSSL_VERSION} || exit 1

    cmake -S ${WORKSPACE_ROOT}/perftools/source \
        -B ${INSTALL_ROOT}/build.libressl-${LIBRESSL_VERSION} \
        -DWITH_OPENSSL_FORK=1 \
        -DCMAKE_PREFIX_PATH=${INSTALL_ROOT}/libressl-${LIBRESSL_VERSION} || exit 1
    cmake --build ${INSTALL_ROOT}/build.libressl-${LIBRESSL_VERSION} || exit 1

    cmake -S . -B $BENCH_INSTALL_ROOT/build.boringssl/ \
        -DCMAKE_PREFIX_PATH=$BENCH_INSTALL_ROOT/boringssl \
        -DWITH_OPENSSL_FORK=1 || exit 1
    cmake --build ${INSTALL_ROOT}/build.boringssl || exit 1

    cmake -S . -B $BENCH_INSTALL_ROOT/build.aws-lc/ \
        -DCMAKE_PREFIX_PATH=$BENCH_INSTALL_ROOT/aws-lc \
        -DWITH_OPENSSL_FORK=1 || exit 1
    cmake --build ${INSTALL_ROOT}/build.aws-lc || exit 1
}

install_openssl ${OPENSSL_VERSION}

#
# enable WolfSSL's compatibility layer with OpenSSL.
# another option is to use ./configure --enable-opensslextra
# see: https://www.wolfssl.com/documentation/manuals/wolfssl/chapter13.html
#
CFLAGS="${CFLAGS} -DOPENSSL_EXTRA -DOPENSSL_ALL"
install_wolfssl ${WOLFSSL_VERSION}
CFLAGS=${CFLAGS_SAVE}

install_libressl ${LIBRESSL_VERSION}

install_boringssl

install_aws_lc

build_perftools
