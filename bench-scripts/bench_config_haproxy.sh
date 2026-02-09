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
WORKSPACE_ROOT=${BENCH_WORKSPACE_ROOT:-"/tmp/bench.workspace"}
MAKE_OPTS=${BENCH_MAKE_OPTS}
HAPROXY_BUILD_TARG=${BENCH_HAPROXY_BUILD_TARG:-'linux-glibc'}
CERT_SUBJ=${BENCH_CERT_SUBJ:-'/CN=localhost'}
CERT_ALT_SUBJ=${BENCH_CERT_ALT_SUBJ:-'subjectAltName=DNS:localhost,IP:127.0.0.1'}
HOST=${BENCH_HOST:-'127.0.0.1'}
HTTPTERM_HOST=${BENCH_HTTPTERM_HOST:-${HOST}}
HTTPTERM_PORT=${BENCH_HTTPTERM_PORT:-9999}
PORT_RSA_REUSE=${BENCH_PORT_RSA_REUSE:-10000}
PORT_RSA=${BENCH_PORT_RSA:-10100}
PORT_EC_REUSE=${BENCH_PORT_EC_REUSE:-10200}
PORT_EC=${BENCH_PORT_EC:-10300}
HAPROXY_VERSION='v3.2.0'
PROXY_CHAIN=${BENCH_PROXY_CHAIN:-21}

function install_httpterm {
    typeset SSL_LIB=$1
    typeset HTTPTERM_REPO="https://github.com/wtarreau/httpterm"
    typeset BASENAME='httpterm'
    typeset DIRNAME="${BASENAME}"
    typeset SSL_CFLAGS=''
    typeset SSL_LFLAGS=''

    if [[ -z "${SSL_LIB}" ]] ; then
        SSL_LIB="openssl-master"
    fi

    cd "${WORKSPACE_ROOT}" || exit 1
    git clone "${HTTPTERM_REPO}" "${DIRNAME}" || exit 1
    cd ${DIRNAME} || exit 1
    make || exit 1
    install httpterm "${INSTALL_ROOT}/${SSL_LIB}/bin/httpterm" || exit 1
}

function install_h1load {
    typeset SSL_LIB=$1
    typeset H1LOAD_REPO="https://github.com/wtarreau/h1load"
    typeset BASENAME='h1load'
    typeset DIRNAME="${BASENAME}"
    typeset SSL_CFLAGS=''
    typeset SSL_LFLAGS=''

    if [[ -z "${SSL_LIB}" ]] ; then
        SSL_LIB="openssl-master"
    fi

    echo $SSL_LIB | grep 'wolfssl' > /dev/null
    if [[ $? -eq 0 ]] ; then
        #
        # adjust flags for wolfssl
        #
        SSL_CFLAGS="-I${INSTALL_ROOT}/${SSL_LIB}/include/wolfssl"
        SSL_CFLAGS="${SSL_CFLAGS} -I${INSTALL_ROOT}/${SSL_LIB}/include"
        SSL_CFLAGS="${SSL_CFLAGS} -include ${INSTALL_ROOT}/${SSL_LIB}/include/wolfssl/options.h"
        SSL_LFLAGS="-L ${INSTALL_ROOT}/${SSL_LIB}/lib -lwolfssl -Wl,-rpath=${INSTALL_ROOT}/lib"
    else
        SSL_CFLAGS="-I${INSTALL_ROOT}/${SSL_LIB}/include"
        SSL_LFLAGS="-L ${INSTALL_ROOT}/${SSL_LIB}/lib -lssl -lcrypto"
    fi
    #
    # this fork adds -u option to keep time as uptime
    #
    cd "${WORKSPACE_ROOT}" || exit 1
    git clone "${H1LOAD_REPO}" "${DIRNAME}" || exit 1
    cd ${DIRNAME} || exit 1
    make SSL_CFLAGS="${SSL_CFLAGS}" SSL_LFLAGS="${SSL_LFLAGS}" || exit 1
    install h1load "${INSTALL_ROOT}/${SSL_LIB}/bin/h1load" || exit 1
    cd scripts
    for i in *.sh ; do
        install $i "${INSTALL_ROOT}/${SSL_LIB}/bin/$i" || exit 1
    done
}

function install_haproxy {
    typeset SSL_LIB=$1
    typeset VERSION=${HAPROXY_VERSION:-v3.2.0}
    typeset HAPROXY_REPO="https://github.com/haproxy/haproxy.git"
    typeset BASENAME='haproxy'
    typeset DIRNAME="${BASENAME}-${VERSION}"
    typeset USE_LIB=''

    if [[ -z "${SSL_LIB}" ]] ; then
        SSL_LIB="openssl-master"
    fi

    case ${SSL_LIB} in
        wolf*)
                USE_LIB='USE_OPENSSL_WOLFSSL=1'
            ;;
        *)
                USE_LIB='USE_OPENSSL=1'
            ;;
    esac

    if [[ -f "${INSTALL_ROOT}/${SSL_LIB}/sbin/haproxy" ]] ; then
        echo "haproxy already installed; skipping.."
    else
        cd "${WORKSPACE_ROOT}" || exit 1
        mkdir -p "${DIRNAME}" || exit 1
        cd "${DIRNAME}"
        git clone "${HAPROXY_REPO}" -b ${VERSION} --depth 1 . || exit 1
        
        # haproxy does not have a configure script; only a big makefile
        make clean
        make ${MAKE_OPTS} \
             TARGET=${HAPROXY_BUILD_TARG} \
             ${USE_LIB} \
             USE_OPENSSL=USE_QUIC \
             SSL_INC="${INSTALL_ROOT}/${SSL_LIB}/include" \
             SSL_LIB="${INSTALL_ROOT}/${SSL_LIB}/lib" || exit 1

        make install ${MAKE_OPTS} \
             PREFIX="${INSTALL_ROOT}/${SSL_LIB}" || exit 1
    fi

    cd ${WORKSPACE_ROOT}
}

function emit_global {
    typeset HAPROXY_CONF=$1

cat <<EOF > ${HAPROXY_CONF}
global
        default-path config
        tune.listener.default-shards by-thread
        tune.idle-pool.shared off
        ssl-default-bind-options ssl-min-ver TLSv1.3 ssl-max-ver TLSv1.3
        ssl-server-verify none

EOF

}

function emit_frontend {
        typeset HAPROXY_CONF=$1
        typeset REUSE_LABEL=$2
        typeset BASEPORT=$3
        typeset PROXYCERT=$4
        typeset SSL_REUSE=$5


cat <<EOF >> ${HAPROXY_CONF}
defaults ${REUSE_LABEL}
        mode http
        http-reuse never
        default-server max-reuse 0 ssl ssl-min-ver TLSv1.3 ssl-max-ver TLSv1.3 ${SSL_REUSE}
        option httpclose
        timeout client 10s
        timeout server 10s
        timeout connect 10s

frontend port${BASEPORT}
        bind :${BASEPORT} ssl crt ${PROXYCERT}
        http-request return status 200 content-type "text/plain" string "it works"

EOF
}

function emit_httpterm {
        typeset HAPROXY_CONF=$1
        typeset REUSE_LABEL=$2
        typeset BASEPORT=$3
        typeset PROXYCERT=$4
        typeset SSL_REUSE=$5

cat <<EOF >> ${HAPROXY_CONF}
defaults ${REUSE_LABEL}
        mode http
        http-reuse never
        default-server max-reuse 0 ssl ssl-min-ver TLSv1.3 ssl-max-ver TLSv1.3 ${SSL_REUSE}
        option httpclose
        timeout client 10s
        timeout server 10s
        timeout connect 10s

frontend port${BASEPORT}
        bind :${BASEPORT} ssl crt ${PROXYCERT}
        default_backend httpterm${BASEPORT}

backend httpterm${BASEPORT}
        server httpterm1-${BASEPORT} ${HTTPTERM_HOST}:${HTTPTERM_PORT} no-ssl

EOF
}

function emit_stats {
        typeset HAPROXY_CONF=$1
        typeset BASEPORT=$2
        typeset PROXYCERT=$3

cat <<EOF >> ${HAPROXY_CONF}
listen port${BASEPORT}
        bind :${BASEPORT} ssl crt ${PROXYCERT}
        stats uri /stats
        server next ${HOST}:$(( ${BASEPORT} - 1))

EOF
}

function emit_https_port {
        typeset HAPROXY_CONF=$1
        typeset PORT=$2
        typeset PROXYCERT=$3
cat <<EOF >> ${HAPROXY_CONF}
listen port${PORT}
        bind :${PORT} ssl crt ${PROXYCERT}
        server next ${HOST}:$(( ${PORT} - 1))

EOF
}

function emit_http_port {
        typeset HAPROXY_CONF=$1
        typeset HTTP_PORT=$2
        typeset PORT=$3

cat <<EOF >> ${HAPROXY_CONF}
listen port${HTTP_PORT}
        bind :${HTTP_PORT}
        server port${PORT} ${HOST}:${PORT} ssl verify none

EOF
}

#
# function creates haproxy.conf which should be
# identical to configuration used here [1].
#
# The configuration file defines 4 proxy variants:
#   ssl-reause with rsa+dh certificate,
#       https client connects to port 7020
#
#   no-ssl-reuse, with rsa+dh certificate,
#       https client connects to port 7120
#
#   ssl-reuse with ecdsa-256 certificate,
#       https client connects to port 7220
#
#   no-ssl-reuse with ecdsa-256 certificate,
#       https client connects to port 7320
#
# [1] https://www.haproxy.com/blog/state-of-ssl-stacks
#   search for 'daisy-chain'
#
function config_haproxy {
    typeset SSL_LIB=$1
    typeset RSACERTKEY=''
    typeset ECCERTKEY=''
    typeset HAPROXY_CONF='etc/haproxy.conf'
    typeset BASEPORT=''
    typeset TOPPORT=''
    typeset PORT=''
    typeset HTTP_PORT=''
    typeset SSL_REUSE=''
    typeset REUSE_LABEL=''
    typeset BASEPORT_RSA_REUSE=''
    typeset BASEPORT_RSA=''
    typeset BASEPORT_EC_REUSE=''
    typeset BASEPORT_EC=''

    if [[ -z "${SSL_LIB}" ]] ; then
        SSL_LIB='openssl-=master'
    fi

    mkdir -p ${INSTALL_ROOT}/${SSL_LIB}/etc || exit 1
    HAPROXY_CONF=${INSTALL_ROOT}/${SSL_LIB}/${HAPROXY_CONF}
    RSACERTKEY=${INSTALL_ROOT}/${SSL_LIB}/etc/dh-rsa-2048.pem
    ECCERTKEY=${INSTALL_ROOT}/${SSL_LIB}/etc/ec-dsa-256.pem

    emit_global ${HAPROXY_CONF}

    for i in `seq 2` ; do
        #
        # 1 - use built-in http server as chain terminator
        # 2 - use external http/term server as chain terminator,
        #     ports are moved by 1000
        #
        if [[ ${i} -eq 1 ]] ; then
            BASEPORT_RSA_REUSE=${PORT_RSA_REUSE}
            BASEPORT_RSA=${PORT_RSA}
            BASEPORT_EC_REUSE=${PORT_EC_REUSE}
            BASEPORT_EC=${PORT_EC}
        else
            BASEPORT_RSA_REUSE=$(( ${PORT_RSA_REUSE} + 1000))
            BASEPORT_RSA=$(( ${PORT_RSA} + 1000))
            BASEPORT_EC_REUSE=$(( ${PORT_EC_REUSE} + 1000))
            BASEPORT_EC=$(( ${PORT_EC} + 1000))
        fi
        for BASEPORT in ${BASEPORT_RSA_REUSE} ${BASEPORT_RSA} ${BASEPORT_EC_REUSE} ${BASEPORT_EC} ; do
            if [[ ${BASEPORT} -eq ${BASEPORT_RSA_REUSE} || ${BASEPORT} -eq ${BASEPORT_RSA} ]] ; then
                PROXYCERT=${RSACERTKEY}
            else
                PROXYCERT=${ECCERTKEY}
            fi
            if [[ ${BASEPORT} -eq ${BASEPORT_RSA_REUSE} || ${BASEPORT} -eq ${BASEPORT_EC_REUSE} ]] ; then
                SSL_REUSE=''
                REUSE_LABEL='ssl-reuse'
            else
                SSL_REUSE='no-ssl-reuse'
                REUSE_LABEL='no-ssl-reuse'
            fi
            if [[ ${i} -eq 1 ]] ; then
                emit_frontend ${HAPROXY_CONF} ${REUSE_LABEL} ${BASEPORT} ${PROXYCERT} ${SSL_REUSE}
            else
                emit_httpterm ${HAPROXY_CONF} ${REUSE_LABEL} ${BASEPORT} ${PROXYCERT} ${SSL_REUSE}
            fi

            BASEPORT=$(( ${BASEPORT} + 1))
            TOPPORT=$(( ${BASEPORT} + ${PROXY_CHAIN} - 1 ))
            emit_stats ${HAPROXY_CONF} ${BASEPORT} ${PROXYCERT}

            BASEPORT=$(( ${BASEPORT} + 1))
            for PORT in $(seq ${BASEPORT} ${TOPPORT}) ; do
                emit_https_port ${HAPROXY_CONF} ${PORT} ${PROXYCERT}
            done
            #
            # tests use siege client without https support.
            # so here we create http to https proxy. The proxy
            # is created for no-reuse tests only.
            #
            if [[ ${REUSE_LABEL} = 'no-ssl-reuse' ]] ; then
                HTTP_PORT=$(( ${PORT} + 1))
                emit_http_port ${HAPROXY_CONF} ${HTTP_PORT} ${PORT}
            fi
        done
    done
    gen_certkey ${RSACERTKEY} ${RSACERTKEY}.key
    gen_certkey_ec ${ECCERTKEY} ${ECCERTKEY}.key
    cd ${WORKSPACE_ROOT} || exit 1
}

function setup_tests {
    typeset i=0
    cd "${WORKSPACE_ROOT}"
    install_openssl master
    install_haproxy openssl-master
    install_httpterm openssl-master
    install_h1load openssl-master
    install_siege openssl-master
    config_haproxy openssl-master
    clean_build

    for i in 3.0 3.1 3.2 3.3 3.4 3.5 3.6 ; do
        cd "${WORKSPACE_ROOT}"
        install_openssl openssl-$i
        install_haproxy openssl-$i
        install_httpterm openssl-$i
        install_h1load openssl-$i
        install_siege openssl-$i
        config_haproxy openssl-$i
        clean_build
    done

    cd "${WORKSPACE_ROOT}"
    install_openssl OpenSSL_1_1_1-stable
    install_haproxy OpenSSL_1_1_1-stable
    install_httpterm OpenSSL_1_1_1-stable
    install_h1load OpenSSL_1_1_1-stable
    install_siege OpenSSL_1_1_1-stable
    config_haproxy OpenSSL_1_1_1-stable
    clean_build

    cd "${WORKSPACE_ROOT}"
    install_wolfssl 5.8.2 '--enable-haproxy --enable-quic'
    install_haproxy wolfssl-5.8.2
    install_httpterm wolfssl-5.8.2
    install_h1load wolfssl-5.8.2
    install_siege wolfssl-5.8.2
    config_haproxy wolfssl-5.8.2
    clean_build

    cd "${WORKSPACE_ROOT}"
    install_libressl 4.1.0
    install_haproxy libressl-4.1.0
    install_httpterm libressl-4.1.0
    install_h1load libressl-4.1.0
    install_siege libressl-4.1.0
    config_haproxy libressl-4.1.0
    clean_build

    #
    # does not build with boring
    #
    #install_boringssl
    #install_haproxy boringssl
    #install_httpterm boringssl
    #install_h1load boringssl
    #config_haproxy boringssl
    #cd "${WORKSPACE_ROOT}"
    #clean_build

    cd "${WORKSPACE_ROOT}"
    install_aws_lc
    install_haproxy aws-lc
    install_httpterm aws-lc
    install_h1load aws-lc
    #
    # siege does not build for aws-lc due to missing CRYPTO_thread_id()
    #
    #install_siege aws-lc
    config_haproxy aws-lc
    clean_build aws-lc
}

check_env
setup_tests
