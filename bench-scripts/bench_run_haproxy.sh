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

INSTALL_ROOT=${BENCH_INSTALL_ROOT:-"/tmp/bench.binaries"}
WORKSPACE_ROOT=${BENCH_WORKSPACE_ROOT:-"/tmp/bench.workspace"}
HAPROXY_NOSSL_PORT='42128'
HAPROXY_C2P_PORT='42132'
HAPROXY_P2S_PORT='42134'
HAPROXY_C2S_PORT='42136'
CERT_SUBJ=${BENCH_CERT_SUBJ:-'/CN=localhost'}
CERT_ALT_SUBJ=${BENCH_CERT_ALT_SUBJ:-'subjectAltName=DNS:localhost,IP:127.0.0.1'}
HOST=${BENCH_HOST:-'127.0.0.1'}
HAPROXY_VERSION='v3.2.0'

#
# Starts haproxy based on the configuration that was done beforehand calling
# install_haproxy.
#
function run_haproxy {
    typeset SSL_LIB=$1
    if [[ -z "${SSL_LIB}" ]] ; then
        SSL_LIB="openssl-master"
    fi
    typeset OPENSSL_DIR="${INSTALL_ROOT}/${SSL_LIB}"

    LD_LIBRARY_PATH="${OPENSSL_DIR}/lib:${LD_LIBRARY_PATH}" "${OPENSSL_DIR}/sbin/haproxy" -f "${OPENSSL_DIR}/conf/haproxy.cfg" -D
    if [[ $? -ne 0 ]] ; then
        echo "could not start haproxy"
        exit 1
    fi
}

#
# Configures the client (siege) to run with haproxy modes server and both.
# Those modes require the client to have the haproxy certificates.
#
function conf_siege_haproxy_cert {
    typeset SSL_LIB=$1
    if [[ -z "${SSL_LIB}" ]] ; then
        SSL_LIB="openssl-master"
    fi
    typeset OPENSSL_DIR="${INSTALL_ROOT}/${SSL_LIB}"
    # siege is currently installed only with openssl-master
    typeset SIEGE_CONF="${INSTALL_ROOT}/openssl-master/etc/siegerc"
	# configure siege to use haproxy
	if [[ ! -f "${SIEGE_CONF}" ]] ; then
	    echo "Did not found siegerc. Siege should be installed first."
	    exit 1
	fi
	echo "#haproxy" >> "${SIEGE_CONF}"
	echo "ssl-cert = ${OPENSSL_DIR}/conf/certs/client_cert.pem" >> "${SIEGE_CONF}"
	echo "ssl-key = ${OPENSSL_DIR}/conf/certs/client_key.pem" >> "${SIEGE_CONF}"
}

#
# Clears the haproxy certificates from the siege client config.
#
function unconf_siege_haproxy_cert {
    typeset SIEGE_CONF="${INSTALL_ROOT}/openssl-master/etc/siegerc"

    # clear the siege config
    sed -i '/#haproxy/{N;d;}' "${SIEGE_CONF}" || exit 1
}

function kill_haproxy {
    pkill -TERM -f haproxy
}
