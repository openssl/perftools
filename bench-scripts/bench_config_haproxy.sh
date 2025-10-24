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
RESULT_DIR=${BENCH_RESULTS:-"${INSTALL_ROOT}/results"}
WORKSPACE_ROOT=${BENCH_WORKSPACE_ROOT:-"/tmp/bench.workspace"}
MAKE_OPTS=${BENCH_MAKE_OPTS}
HAPROXY_NOSSL_PORT='42128'
HAPROXY_C2P_PORT='42132'
HAPROXY_P2S_PORT='42134'
HAPROXY_C2S_PORT='42136'
CERT_SUBJ=${BENCH_CERT_SUBJ:-'/CN=localhost'}
CERT_ALT_SUBJ=${BENCH_CERT_ALT_SUBJ:-'subjectAltName=DNS:localhost,IP:127.0.0.1'}
HOST=${BENCH_HOST:-'127.0.0.1'}
HAPROXY_VERSION='v3.2.0'

function install_haproxy {
    typeset SSL_LIB=$1
    typeset VERSION=${HAPROXY_VERSION:-v3.2.0}
    typeset HAPROXY_REPO="https://github.com/haproxy/haproxy.git"
    typeset BASENAME='haproxy'
    typeset DIRNAME="${BASENAME}-${VERSION}"
    typeset CERTDIR="${INSTALL_ROOT}/${SSL_LIB}/conf/certs"

    if [[ -z "${SSL_LIB}" ]] ; then
        SSL_LIB="openssl-master"
    fi

    if [[ -f "${INSTALL_ROOT}/${SSL_LIB}/sbin/haproxy" ]] ; then
        echo "haproxy already installed; skipping.."
    else
        cd "${WORKSPACE_ROOT}"
        mkdir -p "${DIRNAME}" || exit 1
        cd "${DIRNAME}"
        git clone "${HAPROXY_REPO}" -b ${VERSION} --depth 1 . || exit 1
        
        # haproxy does not have a configure script; only a big makefile
        make clean
        make ${MAKE_OPTS} \
             TARGET=generic \
             USE_OPENSSL=1 \
             SSL_INC="${INSTALL_ROOT}/${SSL_LIB}/include" \
             SSL_LIB="${INSTALL_ROOT}/${SSL_LIB}/lib" || exit 1

        make install ${MAKE_OPTS} \
             PREFIX="${INSTALL_ROOT}/${SSL_LIB}" || exit 1
    fi

    mkdir -p ${CERTDIR}

    # now generate the certificates
    echo "generating new certificates for haproxy"
    OPENSSL_BIN="env LD_LIBRARY_PATH=${INSTALL_ROOT}/${SSL_LIB}/lib ${INSTALL_ROOT}/${SSL_LIB}/bin/openssl"

    # generating the key, cert of ca
    $OPENSSL_BIN genpkey -algorithm rsa -pkeyopt rsa_keygen_bits:2048 -out "${CERTDIR}/ca_key.pem" || exit 1
    $OPENSSL_BIN req -new -x509 -days 1 -key "${CERTDIR}/ca_key.pem" -out "${CERTDIR}/ca_cert.pem" -subj "/CN=Root CA" \
        -addext "basicConstraints=critical,CA:true"  \
        -addext "keyUsage=critical,keyCertSign,cRLSign" || exit 1
    
    # generating the client side
    $OPENSSL_BIN genpkey -algorithm rsa -pkeyopt rsa_keygen_bits:2048 -out "${CERTDIR}/client_key.pem" || exit 1
    $OPENSSL_BIN pkey -in "${CERTDIR}/client_key.pem" -pubout -out "${CERTDIR}/client_key_pub.pem" || exit 1
    $OPENSSL_BIN req -new -out "${CERTDIR}/client_csr.pem" -subj "/CN=${HOST}" -key "${CERTDIR}/client_key.pem" \
        -addext "${CERT_ALT_SUBJ}" \
        -addext "keyUsage=critical,digitalSignature" || exit 1
    $OPENSSL_BIN x509 -req -out "${CERTDIR}/client_cert.pem" -CAkey "${CERTDIR}/ca_key.pem" -CA "${CERTDIR}/ca_cert.pem" \
        -days 1 -in "${CERTDIR}/client_csr.pem" -copy_extensions copy -ext "subjectAltName,keyUsage" \
        -extfile <(printf "basicConstraints=critical,CA:false\nsubjectKeyIdentifier=none\n") || exit 1

    # generating the server side
    $OPENSSL_BIN genpkey -algorithm rsa -pkeyopt rsa_keygen_bits:2048 -out "${CERTDIR}/server_key.pem" || exit 1
    $OPENSSL_BIN pkey -in "${CERTDIR}/server_key.pem" -pubout -out "${CERTDIR}/server_key_pub.pem" || exit 1
    $OPENSSL_BIN req -new -out "${CERTDIR}/server_csr.pem" -subj "/CN=${HOST}" -key "${CERTDIR}/server_key.pem" \
        -addext "${CERT_ALT_SUBJ}" \
        -addext "keyUsage=critical,digitalSignature" || exit 1
    $OPENSSL_BIN x509 -req -out "${CERTDIR}/server_cert.pem" -CAkey "${CERTDIR}/ca_key.pem" -CA "${CERTDIR}/ca_cert.pem" \
        -days 1 -in "${CERTDIR}/server_csr.pem" -copy_extensions copy -ext "subjectAltName,keyUsage" \
        -extfile <(printf "subjectKeyIdentifier=none\n"
                   printf "${CERT_ALT_SUBJ}\n"
                   printf "basicConstraints=critical,CA:false\n"
                   printf "keyUsage=critical,keyEncipherment\n") || exit 1

    # HAProxy PEM must be: server cert + server key (+ chain)
    cat "${CERTDIR}/server_cert.pem" "${CERTDIR}/server_key.pem" "${CERTDIR}/ca_cert.pem" > "${CERTDIR}/haproxy_server.pem"

    # setting up SSL Termination mode for now
    # haproxy modes: encoding from client to haproxy, to server from haproxy, both
    # the first needs a non TLS connection to the server - use the HTTP_PORT, otherwise use the HTTPS_PORT
    cat <<EOF > "${INSTALL_ROOT}/${SSL_LIB}/conf/haproxy.cfg"
defaults
  timeout server 10s
  timeout client 10s
  timeout connect 10s

frontend test_no_ssl
  mode http
  bind :${HAPROXY_NOSSL_PORT}
  default_backend http_test

frontend test_client2proxy
  mode http
  bind :${HAPROXY_C2P_PORT} ssl crt ${CERTDIR}/haproxy_server.pem ca-file ${CERTDIR}/ca_cert.pem verify required
  default_backend http_test

frontend test_proxy2server
  mode http
  bind :${HAPROXY_P2S_PORT}
  default_backend https_test

frontend test_client2server
  mode http
  bind :${HAPROXY_C2S_PORT} ssl crt ${CERTDIR}/haproxy_server.pem ca-file ${CERTDIR}/ca_cert.pem verify required
  default_backend https_test

backend http_test
  mode http
  balance random
  server s1 ${HOST}:${HTTP_PORT}

backend https_test
  mode http
  balance random
  server s2 ${HOST}:${HTTPS_PORT} ssl verify required ca-file ${INSTALL_ROOT}/${SSL_LIB}/conf/server.crt
EOF
}
