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

#
#
# make sure to disable firewall
#	ufw disable
# it feels like ipv6 loopback traffic is disabled on ubuntu
#

#
# This is the output of apachectl -V  we use to test
#  libraries:
#
# Server version: Apache/2.4.65 (Unix)
# Server built:   Sep 12 2025 14:49:08
# Server's Module Magic Number: 20120211:141
# Server loaded:  APR 1.7.6, APR-UTIL 1.6.3, PCRE 10.42 2022-12-11
# Compiled using: APR 1.7.6, APR-UTIL 1.6.3, PCRE 10.42 2022-12-11
# Architecture:   64-bit
# Server MPM:     event
#   threaded:     yes (fixed thread count)
#     forked:     yes (variable process count)
#
# the siege client downloads static files which look as follows
# for all tests:
#    64 Sep 12 14:49 test.txt
#   128 Sep 12 14:49 test_1.txt
#   256 Sep 12 14:49 test_2.txt
#   512 Sep 12 14:49 test_3.txt
#  1.0K Sep 12 14:49 test_4.txt
#  2.0K Sep 12 14:49 test_5.txt
#  4.0K Sep 12 14:49 test_6.txt
#  8.0K Sep 12 14:49 test_7.txt
#   16K Sep 12 14:49 test_8.txt
#   32K Sep 12 14:49 test_9.txt
#   64K Sep 12 14:49 test_10.txt
#  128K Sep 12 14:49 test_11.txt
#  256K Sep 12 14:49 test_12.txt
#  512K Sep 12 14:49 test_13.txt
#  1.0M Sep 12 14:49 test_14.txt
#  2.0M Sep 12 14:49 test_15.txt
#  4.0M Sep 12 14:49 test_16.txt
#

INSTALL_ROOT=${BENCH_INSTALL_ROOT:-"/tmp/bench.binaries"}
RESULT_DIR=${BENCH_RESULTS:-"${INSTALL_ROOT}/results"}
HTTPS_PORT=${BENCH_HTTPS_PORT:-'4430'}
HTTP_PORT=${BENCH_HTTP_PORT:-'8080'}
CERT_SUBJ=${BENCH_CERT_SUBJ:-'/CN=localhost'}
CERT_ALT_SUBJ=${BENCH_CERT_ALT_SUBJ:-'subjectAltName=DNS:localhost,IP:127.0.0.1'}
TEST_TIME=${BENCH_TEST_TIME:-'5M'}
HOST=${BENCH_HOST:-'127.0.0.1'}
APACHE_VERSION='2.4.65'
HAPROXY='no'

. ./common_util.sh
. ./bench_run_haproxy.sh

function enable_mpm {
	typeset MODE=$1
	typeset SSL_LIB=$2
	if [[ -z "${SSL_LIB}" ]] ; then
		SSL_LIB='openssl-master'
	fi
	if [[ -z "${MODE}" ]] || { [[ "${MODE}" != 'event' ]] &&
	   [[ "${MODE}" != 'worker' ]] && [[ "${MODE}" != 'prefork' ]] ; } ; then
		echo "enable_mpm: MODE needs to be set as the second argument."
	    	echo "given argument: ${MODE}"
	    	echo "enable_mpm: options are: event, worker, and prefork."
	    	exit 1
	fi
	typeset CONF_FILE="${INSTALL_ROOT}/${SSL_LIB}/conf/httpd.conf"

	#
	# comment out currently loaded mpm module
	#
	cp "${CONF_FILE}" "${CONF_FILE}".wrk
	sed -e 's/\(^LoadModule mpm_.*$\)/#\1/g' \
	    "${CONF_FILE}".wrk > "${CONF_FILE}" || exit 1

	#
	# enable MODE mpm module
	#
	cp "${CONF_FILE}" "${CONF_FILE}".wrk
	sed -e "s/\(^#\)\(LoadModule mpm_${MODE}_module .*$\)/\2/g" "${CONF_FILE}".wrk > "${CONF_FILE}" || exit 1
}

function run_test {
	typeset SSL_LIB=$1
	typeset HAPROXY=$2
	typeset i=0
	typeset PORT=${HTTPS_PORT}
	typeset PROTOCOL="https"
	if [[ -z "${SSL_LIB}" ]] ; then
		SSL_LIB='openssl-master'
	fi
	if [[ -z "${HAPROXY}" ]] ; then
		HAPROXY='no'
	fi
	typeset RESULTS="${SSL_LIB}".txt
	if [[ "${SSL_LIB}" = 'nossl' ]] ; then
		SSL_LIB='openssl-master'
		RESULTS='nossl.txt'
		PORT=${HTTP_PORT}
		PROTOCOL="http"
	fi
	if [[ "${HAPROXY}" != 'no' ]] ; then
		RESULTS="haproxy-${SSL_LIB}-${HAPROXY}.txt"
	fi
	typeset HTDOCS="${INSTALL_ROOT}/${SSL_LIB}"/htdocs
	typeset SIEGE="${INSTALL_ROOT}"/openssl-master/bin/siege

	#
	# we always try to use siege from openssl master by default,
	# if not found then we try the one which is installed for
	# openssl version we'd like to test.
	#
	if [[ ! -x "${SIEGE}" ]] ; then
		echo "no ${SIEGE}"
		exit 1
	fi

	#
	# generate URLs for sewage
	#
	# The different modes for haproxy are:
	# no: client - server
	# no-ssl: client -http- haproxy -http- server
	# server: client -https- haproxy -http- server
	# client: client -http- haproxy -https- server
	# both: client -https- haproxy -https- server
	#
	# Otherwise said, haproxy is a client when it encrypts the outgoing encryption;
	# or it's client side.
	#
	rm -f siege_urls.txt
	for i in `ls -1 ${HTDOCS}/*.txt` ; do
		if [[ "${HAPROXY}" = "no" ]] ; then
			echo "${PROTOCOL}://${HOST}:${PORT}/`basename $i`" >> siege_urls.txt
		elif [[ "${HAPROXY}" = "no-ssl" ]] ; then
			echo "http://${HOST}:${HAPROXY_NOSSL_PORT}/`basename $i`" >> siege_urls.txt
		elif [[ "${HAPROXY}" = "server" ]] ; then
			echo "https://${HOST}:${HAPROXY_C2P_PORT}/`basename $i`" >> siege_urls.txt
		elif [[ "${HAPROXY}" = "client" ]] ; then
			echo "http://${HOST}:${HAPROXY_P2S_PORT}/`basename $i`" >> siege_urls.txt
		elif [[ "${HAPROXY}" = "both" ]] ; then
			echo "https://${HOST}:${HAPROXY_C2S_PORT}/`basename $i`" >> siege_urls.txt
		fi
	done

	if [[ "${HAPROXY}" = "server" ]] || [[ "${HAPROXY}" = "both" ]] ; then
		conf_siege_haproxy_cert $SSL_LIB
	fi

	#
	# start apache httpd server
	#
	LD_LIBRARY_PATH=${INSTALL_ROOT}/${SSL_LIB}/lib \
	    ${INSTALL_ROOT}/${SSL_LIB}/bin/httpd -k start || exit 1
	if [[ $? -ne 0 ]] ; then
		echo "could not start ${INSTALL_ROOT}/${SSL_LIB}/bin/httpd"
		exit 1
	fi
	LD_LIBRARY_PATH=${INSTALL_ROOT}/openssl-master/lib "${SIEGE}" -t ${TEST_TIME}  -b \
	    -f siege_urls.txt 2> "${RESULT_DIR}/${RESULTS}"
	if [[ $? -ne 0 ]] ; then
		echo "${INSTALL_ROOT}/${SSL_LIB} can not run siege"
		cat "${RESULT_DIR}/${RESULTS}"
		exit 1
	fi

	LD_LIBRARY_PATH=${INSTALL_ROOT}/${SSL_LIB}/lib \
	    ${INSTALL_ROOT}/${SSL_LIB}/bin/httpd -k stop || exit 1
	sleep 1
	pgrep httpd
	while [[ $? -eq 0 ]] ; do
		sleep 1
		LD_LIBRARY_PATH=${INSTALL_ROOT}/${SSL_LIB}/lib \
		    ${INSTALL_ROOT}/${SSL_LIB}/bin/httpd -k stop || exit 1
		echo "stopping ${INSTALL_ROOT}/${SSL_LIB}/bin/httpd"
		pgrep httpd
	done

	#
	# save apache configuration used for testing along the results.
	# we do care about httpd.conf and httpd-ssl.conf only as only
	# those two were modified.
	#
	cp ${INSTALL_ROOT}/${SSL_LIB}/conf/httpd.conf \
	    ${RESULT_DIR}/httpd-${SSL_LIB}.conf
	cp ${INSTALL_ROOT}/${SSL_LIB}/conf/extra/httpd-ssl.conf \
	    ${RESULT_DIR}/httpd-ssl-${SSL_LIB}.conf

	if [[ "${HAPROXY}" = "server" ]] || [[ "${HAPROXY}" = "both" ]] ; then
		unconf_siege_haproxy_cert
	fi
}

function run_tests {
	typeset SAVE_RESULT_DIR="${RESULT_DIR}"
	typeset HAPROXY_OPTIONS=('no' 'client' 'server' 'both')
	typeset mode=""
	typeset i=""

	for mode in event worker prefork ; do
		mkdir -p ${SAVE_RESULT_DIR}/${mode} || exit 1

		enable_mpm ${mode}
		RESULT_DIR="${SAVE_RESULT_DIR}/${mode}"
		run_test nossl
		run_haproxy
		run_test nossl 'no-ssl'
		kill_haproxy
		for i in 3.0 3.1 3.2 3.3 3.4 3.5 3.6 master ; do
		    enable_mpm ${mode} openssl-${i}
		    run_haproxy openssl-${i}
		    for OPTION in ${HAPROXY_OPTIONS[@]} ; do
				run_test openssl-${i} ${OPTION}
		    done
		    kill_haproxy
		done
		enable_mpm ${mode} OpenSSL_1_1_1-stable
		run_test OpenSSL_1_1_1-stable
		enable_mpm ${mode} libressl-4.1.0
		run_test libressl-4.1.0
		#enable_mpm ${mode} wolfssl-5.8.2
		#run_test wolfssl-5.8.2
		enable_mpm ${mode} boringssl
		run_test boringssl
		enable_mpm ${mode} aws-lc
		run_test aws-lc
	done

	RESULT_DIR=${SAVE_RESULT_DIR}
}

check_env
run_tests
SAVE_RESULT_DIR=${RESULT_DIR}
for mode in event worker prefork ; do
	RESULT_DIR=${SAVE_RESULT_DIR}/${mode}
	plot_results
done
RESULT_DIR=${SAVE_RESULT_DIR}

echo "testing using siege is complete, results can be found ${RESULT_DIR}:"
