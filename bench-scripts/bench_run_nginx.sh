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
INSTALL_ROOT=${BENCH_INSTALL_ROOT:-"/tmp/bench.binaries"}
RESULT_DIR=${BENCH_RESULTS:-"${INSTALL_ROOT}/results"}
WORKSPACE_ROOT=${BENCH_WORKSPACE_ROOT:-"/tmp/bench.workspace"}
MAKE_OPTS=${BENCH_MAKE_OPTS}
HTTPS_PORT=${BENCH_HTTPS_PORT:-'4430'}
HTTP_PORT=${BENCH_HTTP_PORT:-'8080'}
CERT_SUBJ=${BENCH_CERT_SUBJ:-'/CN=localhost'}
CERT_ALT_SUBJ=${BENCH_CERT_ALT_SUBJ:-'subjectAltName=DNS:localhost,IP:127.0.0.1'}
TEST_TIME=${BENCH_TEST_TIME:-'5M'}
HOST=${BENCH_HOST:-'127.0.0.1'}

. ./common_util.sh

#
# the script builds various libssl libraries:
#	openssl, wolfssl, boringss, libressl
# each library is installed to its own install root under INSTALL_ROOT
# directory. The script also builds nginx server version 1.28 and installs
# it alongside each openssl library.
#
# for openssl the build process is straightforward:
#	clone desired version from github
#
#	build it with prefix set to INSTALL_ROOT/openssl-version
#	and install it
#
#	then clone the nginx server version 1.28, build process
#	for nginx is straightforward. the build options are as follows:
#		--with-http_ssl_module \
#		--with-threads \
#		--with-cc-opt="-fPIC" \
#		--with-ld-opt="-Wl,-rpath,${INSTALL_ROOT}/${SSL_LIB}/lib -L ${INSTALL_ROOT}/${SSL_LIB}/lib -lcrypto -L ${INSTALL_ROOT}/${SSL_LIB}/lib -lssl" \
#		--with-openssl="${WORKSPACE_ROOT}/${SSL_LIB}" || exit 1
#	with-openssl flag points to openssl sources
#	we deliberately pass lcrypto/lssl as we want to link them dynamically
#	without this hack the build process picks static version
#	found in WORKSPACE_ROOT/SSL_LIB
#
# for libressl the build process is similar. however we download
# ,tar.gz package instead doing git clone
#
# for boringssl the build process slightly differs as boringssl uses cmake.
# the build flags for boringssl are as follows:
#	-DCMAKE_INSTALL_PREFIX="${INSTALL_ROOT}/${BORING_NAME}" \
#	-DBUILD_SHARED_LIBS=1 \
#	-DCMAKE_BUILD_TYPE=Release
# nginx build process needs to be adjusted too. It happens in separate
# function setup_sslib_for_nginx() here in shell. Basically we create
# .openssl directory under $WORKSPACE_ROOT/boringssl sourcetree and populate
# it with boringssl headers files and create ,openssl/lib/libcrypto.a
# and .openssl/lib/libssl.a empty files using touch(1) this hack
# is sufficient to get nginx build process going. The nginx expects
# static libraries but we are forcing it to use dynamic versions
# by tweaking --with-ld-opt flags.
#
# there is a separate function install_wolf_nginx() which builds nginx
# with wolfssl it follows guide found here:
#	https://github.com/wolfssl/wolfssl-nginx
#
# all nginx servers use the same configuration:
#
#	worker_processes  auto;
#	events {
#	    worker_connections  1024;
#}
#
#	http {
#	    include       mime.types;
#	    default_type  application/octet-stream;
#	    #access_log  logs/access.log  main;
#	    sendfile        on;
#	    #tcp_nopush     on;
#	    #keepalive_timeout  0;
#	    keepalive_timeout  65;
#
#	    #gzip  on;
#
#	    server {
#	        listen       ${HTTP_PORT};
#	        server_name  ${SERVER_NAME};
#
#	        location / {
#	            root   html;
#	            index  index.html index.htm;
#	        }
#
#	        #error_page  404              /404.html;
#
#	        # redirect server error pages to the static page /50x.html
#	        #
#	        error_page   500 502 503 504  /50x.html;
#	        location = /50x.html {
#	            root   html;
#	        }
#
#	    }
#
#	    # HTTPS server
#	    #
#	    server {
#	        listen       ${HTTPS_PORT} ssl;
#	        server_name  ${SERVER_NAME};
#
#	        ssl_certificate      ${SERVERCERT};
#	        ssl_certificate_key  ${SERVERKEY};
#
#	        ssl_ciphers  HIGH:!aNULL:!MD5;
#	        ssl_prefer_server_ciphers  on;
#
#	        location / {
#	            root   html;
#	            index  index.html index.htm;
#	        }
#	    }
#	}
#
# the serverkey and servercert are self-signed certificate for
# localhost/127.0.0.1
#
# The performance is tested using siege (https://github.com/JoeDog/siege
# scripts build it and installs it along openssl-master
# the client by default fetches set of 17 urls for 5 minutes to
# gather performance data for each nginx/ssl combination.
# the sizes of files which are downloaded are {64, 128, 256, ... 4MB)
#


function run_test {
	typeset SSL_LIB=$1
	typeset HTTP='https'
	typeset i=0
	typeset PORT=${HTTPS_PORT}
	if [[ -z "${SSL_LIB}" ]] ; then
		SSL_LIB='openssl-master'
	fi
	typeset RESULTS="${SSL_LIB}".txt
	if [[ "${SSL_LIB}" = 'nossl' ]] ; then
		HTTP='http'
		SSL_LIB='openssl-master'
		RESULTS='nossl.txt'
		PORT=${HTTP_PORT}
	fi
	typeset HTDOCS="${INSTALL_ROOT}/${SSL_LIB}"/html
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

	rm -f siege_urls.txt
	for i in `ls -1 ${HTDOCS}/*.txt` ; do
		echo "${HTTP}://${HOST}:${PORT}/`basename $i`" >> siege_urls.txt
	done

	#
	# start nginx server
	#
	echo LD_LIBRARY_PATH=${INSTALL_ROOT}/${SSL_LIB}/lib ${INSTALL_ROOT}/${SSL_LIB}/sbin/nginx
	LD_LIBRARY_PATH=${INSTALL_ROOT}/${SSL_LIB}/lib ${INSTALL_ROOT}/${SSL_LIB}/sbin/nginx
	if [[ $? -ne 0 ]] ; then
		echo "could not start ${INSTALL_ROOT}/${SSL_LIB}/sbin/nginx"
		exit 1
	fi

	LD_LIBRARY_PATH=${INSTALL_ROOT}/openssl-master/lib "${SIEGE}" -t ${TEST_TIME}  -b \
	    -f siege_urls.txt 2> "${RESULT_DIR}/${RESULTS}"

	#
	# stop nginx server
	#
	LD_LIBRARY_PATH=${INSTALL_ROOT}/${SSL_LIB}/lib ${INSTALL_ROOT}/${SSL_LIB}/sbin/nginx -s quit

	#
	# save nginx.conf used for testing along the results
	#
	cp ${INSTALL_ROOT}/${SSL_LIB}/conf/nginx.conf ${RESULT_DIR}/nginx-${SSL_LIB}.conf
}

function run_tests {
	run_test nossl
	for i in 3.0 3.1 3.2 3.3 3.4 3.5 3.6 ; do
		run_test openssl-${i}
	done
	run_test openssl-master
	run_test OpenSSL_1_1_1-stable
	run_test libressl-4.1.0
	#
	# could not get apache with wolfssl working
	#
	run_test wolfssl-5.8.2
	run_test boringssl
	#run_test aws-lc
}

check_env
run_tests
plot_results

echo "testing using siege is complete, results can be found ${RESULT_DIR}:"
