# https performance tests with apache (or nginx)

The scripts here install and configure desired server with OpenSSL [1],
WolfSSL[2], LibreSSL [3], BoringSSL [4] and aws-lc [5]. Script builds
and installs the library to dedicated directory. Each library is built
with its default options which enable/disable features. The script then
uses siege [6] to measure https performance for each library. There are
no command line options everything is controlled using env. variables:
    -  `BENCH_INSTALL_ROOT` sets the directory under which the SSL libraries
	and tools are installed (`/tmp/branch.binaries` by default)
    -  `BENCH_WORKSPACE_ROOT` sets the workspace directory where libraries and
	tools are compiled.
    -  `BENCH_MAKE_OPTS` command line options for make(1) command
    -  `BENCH_RESULTS` directory where to save results
	(`$BENCH_INSTALL_ROOT/results` by default)
    -  `BENCH_HTTPS_PORT` port where https test server should listen to
	(4430 by default).
    -  `BENCH_HTTP_PORT` port where http test server should listen to
	(8080 by default)
    -  `BENCH_TEST_TIME` time to run performance test. default value is
	5 minutes (5M). See option `-t` in siege manual [7] for details.
    -  `BENCH_HOST` hostname/ip address where server is listening to
	(127.0.0.1 by default)
    -  `BENCH_CERT_SUBJ` set to `/CN=localhost` by default
    -  `BENCH_CERT_ALT_SUBJ`  set to `subjectAltName=DNS:localhost,IP:127.0.0.1`
	by default
The siege client runs in benchmark mode (with option `-b`). It is told to fetch
16 files until `BENCH_TEST_TIME` elapses. The file sizes are 64B, 128B,
256B, ... 4MB.

The libraries the benchmark tests are as follows:
    - OpenSSL 3.0, 3.1, ... 3.6, master
    - WolfSSL 5.8.2
    - BorinSSL master version
    - LibreSSL 4.1.0
    - aws-lc master version

## Apache

All tests use version 2.4.65 (except wolfssl which must use 2.4.51, however the
apache still does not work with WolfSSL, issue is still being investigated).
The apache server configuration is identical for all SSL libraries. The apache
server is built with mpm worker, event and pre-fork loadable modules. The test
iterates over three server configurations which each uses particular mpm
module. The modules run with their configuration supplied by apache.

The configuration for apache server (httpd.conf) is saved along the results
together with configuration for mod\_ssl. The script does not change any
parameters except adjustments of file paths. Everything runs with
default settings which come with apache installation.

## nginx

All tests use nginx 1.28 (except WolfSSL which uses 1.24). The
`worker_processes` configuration option is st to auto.
Apart from adjusting paths in nginx.conf the script also sets
option `work_process` to auto. Nginx server configuration is
saved along the results for each test.

## Build requirements

Requirements for ubuntu are the following:
    - ksh
    - gnuplot
    - git
    - ninja-build
    - cmake
    - wget
    - autoconf
    - bzip2
    - libpcre2-dev
    - libexpat-dev
    - golang-go
    - zlib1g-dev
    - libtool
    - g++

[1]: https://www.openssl.org/

[2]: https://www.wolfssl.com/

[3]: https://www.libressl.org/

[4]: https://www.chromium.org/Home/chromium-security/boringssl/

[5]: https://aws.amazon.com/security/opensource/cryptography/

[6]: https://www.joedog.org/siege-home/

[7]: https://www.joedog.org/siege-manual/
