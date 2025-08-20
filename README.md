# OpenSSL performance testing tools

This directory holds tools for carrying out performance tests on OpenSSL.

The various performance test applications are held within this directory, and
various helper files are held in perflib.

The performance test applications are intended to be linked against a supported
OpenSSL version, e.g. 3.1, 3.0, 1.1.1 - which is the version of OpenSSL that
is to be tested. Typically we would expect the apps to be built multiple times
(once for each target OpenSSL version to be tested).

## Build

To build the tests we assume that the target OpenSSL has already been built.

```sh
cmake -S . -B <OUTPUT PATH> -DOPENSSL_ROOT_DIR=<OPENSSL_ROOT_DIR>
cmake --build <OUTPUT PATH> --config Release
```

## Run

The performance testing apps must be run ensuring that `libcrypto.so` and
`libssl.so` are on the library path.

For example:

```sh
LD_LIBRARY_PATH=<PATH TO OPENSSL LIB> ./randbytes 10
```

Each performance testing app will take different parameters. They are described
individually below. All performance testing apps take the `--terse` option
which has the affect of just printing bare performance numbers without any
labels.

## randbytes

The randbytes test does 10000 calls of the [RAND_bytes()](https://docs.openssl.org/master/man3/RAND_bytes/) function divided
evenly among multiple threads. The number of threads to use is provided as
an argument and the test reports the average time take to execute a block of
1000 [RAND_bytes()](https://docs.openssl.org/master/man3/RAND_bytes/) calls.

## handshake

Performs a combined in-memory client and server handshake. In total 100000
handshakes are performed divided evenly among each thread. It take 2 optional
and two required arguments:

```
handshake [-t] [-s] <certsdir> <threadcount>
-t - produce terse output
-s - create an ssl_ctx per connection, rather than a single thread-shared ctx
-p - use ossl_lib_ctx per thread
-P - use ossl_lib_ctx pool (can be combined with -s. If sharing is enabled, ssl_ctx
     is shared within single thread)
-o - set ossl_lib_ctx pool size (use only with -P)
-l - use ssl_ctx pool
certsdir - Directory where the test can locate servercert.pem and serverkey.pem
threadcount - Number of concurrent threads to run in test
```

The output is two values: the average time taken for a single handshake in us,
and the average number of simultaneous handshakes per second performed over the
course of the test.

Note: Note on OpenSSL earlier than 3.6 you might hit the thread key local storage
limit with higher number of threads.

## sslnew

The `sslnew` test repeatedly constructs a new SSL object and associates it with a
newly constructed read BIO and a newly constructed write BIO, and finally frees
them again. It does 100000 repetitions divided evenly among each thread.
The number of threads to use is provided as an argument and the test
reports the average time taken to execute a block of 1000 construction/free
calls.

## newrawkey

The `newrawkey` test repeatedly calls the [EVP_PKEY_new_raw_public_key_ex()](https://docs.openssl.org/master/man3/EVP_PKEY_new/)
function. It does 100000 repetitions divided evenly among each thread. The
number of threads to use is provided as an argument and the test reports the
average time take to execute a block of 1000 [EVP_PKEY_new_raw_public_key_ex()](https://docs.openssl.org/master/man3/EVP_PKEY_new/)
calls.

Note that this test does not support OpenSSL 1.1.1.

## rsasign

The `rsasign` test repeatedly calls the [EVP_PKEY_sign_init()/EVP_PKEY_sign()](https://docs.openssl.org/master/man3/EVP_PKEY_sign/)
functions, using a 512 bit RSA key. It does 100000 repetitions divided evenly
among each thread. The number of threads to use is provided as an argument and
the test reports the average time take to execute a block of 1000
[EVP_PKEY_sign_init()/EVP_PKEY_sign()](https://docs.openssl.org/master/man3/EVP_PKEY_sign/) calls.

## x509storeissuer

Runs the function call [X509_STORE_CTX_get1_issuer()](https://docs.openssl.org/master/man3/X509_STORE_set_verify_cb_func/) repeatedly in a loop (which
is used in certificate chain building as part of a verify operation). The test
assumes that the default certificates directly exists but is empty. For a
default configuration this is "/usr/local/ssl/certs". The test takes the number
of threads to use as an argument and the test reports the average time take to
execute a block of 1000 [X509_STORE_CTX_get1_issuer()](https://docs.openssl.org/master/man3/X509_STORE_set_verify_cb_func/) calls.

## providerdoall

The `providerdoall` test repeatedly calls the [OSSL_PROVIDER_do_all()](https://docs.openssl.org/master/man3/OSSL_PROVIDER) function.
It does 100000 repetitions divided evenly among each thread. The number of
threads to use is provided as an argument and the test reports the average time
take to execute a block of 1000 [OSSL_PROVIDER_do_all()](https://docs.openssl.org/master/man3/OSSL_PROVIDER) calls.

## rwlocks

The `rwlocks` test creates the command line specified number of threads, splitting
them evenly between read and write functions (though this is adjustable via the
LOCK_WRITERS environment variable).  Threads then iteratively acquire a shared
rwlock to read or update some shared data.  The number of read and write
lock/unlock pairs are reported as a performance measurement

## pkeyread

The `pkeyread` test repeatedly calls the [PEM_read_bio_PrivateKey()](https://docs.openssl.org/master/man3/PEM_read_bio_PrivateKey/) function on a
memory BIO with a private key of desired type, when it is running in pem mode
(-f pem).  If test is running in der mode (-f der) it calls to
[d2i_PrivateKey_ex()](https://docs.openssl.org/master/man3/d2i_PrivateKey/) function to repeatedly read private key of desired type.
It does 10000 repetitions divided evenly among each thread. The number of
threads to use is provided by option `-t`. The test reports average time per
call. Use option `-k` to select key type for benchmark.  The list of keys for
testing is as follows: dh, dhx, dsa, ec, rsa, xkey.  To run benchmark for all
keys and formats using 4 threads run pkeyread as follows:

```sh
./pkeyread -f all -k all -t 4
```

## evp_setpeer

The `evp_setpeer` test repeatedly calls the [EVP_PKEY_derive_set_peer()](https://docs.openssl.org/master/man3/EVP_PKEY_derive/) function
on a memory BIO with a private key of desired type.  It does 10000
repetitions divided evenly among each thread. The last argument will be the
number of threads run. The test reports average time per call. Use option `-k`
to select key type for benchmark.  The list of keys for testing is as follows:
dh, ec256, ec521, x25519.  To run benchmark for all keys using 4 threads, run
evp_setpeer as follows:

```sh
./evp_setpeer -k all -t 4
```

## writeread

Performs an in-memory client and server handshake and measures the average
time taken for a single sequence of calling [SSL_write_ex()](https://docs.openssl.org/master/man3/SSL_write/) on the client and
[SSL_write_ex()](https://docs.openssl.org/master/man3/SSL_write/) on the server.  In total 1000000 writes and reads are performed
divided evenly among each thread. It take 4 optional and 2 required arguments:

```
writeread [-t] [-s] [-d] [-b size] <certsdir> <threadcount>
-t - produce terse output.
-s - create an ssl_ctx per connection, rather than a single thread-shared ctx.
-d - use DTLS as connection method.
-b - size of buffer to write and read, default is 1024 bytes.
certsdir - directory where the test can locate servercert.pem and serverkey.pem.
threadcount - number of concurrent threads to run in test.
```

## ssl_poll_perf

Tool to evaluate performance of QUIC client and server which both use
[SSL_poll](https://docs.openssl.org/master/man3/SSL_poll/)(3ossl). Application creates two threads, one for client the
other for server. Server and client can both accept/create simultanous
connections. Each connection then can carry multiple unidirectional/bidirectional
streams. The streams handle HTTP/1.0 GET request/responses only.
Server always drains the incoming stream initiated by client.  It answers to
any GET request. The default reply is 200 OK with 12345 bytes of payload.
Client may request desired payload with URL as follows:

```
/any/path/to_8192whatever/foo_4096.txt
```

In which case the server will send response with 8kB http/1.0 body.
The URL parser attempts to find leftmost number, which denotes the number
of bytes client expects in response.
The test program supports options as follows:

```
-c - number of connections to create (default 10)
-b - number of bidirectional streams each connection creates (default 10)
-u - number of unidirectional streams each connection creates (default 10)
-s - the size of reply body, the maximum size is 100MB. The default size is 64.
-w - the size of request body, the maximum size is 100MB. The default size is 64.
-p - port number to use
-t - terse output
```
