#
# make sure to set env. variables first:
#	OPENSSL_ROOT_DIR - points to OpenSSL installation
#		prefix with desired version
#
# to run performance test I suggest to build binaries outside of soruces.
# run cmake as follows:
#	cmake -S . -B ./build
# option -B defines location of project files and resulting binaries.
#
# then you can build tools using cmake:
#	cmake --build ./build
#
#

cmake_minimum_required(VERSION 3.10)
project(perf-tools)

add_library(perf perflib/perfhelper.c perflib/perfsslhelper.c perflib/threads.c
	perflib/time.c perflib/getopt.c perflib/basename.c perflib/strcasecmp.c)

#
# Using PRIVATE instead of PUBLIC will will break build with 1.1.1 version
# on Windows. This glitch is specific to 1.1.1 3.x versions do build fine.
# So let's keep PUBLIC here.
#
include_directories(PUBLIC ${OPENSSL_INCLUDE_DIR} . )

find_package(Threads)
link_libraries(${CMAKE_THREAD_LIBS_INIT})

find_package(OpenSSL REQUIRED)

if( "${OPENSSL_VERSION}" MATCHES 3\.* )
    add_executable(evp_fetch evp_fetch.c)
    target_include_directories(evp_fetch PRIVATE "$(PROJECT_BINARY_DIR)" "$(PROJECT_SOURCE_DIR)")
    target_link_libraries(evp_fetch PRIVATE perf OpenSSL::Crypto)

    add_executable(providerdoall providerdoall.c)
    target_include_directories(providerdoall PRIVATE "$(PROJECT_BINARY_DIR)" "$(PROJECT_SOURCE_DIR)")
    target_link_libraries(providerdoall PRIVATE perf OpenSSL::Crypto)
endif()

add_executable(randbytes randbytes.c)
target_include_directories(randbytes PRIVATE "$(PROJECT_BINARY_DIR)" "$(PROJECT_SOURCE_DIR)")
target_link_libraries(randbytes PRIVATE perf OpenSSL::Crypto)

add_executable(handshake handshake.c)
target_include_directories(handshake PRIVATE "$(PROJECT_BINARY_DIR)" "$(PROJECT_SOURCE_DIR)")
target_link_libraries(handshake PRIVATE perf OpenSSL::Crypto OpenSSL::SSL)

add_executable(sslnew sslnew.c)
target_include_directories(sslnew PRIVATE "$(PROJECT_BINARY_DIR)" "$(PROJECT_SOURCE_DIR)")
target_link_libraries(sslnew PRIVATE perf OpenSSL::Crypto OpenSSL::SSL)

add_executable(newrawkey newrawkey.c)
target_include_directories(newrawkey PRIVATE "$(PROJECT_BINARY_DIR)" "$(PROJECT_SOURCE_DIR)")
target_link_libraries(newrawkey PRIVATE perf OpenSSL::Crypto)

add_executable(rsasign rsasign.c)
target_include_directories(rsasign PRIVATE "$(PROJECT_BINARY_DIR)" "$(PROJECT_SOURCE_DIR)")
target_link_libraries(rsasign PRIVATE perf OpenSSL::Crypto)

add_executable(x509storeissuer x509storeissuer.c)
target_include_directories(x509storeissuer PRIVATE "$(PROJECT_BINARY_DIR)" "$(PROJECT_SOURCE_DIR)")
target_link_libraries(x509storeissuer PRIVATE perf OpenSSL::Crypto)

add_executable(rwlocks rwlocks.c)
target_include_directories(rwlocks PRIVATE "$(PROJECT_BINARY_DIR)" "$(PROJECT_SOURCE_DIR)")
target_link_libraries(rwlocks PRIVATE perf OpenSSL::Crypto)

add_executable(pkeyread pkeyread.c)
target_include_directories(pkeyread PRIVATE "$(PROJECT_BINARY_DIR)" "$(PROJECT_SOURCE_DIR)")
target_link_libraries(pkeyread PRIVATE perf OpenSSL::Crypto)
