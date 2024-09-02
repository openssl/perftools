#
# Configuration
# =============
#
# To run performance test, it is suggested to build binaries outside of soruces.
# In the examples shown here, ./build is used with the normal CMake option to
# indicate the build directory.
#
# Configuration may be tricky with regards to using your OpenSSL installation
# of choice.  There are two ways:
#
# 1. Module mode:
#
#    - To use the system installation, or an installation in /usr/local,
#      nothing special needs to be set
#    - To use your own installation, such as in $HOME/.local, you can set
#      CMAKE_PREFIX_PATH to that directory.  Alternatively, you can use
#      OPENSSL_ROOT_DIR.
#      Caveat: on Windows, it's safest to always use OPENSSL_ROOT_DIR
#
#    Configuration examples:
#
#    System installation:
#
#        cmake -S . -B ./build
#
#    Your own installation (example: in $HOME/.local/opt/openssl-3.2):
#
#        cmake -S . -B ./build -DCMAKE_PREFIX_PATH=$HOME/.local/opt/openssl-3.2
#
#      or:
#
#        cmake -S . -B ./build -DOPENSSL_ROOT_DIR=$HOME/.local/opt/openssl-3.2
#
#      or on Windows:
#
#        cmake -S . -B ./build -DOPENSSL_ROOT_DIR=c:\Users\your\openssl.root
#
# 2. Config mode:
#
#    Support for Config mode is a fairly new addition to OpenSSL (only supported
#    by openSSL 3.3 and up).  It's only used by CMake when the Module mode hasn't
#    found Find<Package>.cmake, or when explicitly told to use Config mode only.
#
#    These two variables are involved:
#
#    - OPENSSL_CONFIG_MODE
#
#      Set to some value that means True to CMake (1, or YES), to force Config mode
#      to be used when looking for the openSSL package.
#
#    - CMAKE_PREFIX_PATH, if you want to use your own installation, or even just your
#      uninstalled OpenSSL build.
#
#    Configuration examples:
#
#    System installation:
#
#        cmake -S . -B ./build -DOPENSSL_CONFIG_MODE=1
#
#    Your own installation (example: in $HOME/.local/opt/openssl-3.3):
#
#        cmake -S . -B ./build -DOPENSSL_CONFIG_MODE=1 -DCMAKE_PREFIX_PATH=$HOME/.local/opt/openssl-3.3
#
#    Your own uninstalled build (example: in $HOME/tmp/openssl-3.3-build):
#
#        cmake -S . -B ./build -DOPENSSL_CONFIG_MODE=1 -DCMAKE_PREFIX_PATH=$HOME/tmp/openssl-3.3-build
#
# Build
# =====
#
# Build in default (Debug) mode:
#
#	cmake --build ./build
#
# Build in Release mode (only relevant for multi-configuration build generators,
# such as the default on Windows):
#
#	cmake --build ./build --config Release
#
# Running
# =======
#
# All programs that are built are in the build directory.
#
# Example:
#
#       ./build/randbytes 10
#
#
# 32-bit builds
# =============
# To perform 32-bit build on windows you need to add
# 	-DCMAKE_GENERATOR_PLATFORM=Win32
# option on command line. This also assumes you have 32-bit version of
# OpenSSL library ready in -DOPENSSL_ROOT_DIR path.
#

cmake_minimum_required(VERSION 3.10)
project(perf-tools)

find_package(Threads)
link_libraries(${CMAKE_THREAD_LIBS_INIT})

# OpenSSL 3.3 and on have config mode files.
if(OPENSSL_CONFIG_MODE)
    set(OPENSSL_CONFIG_MODE CONFIG)
else()
    unset(OPENSSL_CONFIG_MODE)
endif()
find_package(OpenSSL REQUIRED ${OPENSSL_CONFIG_MODE})

add_library(perf perflib/perfhelper.c perflib/perfsslhelper.c perflib/threads.c
	perflib/time.c)

if (WIN32)
    target_source(perf PRIVATE perflib/getopt.c perflib/basename.c
        perflib/strcasecmp.c)
endif()

target_include_directories(perf PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(perf PUBLIC OpenSSL::SSL OpenSSL::Crypto)

if( OPENSSL_VERSION VERSION_GREATER_EQUAL 3 )
    add_executable(evp_fetch evp_fetch.c)
    target_link_libraries(evp_fetch PRIVATE perf)

    add_executable(providerdoall providerdoall.c)
    target_link_libraries(providerdoall PRIVATE perf)
endif()

add_executable(randbytes randbytes.c)
target_link_libraries(randbytes PRIVATE perf)

add_executable(handshake handshake.c)
target_link_libraries(handshake PRIVATE perf)

add_executable(sslnew sslnew.c)
target_link_libraries(sslnew PRIVATE perf)

add_executable(newrawkey newrawkey.c)
target_link_libraries(newrawkey PRIVATE perf)

add_executable(rsasign rsasign.c)
target_link_libraries(rsasign PRIVATE perf)

add_executable(x509storeissuer x509storeissuer.c)
target_link_libraries(x509storeissuer PRIVATE perf)

add_executable(rwlocks rwlocks.c)
target_link_libraries(rwlocks PRIVATE perf)

add_executable(pkeyread pkeyread.c)
target_link_libraries(pkeyread PRIVATE perf)

add_executable(evp_setpeer evp_setpeer.c)
target_link_libraries(evp_setpeer PRIVATE perf)
