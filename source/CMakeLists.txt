#
# Configuration
# =============
#
# To run performance test, it is suggested to build binaries outside of sources.
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
#    by OpenSSL 3.3 and up).  It's only used by CMake when the Module mode hasn't
#    found Find<Package>.cmake, or when explicitly told to use Config mode only.
#
#    These two variables are involved:
#
#    - OPENSSL_CONFIG_MODE
#
#      Set to some value that means True to CMake (1, or YES), to force Config mode
#      to be used when looking for the OpenSSL package.
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
# cmake also generates a run target.  The run target serves as a
# unit test which runs all commands. Use 'cmake --build build -t run' command
# to run it.  Note that if the build was configured without explicit
# OPENSSL_ROOT_DIR set, one might wants to properly set run_certdir cache
# variable beforehand.
#
# 32-bit builds
# =============
# To perform 32-bit build on windows you need to add
# 	-DCMAKE_GENERATOR_PLATFORM=Win32
# option on command line. This also assumes you have 32-bit version of
# OpenSSL library ready in -DOPENSSL_ROOT_DIR path.
#
# Using cmake 4.x on MacOS
# ========================
# According to cmake changelog [1] you may need to add -DCMAKE_OSX_SYSROOT=macosx
# option to prevent cmake to search for header files in /usr/local/include.
# You typically need it if openssl library you want to test is installed
# in non-standard location (for example in ~/openssl.binaries. In that
# case you want to build tools using commands:
#	cmake -S . -B build -DOPENSSL_ROOT_DIR=~/openssl.binaries \
#		-DCMAKE_OSX_SYSROOT=macosx
#	cmake --build build
#
# [1] https://cmake.org/cmake/help/v4.0/release/4.0.html#other-changes
#

option(WITH_OPENSSL_FORK "WITH_OPENSSL_FORK" 0)

cmake_minimum_required(VERSION 3.10)
project(perf-tools)
include(CheckSymbolExists)

if(WIN32)
    set(CFLAGS_WARNINGS "/Wall" CACHE STRING "Compiler options for warnings")
else()
    set(CFLAGS_WARNINGS "-Wall" CACHE STRING "Compiler options for warnings")
endif()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${CFLAGS_WARNINGS}"
    CACHE STRING "C compiler options" FORCE)

find_package(Threads)
link_libraries(${CMAKE_THREAD_LIBS_INIT})

# OpenSSL 3.3 and on have config mode files.
if(OPENSSL_CONFIG_MODE)
    set(OPENSSL_CONFIG_MODE CONFIG)
else()
    unset(OPENSSL_CONFIG_MODE)
endif()

add_library(perf perflib/perfhelper.c perflib/perfsslhelper.c perflib/threads.c
	perflib/time.c)

if(WIN32)
    target_sources(perf PRIVATE perflib/getopt.c perflib/basename.c perflib/err.c)
    #
    # windows release build on github workflow places places .exe files under
    # build\Release. This tweak hopes to place or .exe files under \build
    # for both build types.
    #
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_DEBUG "${OUTPUT_DIRECTORY}")
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELEASE "${OUTPUT_DIRECTORY}")
endif()

target_include_directories(perf PUBLIC "${PROJECT_SOURCE_DIR}")

if (WITH_OPENSSL_FORK)
    find_package(PkgConfig)
    if( ${CMAKE_PREFIX_PATH} MATCHES .*wolfssl.* )
        pkg_check_modules(WOLFSSL REQUIRED IMPORTED_TARGET wolfssl)
        target_link_libraries(perf PUBLIC PkgConfig::WOLFSSL)
        include_directories(BEFORE ${WOLFSSL_INCLUDE_DIRS})
        include_directories(BEFORE ${CMAKE_PREFIX_PATH}/include/wolfssl)
        include_directories(BEFORE ${CMAKE_PREFIX_PATH}/include)
        #
        # wolfssl recommends applications to include
        # wolfssl/options.h header file which is generated
        # at build time during configure step.
        # Instead of updating perftools applications we
        # just pass missing definitions here:
        #	OPENSSL_EXTRA
        #	WOLFSSL_DTLS
        #	WOLFSSL_NO_OPTIONS_H
        #       WC_NO_HARDEN (suppresses false positive warning)
        #
        add_compile_definitions(WOLFSSL_NO_OPTIONS_H
                                WITH_OPENSSL_FORK
                                OPENSSL_EXTRA
                                WC_NO_HARDEN
                                WOLFSSL_DTLS)
    elseif( ${CMAKE_PREFIX_PATH} MATCHES .*libressl.* )
        pkg_check_modules(LIBRESSL REQUIRED IMPORTED_TARGET openssl)
        target_link_libraries(perf PUBLIC PkgConfig::LIBRESSL)
        include_directories(BEFORE ${CMAKE_PREFIX_PATH}/include)
        add_compile_definitions(WITH_OPENSSL_FORK)
    elseif( ${CMAKE_PREFIX_PATH} MATCHES .*boringssl.* )
        find_package(OpenSSL REQUIRED ${OPENSSL_CONFIG_MODE})
        target_link_libraries(perf PUBLIC OpenSSL::SSL OpenSSL::Crypto)
        include_directories(BEFORE ${CMAKE_PREFIX_PATH}/include)
        add_compile_definitions(WITH_OPENSSL_FORK)
        set(SKIP_HANDSHAKE 1)
        set(SKIP_STOREISSUER 1)
    elseif( ${CMAKE_PREFIX_PATH} MATCHES .*aws-lc.* )
        find_package(OpenSSL REQUIRED ${OPENSSL_CONFIG_MODE})
        target_link_libraries(perf PUBLIC OpenSSL::SSL OpenSSL::Crypto)
        include_directories(BEFORE ${CMAKE_PREFIX_PATH}/include)
        add_compile_definitions(WITH_OPENSSL_FORK)
        set(SKIP_HANDSHAKE 1)
    else()
        message(FATAL_ERROR
            "CMAKE_PREFIX_PATH does not point to wolfssl|libressl|boringssl|aws-lc")
    endif()
else()
    find_package(OpenSSL REQUIRED ${OPENSSL_CONFIG_MODE})
    target_link_libraries(perf PUBLIC OpenSSL::SSL OpenSSL::Crypto)
    set(CMAKE_REQUIRED_LIBRARIES OpenSSL::SSL OpenSSL::Crypto)
    set(CMAKE_REQUIRED_INCLUDES "${OPENSSL_INCLUDE_DIR}")
endif()

check_symbol_exists(OSSL_LIB_CTX_freeze "openssl/crypto.h" HAVE_OSSL_LIB_CTX_FREEZE)
check_symbol_exists(SSL_set1_dnsname "openssl/ssl.h" HAVE_SSL_SET1_DNSNAME)

set(run_tests CACHE STRING "List of tests to run")
set(run_opts CACHE STRING "List of per-text options")

if( OPENSSL_VERSION VERSION_GREATER_EQUAL 3 )
    add_executable(evp_fetch evp_fetch.c)
    target_link_libraries(evp_fetch PRIVATE perf)
    list(APPEND run_tests evp_fetch)

    set(run_evp_fetch_pqs
        evp_fetch "" "" "-q"
        CACHE STRING "Post-quantum option for evp_fetch")
    list(APPEND run_opts run_evp_fetch_pqs)
    if(HAVE_OSSL_LIB_CTX_FREEZE)
        set(run_evp_fetch_freeze
            evp_fetch "" "" "-F"
            CACHE STRING "Freeze LIB_CTX for evp_fetch")
        list(APPEND run_opts run_evp_fetch_pqs)
    endif()

    add_executable(providerdoall providerdoall.c)
    target_link_libraries(providerdoall PRIVATE perf)
    list(APPEND run_tests providerdoall)

    add_executable(evp_cipher evp_cipher.c)
    target_link_libraries(evp_cipher PRIVATE perf)
    list(APPEND run_tests evp_cipher)
    set(run_evp_cipher_operations
        evp_cipher "" "" "-o evp_isolated" "-o evp_shared"
        CACHE STRING "Modes of operation for evp_cipher")
    list(APPEND run_opts run_evp_cipher_operations)
    set(run_evp_cipher_algorithms
        evp_cipher "" "" "-a AES-128-CBC" "-a AES-256-CBC"
        CACHE STRING "Encryption algorithms for evp_cipher")
    list(APPEND run_opts run_evp_cipher_algorithms)
    if(HAVE_OSSL_LIB_CTX_FREEZE)
        set(run_evp_cipher_freeze
            evp_cipher "" "" "-f"
            CACHE STRING "Freeze LIB_CTX for evp_cipher")
        list(APPEND run_opts run_evp_cipher_freeze)
    endif()

    add_executable(evp_mac evp_mac.c)
    target_link_libraries(evp_mac PRIVATE perf)
    list(APPEND run_tests evp_mac)
    set(run_evp_mac_operations
        evp_mac "" "" "-o deprecated_isolated" "-o deprecated_shared" "-o evp_isolated" "-o evp_shared"
        CACHE STRING "Modes of operation for evp_mac")
    list(APPEND run_opts run_evp_mac_operations)

    add_executable(evp_kdf evp_kdf.c)
    target_link_libraries(evp_kdf PRIVATE perf)
    list(APPEND run_tests evp_kdf)
    set(run_evp_kdf_operations
        evp_kdf "" "" "-o evp_shared" "-o evp_isolated" "-o deprecated_shared" "-o deprecated_isolated"
        CACHE STRING "Modes of operation for evp_kdf")
    list(APPEND run_opts run_evp_kdf_operations)
    if(HAVE_OSSL_LIB_CTX_FREEZE)
        set(run_evp_kdf_freeze
            evp_kdf "" "" "-f"
            CACHE STRING "Freeze LIB_CTX for evp_kdf")
        list(APPEND run_opts run_evp_kdf_freeze)
    endif()

    add_executable(evp_rand evp_rand.c)
    target_link_libraries(evp_rand PRIVATE perf)
    list(APPEND run_tests evp_rand)
    set(run_evp_rand_operations
        evp_rand "" "" "-o evp_isolated" "-o evp_shared"
        CACHE STRING "Modes of operation for evp_rand")
    list(APPEND run_opts run_evp_rand_operations)
    if(HAVE_OSSL_LIB_CTX_FREEZE)
        set(run_evp_rand_freeze
            evp_rand "" "" "-f"
            CACHE STRING "Freeze LIB_CTX for evp_rand")
        list(APPEND run_opts run_evp_rand_freeze)
    endif()

    add_executable(evp_pkey evp_pkey.c)
    target_link_libraries(evp_pkey PRIVATE perf)
    list(APPEND run_tests evp_pkey)
    set(run_evp_pkey_operations
        evp_pkey "" "" "-o evp_isolated" "-o evp_shared"
        CACHE STRING "Modes of operation for evp_pkey")
    list(APPEND run_opts run_evp_pkey_operations)
    set(run_evp_pkey_algorithms
        evp_pkey "" "" "-a RSA" "-a X25519" "-a X448" "-a ED25519" "-a ED448"
        CACHE STRING "Algorithms for evp_pkey")
    list(APPEND run_opts run_evp_pkey_algorithms)

endif()

if( OPENSSL_VERSION VERSION_GREATER_EQUAL 3.6 )
    add_executable(ssl_poll_perf ssl_poll_perf.c)
    if(WIN32)
        target_link_libraries(ssl_poll_perf PUBLIC wsock32 ws2_32 PRIVATE perf)
    else()
        target_link_libraries(ssl_poll_perf PRIVATE perf)
    endif()
endif()

add_executable(randbytes randbytes.c)
target_link_libraries(randbytes PRIVATE perf)
list(APPEND run_tests randbytes)

add_executable(handshake handshake.c)
target_link_libraries(handshake PRIVATE perf)
if( NOT ${SKIP_HANDSHAKE} )
    list(APPEND run_tests handshake)
    set(run_handshake_ctx_sharing
        handshake "" "" "-s"
        CACHE STRING "Context sharing option for handshake")
    list(APPEND run_opts run_handshake_ctx_sharing)
    if (NOT WITH_OPENSSL_FORK)
        set(run_handshake_pools
            handshake "" "-p" "-P" "-l"
            CACHE STRING "Pool types for handshake")
        list(APPEND run_opts run_handshake_pools)
        set(run_handshake_pool_size
            handshake "" "" "-o 4" "-o 256"
            CACHE STRING "Pool size for handshake")
        list(APPEND run_opts run_handshake_pool_size)
        set(run_handshake_secure_memory
            handshake "" "-S 1048576"
            CACHE STRING "Secure memory usage for handshake")
        list(APPEND run_opts run_handshake_secure_memory)
    endif() # NOT fork
endif() # skip hadnshake

add_executable(sslnew sslnew.c)
target_link_libraries(sslnew PRIVATE perf)
list(APPEND run_tests sslnew)

if (NOT WITH_OPENSSL_FORK )
    add_executable(newrawkey newrawkey.c)
    target_link_libraries(newrawkey PRIVATE perf)
    list(APPEND run_tests newrawkey)
    set(run_newrawkey_algos
        newrawkey "-a" x25519 ml-kem-512 ml-kem-768 ml-kem-1024
        CACHE STRING "Algorithms for newrawkey")
    list(APPEND run_opts run_newrawkey_algos)
endif()

add_executable(rsasign rsasign.c)
target_link_libraries(rsasign PRIVATE perf)
list(APPEND run_tests rsasign)

add_executable(x509storeissuer x509storeissuer.c)
target_link_libraries(x509storeissuer PRIVATE perf)
if( NOT ${SKIP_STOREISSUER} )
    list(APPEND run_tests x509storeissuer)
endif()

if( NOT WITH_OPENSSL_FORK )
    add_executable(rwlocks rwlocks.c)
    target_link_libraries(rwlocks PRIVATE perf)
    list(APPEND run_tests rwlocks)
endif()

if( NOT WITH_OPENSSL_FORK )
    add_executable(pkeyread pkeyread.c)
    if(WIN32)
        target_link_libraries(pkeyread PRIVATE perf)
    else()
        target_link_libraries(pkeyread PUBLIC m PRIVATE perf)
    endif()
    list(APPEND run_tests pkeyread)
    set(run_pkeyread_keys
        pkeyread "-k" dh dhx dsa ec rsa x25519 all
        CACHE STRING "Key types for pkeyread")
    list(APPEND run_opts run_pkeyread_keys)
    set(run_pkeyread_fmts
        pkeyread "-f" pem der all
        CACHE STRING "Key formats for pkeyread")
    list(APPEND run_opts run_pkeyread_fmts)
endif()

add_executable(evp_setpeer evp_setpeer.c)
target_link_libraries(evp_setpeer PRIVATE perf)
list(APPEND run_tests evp_setpeer)
if ( WITH_OPENSSL_FORK )
    set(run_evp_setpeer_keys
        evp_setpeer "-k" ec256 ec521
        CACHE STRING "Key types for evp_setpeer")
else()
    set(run_evp_setpeer_keys
        evp_setpeer "-k" dh ec256 ec521 x25519 all
        CACHE STRING "Key types for evp_setpeer")
endif()
list(APPEND run_opts run_evp_setpeer_keys)

add_executable(writeread writeread.c)
target_link_libraries(writeread PRIVATE perf)
list(APPEND run_tests writeread)
if (NOT WITH_OPENSSL_FORK)
    set(run_writeread_ctx_sharing
        writeread "" "" "-s"
        CACHE STRING "Context sharing for writeread")
    list(APPEND run_opts run_writeread_ctx_sharing)
    set(run_writeread_dtls
        writeread "" "" "-d"
        CACHE STRING "DTLS mode for writeread")
    list(APPEND run_opts run_writeread_dtls)
endif()
set(run_writeread_buffers
    writeread "" "" "-b 256" "-b 4096"
    CACHE STRING "Buffer size for writeread")
list(APPEND run_opts run_writeread_buffers)

if( NOT WITH_OPENSSL_FORK )
    add_executable(evp_hash evp_hash.c)
    target_link_libraries(evp_hash PRIVATE perf)
    list(APPEND run_tests evp_hash)
    set(run_evp_hash_operations
        evp_hash "" "" "-o deprecated" "-o evp_isolated" "-o evp_shared"
        CACHE STRING "Modes of operation for evp_hash")
    list(APPEND run_opts run_evp_hash_operations)
    set(run_evp_hash_update_times
        evp_hash "" "" "-u 1" "-u 5"
        CACHE STRING "Digest update times for evp_hash")
    list(APPEND run_opts run_evp_hash_update_times)
    set(run_evp_hash_algorithms
        evp_hash "" "" "-a SHA1" "-a SHA224" "-a SHA256" "-a SHA384" "-a SHA512"
        CACHE STRING "Digest hash algorithms for evp_hash")
    list(APPEND run_opts run_evp_hash_algorithms)
    if(HAVE_OSSL_LIB_CTX_FREEZE)
        set(run_evp_hash_freeze
        evp_hash "" "" "-f"
        CACHE STRING "Freeze LIB_CTX for evp_hash")
        list(APPEND run_opts run_evp_hash_freeze)
    endif()
endif()

set(run_add_version_dep ON
    CACHE BOOL "Whether to print version information on run " +
               "(call all the tests with -V option before the main run)")

# Used across multiple tests
set(run_certdir_tests handshake writeread x509storeissuer
    CACHE STRING "List of tests that require certdir parameter")
if ( WITH_OPENSSL_FORK )
    file(TO_NATIVE_PATH "${OPENSSL_SOURCE}/test/certs/" run_certdir_def_path)
else()
    file(TO_NATIVE_PATH "${OPENSSL_ROOT_DIR}/test/certs/" run_certdir_def_path)
endif()
set(run_certdir "${run_certdir_def_path}"
    CACHE PATH "Path to certificates directory for tests that need it")

# Common options
set(run_terse "" "-t"
    CACHE STRING "List of terse output options")
if( WITH_OPENSSL_FORK )
    set(run_threads 1
        CACHE STRING "List of thread counts")
else()
    set(run_threads 1 4
        CACHE STRING "List of thread counts")
endif()

add_custom_target(run
                  COMMENT "Run perf tests"
                  WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}")

# Version target
add_custom_target(run-version
                  COMMENT "Get version information for perf tests"
                  WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}")
if (run_add_version_dep)
    add_dependencies(run run-version)
endif()

#
# On Windows, we can't have nice things, and the easiest way to use
# specifically the libraries we've built against is to copy them
# in the directory where executable reside.
#
if (WIN32)
    #
    # An intermediate target to ensure that any DLLs touching happens strictly
    # before their usage.
    #
    add_custom_target(run-copy-dlls
                      COMMENT "Copy dependent DLLs into the build directory")

    # Generate search path for later DLL copying
    set(dll_search_dirs)
    foreach (f IN LISTS OPENSSL_CRYPTO_LIBRARIES OPENSSL_SSL_LIBRARIES)
        get_filename_component(f_dir "${f}" DIRECTORY)
        list(APPEND dll_search_dirs "${f_dir}")
    endforeach()
endif()

# Generate config.h from config.h.in
configure_file(config.h.in ${CMAKE_SOURCE_DIR}/config.h)

#
# gen_run_target(<cmd> <test> [VAR <var>] [NAME <name>])
#
# Generates a target that runs <cmd> and depends on target <test> and sets
# <var> to the target's name.
#
function(gen_run_taget _CMD _TEST)
    include(CMakeParseArguments)

    set(_Options "")
    set(_OneValueArgs VAR NAME)
    set(_MultiValueArgs "")
    cmake_parse_arguments(GEN_RUN_TARGET
        "${_Options}"
        "${_OneValueArgs}"
        "${_MultiValueArgs}"
        ${ARGN}
    )

    string(REGEX REPLACE "  *" ";" cmd "${_CMD}")
    string(REGEX REPLACE "[^0-9A-Za-z]" "-" cmd_target_name "${cmd}")
    # A hack for lesser OSes that cannot normally distinguish lower-
    # and uppercase letters.
    if (WIN32 OR APPLE)
        string(REGEX REPLACE "[A-Z]" "\\0_" cmd_target_name
               "${cmd_target_name}")
    endif()
    if (NOT GEN_RUN_TARGET_NAME)
        set(GEN_RUN_TARGET_NAME "run-${cmd_target_name}")
    endif()
    string(REPLACE ";" " " cmd_desc "${cmd}")


    add_custom_target("${GEN_RUN_TARGET_NAME}"
                      COMMAND ${cmd}
                      DEPENDS "${_TEST}"
                      COMMENT "Run ${cmd_desc}"
                      WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
                      USES_TERMINAL)

    # A dirty hack to copy the dependent DLLs into the build directory so they
    # get picked up before the ones in the system directory or wherever.
    if(WIN32)
        if (NOT TARGET "${_TEST}-copy-dlls")
            add_custom_target("${_TEST}-copy-dlls"
                              COMMAND ${CMAKE_COMMAND}
                                      -D TARGET_FILE=$<TARGET_FILE:${_TEST}>
                                      -D TARGET_DIR=$<TARGET_FILE_DIR:${_TEST}>
                                      -D "SEARCH_PATHS=${dll_search_dirs}"
                                      -P "${CMAKE_CURRENT_SOURCE_DIR}/cmake/copy_reqs.cmake"
                              COMMENT "Copying DLLs for ${_TEST}")
        endif()
        # Avoid executing any run targets before the DLL copying
        add_dependencies(run-copy-dlls "${_TEST}-copy-dlls")
        add_dependencies("${GEN_RUN_TARGET_NAME}" run-copy-dlls)
    endif()

    if (GEN_RUN_TARGET_VAR)
        set("${GEN_RUN_TARGET_VAR}" "${GEN_RUN_TARGET_NAME}" PARENT_SCOPE)
    endif()
endfunction()

# run targets generation
foreach(test IN LISTS run_tests)
    set(cmds "${test}")

    # test-specific options
    foreach(opt_name IN LISTS run_opts)
        set(opt "${${opt_name}}")
        list(GET opt 0 test_name)
        list(GET opt 1 test_opt)
        list(REMOVE_AT opt 0 1)

        if(test IN_LIST test_name)
            set(new_cmds)
            foreach(cmd IN LISTS cmds)
                foreach(val IN LISTS opt)
                    list(APPEND new_cmds "${cmd} ${test_opt} ${val}")
                endforeach()
            endforeach()
            set(cmds ${new_cmds})
        endif()
    endforeach()

    # terse
    set(new_cmds)
    foreach(cmd IN LISTS cmds)
        foreach(val IN LISTS run_terse)
            list(APPEND new_cmds "${cmd} ${val}")
        endforeach()
    endforeach()
    set(cmds ${new_cmds})

    # certdir
    if(test IN_LIST run_certdir_tests)
        set(new_cmds)
        foreach(cmd IN LISTS cmds)
            list(APPEND new_cmds "${cmd} ${run_certdir}")
        endforeach()
        set(cmds ${new_cmds})
    endif()

    # threads
    set(new_cmds)
    foreach(cmd IN LISTS cmds)
        foreach(val IN LISTS run_threads)
            list(APPEND new_cmds "${cmd} ${val}")
        endforeach()
    endforeach()
    set(cmds ${new_cmds})

    # Run targets
    foreach(cmd IN LISTS cmds)
        gen_run_taget("${cmd}" "${test}" VAR run_target_name)
        add_dependencies(run "${run_target_name}")
    endforeach()

    # Per-test version target
    gen_run_taget("${test} -V" "${test}" NAME "run-version-${test}")
    add_dependencies(run-version "run-version-${test}")
endforeach()
