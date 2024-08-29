#!/usr/bin/env perl
#
# Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html
#

#
# Before running the script you must set up your system/environment.
# The script tests performance for those OpenSSL versions:
#	1.1.1
#	3.0
#	3.3
#	master (3.4-dev)
# The first step is to build and install OpenSSL libraries under prefix
# expected by script:
#	/path/to/your/OpenSSL.binaries/openssl-$desired_verion
# For example to build and install master version into prefix
# /path/to/your/OpenSSL.binaries you do in your OpenSSL source root
# something as follows:
#	./Configure --prefix=/path/to/your/OpensSSL.binaries/openssl-master
#	make
#	make install
# Steps above need to be repeated for 1.1.1 3.0 and 3.3 versions.
#
# The next step is to build testing tools. You need to build tools
# for each OpenSSL version script is testing (1.1.1, 3.0, 3.3 and master).
# We use cmake to build performance test tools. The script assumes
# tools are found under prefix /path/to/perftools/source/build-$version
# Tools also need to be build before running the script. To build tools
# to test master version you do something like this:
#	cd /path/to/perftools/source
#	export OPENSSL_ROOT_DIR=/path/to/your/OpenSSL.binaries/openssl-master
#	cmake -S . -B build-master
#	cmake -S . -B build-master	# two invocations are required,
#					# otherwise build may fail
#	cmake --build build-master
#
# Repeat steps above for each OpenSSL version we test (1.1.1, 3.0, 3.3)
# Don't forget to update OPENSSL_ROOT_DIR and -B option with correct version.
#
# When on Windows:
#	cmake seems to be unable to get OPENSSL_ROOT_DIR from env.
#	variable. It must be passed as command line argument:
#		cmake -S . -B build-... -DOPENSSL_ROOT_DIR=c:\...
#
#	when doing build you want to make a release build:
#		cmake --build build-... --config Release
#	otherwise you'll get Debug build which is a default.
#	run-perf.pl expects Release bits.
#
# Script uses File::Tempdir module, you need to install it. On linux/unix
# use package provided by your system vendor. On windows use cpanm:
# 	cpanm install File::Tempdir
# (assuming you got path set PATH=%PATH;c:\Strawberry\perl\bin)
#
# Almost ready to run the script. The last step is to set up env. variables
# so script can find tools and libraries:
#	export TOOLS_PATH=/path/to/perftools/sources;
#	export OPENSSL_SRC=/path/to/openssl.src
#	export OPENSSL_BINARIES=/path/to/openssl.binaries
#		#required on windows only
#
use strict;
use warnings;
use File::Tempdir;
use IO::Pipe;
use File::Spec

my $TOOLS_PATH;
my $CERT_DIR;
my $OPENSSL_BINARIES;
my $OPENSSL_SRC;
my $TMPDIR;
my $RESULTS;
my @PERF_TESTS = (
	'evp_fetch',
	'randbytes',
	'handshake',
	'sslnew',
	'newrawkey',
	'rsasign',
	'x509storeissuer',
	'providerdoall',
	'rwlocks_rlock',
	'rwlocks_wlock',
	'pkeyread_dh_der',
	'pkeyread_dhx_der',
	'pkeyread_dsa_der',
	'pkeyread_ec_der',
	'pkeyread_rsa_der',
	'pkeyread_x25519_der',
	'pkeyread_dh_pem',
	'pkeyread_dhx_pem',
	'pkeyread_dsa_pem',
	'pkeyread_ec_pem',
	'pkeyread_rsa_pem',
	'pkeyread_x25519_pem',
	'evp_setpeer_dh',
	'evp_setpeer_ec256',
	'evp_setpeer_ec521',
	'evp_setpeer_x25519'
);
my @VERSIONS = ('1.1.1', '3.0', '3.3', 'master');
my @THREAD_COUNTS = (1, 2, 4, 8, 16, 32, 64, 128);
my $ITERATIONS = 25;

my sub get_tool {
	my ($tool_name, $tool_version) = @_;
	my $tool;

	$tool_version = join('-', "build", $tool_version);
	if ("$^O" eq "MSWin32") {
		$tool_name = "$tool_name.exe";
		$tool = File::Spec->catfile($Main::TOOLS_PATH, $tool_version,
		    "Release", $tool_name);
	} else {
		$tool = File::Spec->catfile($Main::TOOLS_PATH, $tool_version,
		    $tool_name);
	}

	if (! -e $tool) {
		return undef;
	} else {
		return $tool;
	}
}

my sub get_test_cmd {
	my ($test_name, $version, $thread_count, $cert_dir) = @_;
	my $test_cmd = get_tool($test_name, $version);

	if (! $test_cmd) {
		#
		# tools was not for desired test,
		# are we dealing with for example rwlocks_wlock?
		#
		my $tool_name = $test_name;

		#
		# we use underscore ('_') in test names as a delimiter
		# between test program tool and eventual parametrs
		# to test (for example rwlocks_rlock).
		#
		# evp_setpeer test tool clashes with our convention,
		# so we are dealing with special case
		#
		if ($tool_name =~ /evp_setpeer/) {
			$tool_name = "evp_setpeer";
			$test_cmd = get_tool($tool_name, $version);
		} else {
			$tool_name = ( split(/_/, $test_name) )[0];
		}

		$test_cmd = get_tool($tool_name, $version);
		if (! $test_cmd) {
			print "No tool for $tool_name ($version)\n";
			return undef;
		}

		if ("$tool_name" eq "pkeyread") {
			my $cipher;
			my $format;

			($tool_name, $cipher, $format) = split(/_/, $test_name);
			$test_cmd = get_tool($tool_name, $version);
			$test_cmd = "$test_cmd -k $cipher -f $format ";
		} elsif ("$tool_name" eq "evp_setpeer") {
			my $cipher;

			$cipher = ( split(/_/, $test_name) )[2];
			$test_cmd = get_tool($tool_name, $version);
			$test_cmd = "$test_cmd -k $cipher";
		}
	}

	#
	# add common options/arguments
	#	-t, terse output
	#	number of threads to use
	#	directory to certificates (when needed)
	#
	if ($test_name == "handshake" || $test_name == "x509storeissuer") {
		$test_cmd = "$test_cmd -t $cert_dir $thread_count";
	} else {
		$test_cmd = "$test_cmd -t $thread_count";
	}

	return $test_cmd
}

my sub do_test {
	my ($test_name, $version, $thread_count, $cert_dir) = @_;
	my $test_cmd;
	my $result;

	$test_cmd = get_test_cmd($test_name, $version, $thread_count,
	    $cert_dir);
	if (! $test_cmd) {
		return undef;
	}

	$ENV{EVP_FETCH_TYPE} = "MD:MD5";
	if ("$^O" eq "MSWin32") {
		#
		# There is no LD_LIBRARY_PATH, nor RTPATH on windows.
		# We have two options here:
		# (https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
		#	1) copy .dll files to the directory where tools
		#	reside
		#
		#	2) add path .dll to PATH env. variable
		# We opt for 2).
		#
		my $path_to_dll = File::Spec->catdir($OPENSSL_BINARIES,
		    join('-', 'openssl', $version), 'bin');
		$ENV{PATH} = "%PATH;$path_to_dll";
	}
	open(PIPE, "$test_cmd |") || return undef;
	while (<PIPE>) {
		chomp;
		$result = $_;
	}
	close PIPE;

	#
	# need to post-process output for those tests
	#
	if ("$test_name" eq "rwlocks_wlock") {
		#
		# rwlocks test returns two numbers,
		# the first is for write-lock
		#
		$result = ( split(/ /, $result) )[0];
	} elsif ("$test_name" eq "rwlocks_rlock") {
		#
		# the second number is for read lock
		#
		$result = ( split(/ /, $result) )[1];
	}

	if ($result =~ "nan") {
		#
		# running 'rwlocks -t 1' gives output similar to this:
		#	nan 0.12345
		#
		return undef;
	}

	return $result;
}


#
# on unix we use RTPATH in elf header to locate
# desired openssl library which tool is linked with
#
if ("$^O" eq "MSWin32") {
	if (!$ENV{OPENSSL_BINARIES}) {
		print "OPENSSL_BINARIES is not set\n";
		exit 1;
	}
	$OPENSSL_BINARIES = $ENV{OPENSSL_BINARIES};
	if (! -d $OPENSSL_BINARIES) {
		print "path OPENSSL_BINARIES($OPENSSL_BINARIES) ",
		    "does not exit\n";
		exit 1;
	}
	foreach(@VERSIONS) {
		my $leaf_dir = join('-', 'openssl', $_);
		my $openssl_version = File::Spec->catdir($OPENSSL_BINARIES,
		    $leaf_dir);

		if (! -d $openssl_version) {
			print "No $leaf_dir found in $OPENSSL_BINARIES\n";
			exit 1;
		}
	}
}

if (!$ENV{TOOLS_PATH}) {
	print "TOOLS_PATH is not set\n";
	exit 1;
}
$Main::TOOLS_PATH=$ENV{TOOLS_PATH};
if (! -d $Main::TOOLS_PATH) {
	print "path TOOLS_PATH($Main::TOOLS_PATH) does not exit\n";
	exit 1;
}
foreach(@VERSIONS) {
	my $leaf_dir = join('-', 'build', $_);
	my $tool_version = File::Spec->catdir($Main::TOOLS_PATH, $leaf_dir);

	if (! -d $tool_version) {
		print "No $leaf_dir found in $Main::TOOLS_PATH\n";
		exit 1;
	}
}

if (!$ENV{OPENSSL_SRC}) {
	print "OPENSSL_SRC is not set\n";
	exit 1;
}
$OPENSSL_SRC=$ENV{OPENSSL_SRC};
if (! -d $OPENSSL_SRC) {
	print "path OPENSSL_SRC($OPENSSL_SRC) does not exit\n";
	exit 1;
}
$CERT_DIR = File::Spec->catfile($OPENSSL_SRC, 'test', 'certs');
if (! -d $CERT_DIR) {
	print "$OPENSSL_SRC does not contain test/certs\n";
	exit 1;
}

if ("$ARGV[0]" eq "") {
	print "output file name argument is mandatory\n";
	exit 1;
}
open(output_fh, ">", $ARGV[0]) or die $!;

$TMPDIR = File::Tempdir->new();
$RESULTS = $TMPDIR->name;

my $version;
foreach $version (@VERSIONS) {
	my $test;
	foreach $test (@PERF_TESTS) {
		my $thread_count;
		foreach $thread_count (@THREAD_COUNTS) {
			my $i;
			my $file_name = join('.', $test, $version);
			$file_name = join('-', $file_name, $thread_count);
			$file_name = File::Spec->catfile($RESULTS, $file_name);
			#
			# LD_LIBRARY_PATH is not needed, because cmake build
			# process uses RPATH which from elf header.
			#

			open(result_fh, ">", $file_name);

			if (!get_test_cmd($test, $version, $thread_count,
			    $CERT_DIR)) {
				print result_fh "N/A | N/A |";
			} else {
				my @result_array = ();
				my @deviation_array = ();
				my $sum_deviations = 0;
				my $avg_usecs = 0;
				my $std_deviation = 0;
				print "Running: $test $thread_count ",
				    "$ITERATIONS for $version\n";
				for($i = 0; $i < $ITERATIONS; $i++) {
					my $result;
					$result = do_test($test, $version,
					    $thread_count, $CERT_DIR);
					if (! $result) {
						# 'rwlocks -t 1' returns undef
						@result_array = ();
						# break is not allowed
						# so let trip condition
						$i = $ITERATIONS + 1;
					} else {
						push(@result_array, $result);
					}
				}
				if (scalar(@result_array) == 0) {
					#
					# we got nan from rwlocks_wlock -t 1 test,
					# so put N/A N/A and break from threads loop.
					#
					printf result_fh "N/A | N/A |";
				} else {
					foreach(@result_array) {
						$avg_usecs = $avg_usecs + $_;
					}
					$avg_usecs = $avg_usecs / $ITERATIONS;

					foreach(@result_array) {
						my $deviation;
						$deviation = $avg_usecs - $_;
						$deviation =
						    $deviation * $deviation;
						push(@deviation_array,
						    $deviation);
						$sum_deviations =
						    $sum_deviations +
						    $deviation;
					}
					$std_deviation = sqrt(
					    $sum_deviations/($ITERATIONS - 1));
					printf result_fh " %.4f | %.4f |",
					    $avg_usecs, $std_deviation;
				}
			}
			close result_fh;
		}
	}
}

foreach(@PERF_TESTS) {
	my $test_name = $_;
	print output_fh "#### $test_name\n\n";
	print output_fh "|thread_ count| number of iterations |";
	foreach(@VERSIONS) {
		my $version = $_;
		print output_fh "openssl $version per operation avg usec | $version std dev |";
	}
	print output_fh "\n";
	print output_fh "|----|----";
	foreach(@VERSIONS) {
		print output_fh "|----|----";
	}
	print output_fh "|\n";

	foreach(@THREAD_COUNTS) {
		my $thread_count = $_;
		print output_fh "| $thread_count | $ITERATIONS |";
		foreach(@VERSIONS) {
			my $version = $_;
			my $file_name;
			my $result;
			$file_name = join('.', $test_name, $version);
			$file_name = join('-', $file_name, $thread_count);
			$file_name = File::Spec->catfile($RESULTS, $file_name);
			open(in_fh, "<", $file_name) or die $!;
			$result = do {
				local $/ = undef;
				open(in_fh, "<", $file_name) ;
				<in_fh>
			};
			close in_fh;
			print output_fh $result;
		}
		print output_fh "\n";
	}
	print output_fh "\n";
}

close output_fh;
