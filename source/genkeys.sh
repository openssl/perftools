#!/bin/sh

#
# Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html
#

#
# Script generates RSA, X25519, DSA, DH, DHX and EC private keys.
# Keys are saved in PEM and DER formats. Script also converts
# the keys to C-friendly definitions. Each key is saved to ASCIIZ
# format. For example RSA key in PEM format is saved as
# PEM_RSA macro which defines ASCIIZ string. DER_RSA macro
# is created for DER representation of RSA key.
#
# Script also constructs convenient arrays:
#	const char sample_keys[][2];
#	const char sample_key_sizes[][2];
# We also get constants to navigate in those arrays.
# Constants for selecting keys are as follows:
#	SAMPLE_RSA
#	SAMPLE_DH
#	...
#	SAMPLE_ALL
#	SAMPLE_INVALID
# Constants to select PEM/DER format are as follows:
#	FORMAT_PEM
#	FORMAT_DER
#	FORMAT_ALL
#	FORMAT_INVALID
#
# There are also arrays sample_names, format_names and evp_pkey_tab so one
# can easily resolve name to number/id and EVP_PKEY_* constant. When adding
# a new key, choose -out option in 'openssl genpkey  wisely. The script
# uses filename to derive EVP_PKEYs_ constant. The constant is derived
# using those commands:
#	NAME=`basename $FILE`;
#	NAME=``echo $NAME|tr '[:lower:]' '[:upper:]'`
#	EVP_PKEY=`echo "EVP_PKEY_$NAME," ;
# So for RSA key the filename is rsa.pem. The commands above then will
# produce output EVP_PKEYs_RSA.
#

#
# generate private RSA and X25519 keys. They can not
# be generated using -paramfile
#
# The keys are stored in {rsa,xkey}.{pem,der} files
#
for i in PEM DER ; do
	SUFFIX=`echo $i|tr '[:upper:]' '[:lower:]'`
	openssl genpkey -algorithm X25519 -out x25519.$SUFFIX -outform $i
done

#
# This is fun part with some historical legacy which dates
# back to 1.1.1. Some details can be found here:
#	https://github.com/openssl/openssl/issues/16479
#
# to put story short, trying to do something like this:
#	openssl genpkey -algorithm RSA -out rsa.der -outform DER
# is kind of futile for us because d2i_PKCS8_PRIV_KEY_INFO_bio(3)
# then fails to read the key. Some details can be found
# at ticket. ASN.1 is fun.
#
# I've figured possible workaround. We use openssl-pkcs8
# command to convert PEM to DER. All the magic happens
# thanks to -topk8 option.
#
openssl genpkey -algorithm RSA -out rsa.pem -outform PEM
openssl pkcs8 -in rsa.pem -inform PEM -nocrypt -out rsa.der -topk8 -outform DER

#
# generate paramfiles for DSA, DH, DHX and EC keys.
#
openssl genpkey -genparam -algorithm DSA -out dsa-param.pem \
	 -pkeyopt pbits:2048 -pkeyopt qbits:224

openssl genpkey -genparam -algorithm DH -out dh-param.pem \
	-pkeyopt group:ffdhe4096

openssl genpkey -genparam -algorithm DHX -out dhx-param.pem \
	-pkeyopt dh_rfc5114:2

openssl genpkey -genparam -algorithm EC -out ec-param.pem \
	-pkeyopt ec_paramgen_curve:P-384 -pkeyopt ec_param_enc:named_curve

#
# generate PEM and DER variants for DSA, DH, DHX and EC keys
# keys are stored in files keyname.{pem,der}
#
for i in PEM DER ; do
	SUFFIX=`echo $i|tr '[:upper:]' '[:lower:]'`

	for j in dsa dh dhx ec ; do
		openssl genpkey -paramfile $j-param.pem \
			-out $j.$SUFFIX -outform $i;
	done
done

#
# DSA and EC keys seem to suffer from the same glitch as RSA.
# Let's ask openssl-pkcs8 to do its magic.
#
rm -f dsa.der
openssl pkcs8 -in dsa.pem -inform PEM -nocrypt -out dsa.der -topk8 -outform DER
rm -f ec.der
openssl pkcs8 -in ec.pem -inform PEM -nocrypt -out ec.der -topk8 -outform DER

rm *-param.pem

cat <<EOF
/*
 * Copyright `date +%Y` The OpenSSL Project Authors. All Rights Reserved.
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * !!!    D O   N O T   E D I T    !!!
 * This file is generated by genkeys.sh script.
 */

EOF

#
# create pem_samples. Define them as C macros.
# The macros will be defined as:
#	#define PEM_keyname	\
#		"line 1" \
#		"line 2" \
#		...
#		"lome m"
#
for i in *.pem ; do
	KEY_NAME=`basename $i .pem | tr '[:lower:]' '[:upper:]'`
	echo -n "#define PEM_${KEY_NAME}	"
	while read -r line ; do
		echo "\\\\"
		echo -n "    \"$line\\\\n\""
	done < $i;
	echo "\n"
done

#
# to write der format in C-friendly form we need sed to
# post process output of od(1). On non-gnu OSes there are
# usually two sed variants available. We need to pick up
# the gnu variant (gsed). gsed should be default one on Liuxes
#
which gsed > /dev/null
if [ $? -eq 0 ] ; then
	SED=gsed
else
	SED=sed
fi

#
# der samples are defined as C-macros too. They look like this:
#	#define	DER_keyname	\
#		"\x41\x42\x43.... \n"	\
#		"\x41\x42\x43.... \n"
#
for i in *.der ; do
	KEY_NAME=`basename $i .der | tr '[:lower:]' '[:upper:]'`
	echo -n "#define DER_${KEY_NAME}	"
	od -t xC $i | while read -r line ; do
		echo "\\\\"
		LINE=`echo $line | ${SED} -e 's/\([0-9]\+\)\(.*$\)/\2/g'| \
			${SED} -e 's/ *\([a-f0-9][a-f0-f9]\) */\\\\x\1/g' \
			-e 's/$/"/'`
		echo -n "    \"$LINE"
	done
	echo "\n"
done

#
# Generate array with sample keys. The definition of array
# looks as follows:
# {
#	{
#       	PEM_DH, DER_DH,
#	},
#	{
#		PEM_DHX, DER_DHX,
#	},
#		..
#	{
#		NULL, NULL
#	},
# }
echo 'static const char *sample_keys[][2] = {'
for i in *.der ; do
	echo '    {'
	echo -n '        '
	for j in PEM DER ; do
		KEY_NAME=`basename $i .der | tr '[:lower:]' '[:upper:]'`
		echo -n " ${j}_${KEY_NAME},"
	done
	echo '\n    }',
done
echo '    {'
echo '        NULL,  NULL'
echo '    }'
echo '};\n'

#
# Generate array which holds sizes of sample keys.
# the array definition looks as follows:
# {
#	{
#       	{ sizeof(DH_PEM) - 1 }, { sizeof(DH_DER) - 1 },
#	},
#	{
#		{ sizeof(DHX_PEM) - 1 }, { sizeof(DHX_DER) - 1 },
#	},
#		...
# }
#
echo 'static const size_t sample_key_sizes[][2] = {'
for i in *.der ; do
	echo -n '    { '
	for j in PEM DER ; do
		KEY_NAME=`basename $i .der | tr '[:lower:]' '[:upper:]'`
		echo -n "\tsizeof(${j}_${KEY_NAME}) - 1,"
	done
	echo ' },'
done
echo '};\n'

#
# genearate SAMPLE_XXX constants
#
echo 'enum {'
for i in *.der ; do
	NAME=`basename $i .der`;
	NAME=`echo $NAME|tr '[:lower:]' '[:upper:]'`
	echo "    SAMPLE_$NAME,"
done
echo '    SAMPLE_ALL,'
echo '    SAMPLE_INVALID'
echo '};\n'

#
# generate array of key sample names.
#
echo 'static const char *sample_names[] = {'
for i in *.der ; do
	NAME=`basename $i .der`;
	echo "    \"$NAME\","
done
	echo "    \"all\","
echo '    NULL'
echo '};'

#
# generate array of EVP_PKEYs to conveniently
# convert sample id to EVP_PKEY
#
echo 'static const int evp_pkey_tab[] = {'
for i in *.der ; do
	NAME=`basename $i .der`;
	NAME=`echo $NAME|tr '[:lower:]' '[:upper:]'`
	echo "    EVP_PKEY_$NAME," ;
done
echo '};'

#
#
# generate constants for key formats.
#
echo 'enum {'
for i in PEM DER ALL INVALID; do echo "    FORMAT_${i},"
done
echo '};\n'

#
# generate array with format names
#
echo 'static const char *format_names[] = {'
for i in pem der all ; do
	echo "    \"$i\","
done
echo "    NULL"
echo '};\n'

rm -f *.pem *.der
