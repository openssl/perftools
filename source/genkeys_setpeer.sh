#!/bin/sh

#
# Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html
#

# Script is similar to genkeys.sh but generates keys specific for evp_setpeer
# perf test. Also, we only need to generate PEM files.
# ./genkeys_setpeer.sh > keys_setpeer.h

set -Eeuo pipefail

openssl genpkey -algorithm DH -out dh.pem \
	-pkeyopt group:ffdhe2048

openssl genpkey -algorithm EC -out ec256.pem \
	-pkeyopt ec_paramgen_curve:P-256

openssl genpkey -algorithm EC -out ec521.pem \
	-pkeyopt ec_paramgen_curve:P-521

openssl genpkey -algorithm X25519 -out x25519.pem


cat <<EOF
/*
 * Copyright `date +%Y` The OpenSSL Project Authors. All Rights Reserved.
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * !!!    D O   N O T   E D I T    !!!
 * This file is generated by genkeys-setpeer.sh script.
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
		echo "\\"
		echo -n "    \"$line\\n\""
	done < $i;
	echo ""
	echo ""
done

#
# Generate array with sample keys.
echo 'static const char *sample_keys[] = {'
for i in *.pem ; do
	KEY_NAME=`basename $i .pem | tr '[:lower:]' '[:upper:]'`
	echo "    PEM_${KEY_NAME},"
done
echo "    NULL"
echo '};'
echo ''

#
# Generate array which holds sizes of sample keys.
echo 'static const size_t sample_key_sizes[] = {'
for i in *.pem ; do
	KEY_NAME=`basename $i .pem | tr '[:lower:]' '[:upper:]'`
	echo "    sizeof(PEM_${KEY_NAME}) - 1,"
done
echo '};'
echo ''

#
# genearate SAMPLE_XXX constants
#
echo 'enum {'
for i in *.pem ; do
	NAME=`basename $i .pem`;
	NAME=`echo $NAME|tr '[:lower:]' '[:upper:]'`
	echo "    SAMPLE_$NAME,"
done
echo '    SAMPLE_ALL,'
echo '    SAMPLE_INVALID'
echo '};'
echo ''

#
# generate array of key sample names.
#
echo 'static const char *sample_names[] = {'
for i in *.pem ; do
	NAME=`basename $i .pem`;
	echo "    \"$NAME\","
done
	echo "    \"all\","
echo '    NULL'
echo '};'

rm -f *.pem
