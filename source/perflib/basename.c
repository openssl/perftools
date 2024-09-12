/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>

#include <openssl/crypto.h>

/*
 * windows variant of basename(3). works on ASCIIZ only.
 * simple and perhaps naive implementation too.
 */
const char *basename(const char *path)
{
	const char *rv, *tmp;
	const char *dirnamesep;
	size_t dirseplen;

	dirnamesep = OPENSSL_info(OPENSSL_INFO_DIR_FILENAME_SEPARATOR);
	if (dirnamesep == NULL)
		return (NULL);

	dirseplen = strlen(dirnamesep);
	if (dirseplen == 1) {

		rv = (const char *)strrchr(path, *dirnamesep);
		if (rv != NULL) {
			rv++;
			if (*rv == '\0')
				rv = path;
		}
	} else {
		rv = path;
		while ((tmp = strstr(rv, dirnamesep)) != NULL) {
			tmp += dirseplen;
			rv = tmp;
		}
		if (*rv == '\0')
			rv = path;
	}

	return (rv);
}
