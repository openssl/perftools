/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifdef	_WIN32

#include <ctype.h>

#include "strcasecmp.h"

int strcasecmp(const char *s1, const char *s2)
{
	if (s1 == NULL && s2 == NULL)
		return (0);
	if (s1 != NULL && s2 == NULL)
		return (1);
	if (s1 == NULL && s2 != NULL)
		return (-1);

	while ((*s1) && (tolower(*s1) == tolower(*s2))) {
		s1++;
		s2++;
	}

	return ((*s1 == *s2) ? 0 : (*s1 > *s2) ? 1 : -1);
}

#endif	/* _WIN32 */
