/*
 * include/haproxy/cloudauth_sigv4-t.h
 * Cloud storage authentication: Signature Version 4 (sigv4), type
 * definitions.
 *
 * Copyright 2026 Aleksandar Lazic <al-haproxy@none.at>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#ifndef _HAPROXY_CLOUDAUTH_SIGV4_T_H
#define _HAPROXY_CLOUDAUTH_SIGV4_T_H

#include <import/ist.h>

/* Maximum number of query string parameters of a request signed with sigv4,
 * which are sorted in a fixed array.
 */
#define CLOUDAUTH_SIGV4_MAX_PARAMS 64

/* Size of a sigv4 date ("YYYYMMDD'T'HHMMSS'Z'", ISO 8601 basic format), with
 * the trailing zero.
 */
#define CLOUDAUTH_SIGV4_DATE_SIZE 17

/* The variant of Signature Version 4 used by a provider: Amazon S3 and the
 * storages compatible with it use the "AWS4" one, with the "x-amz-" headers,
 * and Google Cloud Storage its own "GOOG4" one, with the "x-goog-" headers.
 * The names of the headers must be in lower case, and sort in this order
 * after "host": <hash_hdr>, <date_hdr>, then <token_hdr>, as in the signed
 * headers.
 */
struct cloudauth_sigv4 {
	const char *algorithm;          /* "AWS4-HMAC-SHA256", "GOOG4-HMAC-SHA256" */
	const char *key_prefix;         /* prefix of the secret deriving the signing key: "AWS4", "GOOG4" */
	struct ist hash_hdr;            /* header carrying the hash of the payload: "x-amz-content-sha256"... */
	struct ist date_hdr;            /* header carrying the date: "x-amz-date"... */
	struct ist token_hdr;           /* header carrying the session token: "x-amz-security-token", IST_NULL if none */
	const char *service;            /* service of the credential scope: "s3", "storage" */
	const char *request;            /* request type of the credential scope: "aws4_request", "goog4_request" */
	const char *region;             /* region used without "region", or NULL if it is mandatory */
};

#endif /* _HAPROXY_CLOUDAUTH_SIGV4_T_H */
