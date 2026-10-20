/*
 * include/cloudauth/cloudauth_common.h
 * Cloud storage authentication: helpers shared by the providers.
 *
 * Copyright 2026 Aleksandar Lazic <al-haproxy@none.at>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#ifndef _CLOUDAUTH_COMMON_H
#define _CLOUDAUTH_COMMON_H

#include <sys/types.h>
#include <time.h>

#include <import/ist.h>

#include <haproxy/api-t.h>
#include <haproxy/buf-t.h>
#include <haproxy/jwt-t.h>
#include <haproxy/openssl-compat.h>

struct htx;

/* Size of the buffer receiving <n> bytes encoded in base64 by a2base64():
 * 4 characters per started group of 3 bytes, plus the trailing zero.
 */
#define CLOUDAUTH_B64_SIZE(n) (((n) + 2) / 3 * 4 + 1)

/* Size of the buffer receiving an HTTP date such as
 * "Sun, 06 Nov 1994 08:49:37 GMT", with the trailing zero.
 */
#define CLOUDAUTH_HTTP_DATE_SIZE 30

/* Size of the buffer receiving an ISO 8601 UTC date such as
 * "1994-11-06T08:49:37Z", with the trailing zero.
 */
#define CLOUDAUTH_ISO_DATE_SIZE 21

/* Maximum number of headers covered by a signature, collected by
 * cloudauth_collect_hdrs() in a fixed array.
 */
#define CLOUDAUTH_MAX_SIGNED_HDRS 64

/* A header of a request covered by a signature */
struct cloudauth_hdr {
	struct ist name;
	struct ist value;
};

/* A query string parameter, URL-decoded */
struct cloudauth_qparam {
	struct ist name;
	struct ist value;
};

ssize_t cloudauth_ist_check(const struct ist s, int (*valid)(int));
int cloudauth_http_date(time_t t, char *buf, size_t size);
int cloudauth_iso_date(time_t t, char *buf, size_t size);
int cloudauth_parse_iso_date(struct ist in, unsigned int *date);

struct ist cloudauth_req_path(const struct htx *htx);
int cloudauth_append_query(struct htx *htx, const struct ist params);

int cloudauth_url_decode(struct buffer *work, const struct ist in, struct ist *out);
int cloudauth_qparam_decode(struct buffer *work, const struct ist param, struct cloudauth_qparam *out);
int cloudauth_qparam_cmp(const void *a, const void *b);

int cloudauth_collect_hdrs(struct htx *htx, const struct ist name, const struct ist pfx,
                           struct cloudauth_hdr *hdrs, int max);
int cloudauth_canon_hdrs_cat(struct buffer *out, const struct cloudauth_hdr *hdrs, int nb);

int cloudauth_url_encode_cat(struct buffer *out, const struct ist in);
int cloudauth_form_add(struct buffer *body, const char *name, const struct ist value);

int cloudauth_json_uint(const char *json, int len, const char *path, ullong *out);
int cloudauth_oauth_token(const struct buffer *body, struct buffer *token, unsigned int *expire, char **err);
void cloudauth_oauth_error(int status, const struct buffer *body, char **err);

int cloudauth_is_http_url(const char *url);
int cloudauth_cfg_str(char **args, char **field, int env, int (*valid)(const char *str),
                      const char *what, const char *expects, char **err);

int cloudauth_pem_password(char *buf, int size, int rwflag, void *u);
EVP_PKEY *cloudauth_pem_private_key(const struct ist pem, struct ist password);
int cloudauth_jwt_sign(struct buffer *out, const struct ist header, const struct ist claims,
                       EVP_PKEY *key, enum jwt_alg alg, char **err);

#endif /* _CLOUDAUTH_COMMON_H */
