/*
 * include/cloudauth/cloudauth_sigv4.h
 * Cloud storage authentication: Signature Version 4 (sigv4), functions.
 *
 * Copyright 2026 Aleksandar Lazic <al-haproxy@none.at>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#ifndef _CLOUDAUTH_SIGV4_H
#define _CLOUDAUTH_SIGV4_H

#include <import/ist.h>

#include <cloudauth/cloudauth-t.h>
#include <cloudauth/cloudauth_sigv4-t.h>

struct htx;
struct stream;

int cloudauth_sigv4_check_token(const struct ist token, const struct cloudauth_sigv4 *v4, char **err);
int cloudauth_sigv4_sign(const struct cloudauth_profile *prof, const struct stream *strm, struct htx *htx,
                         const struct cloudauth_sigv4 *v4, const char **reason);

#endif /* _CLOUDAUTH_SIGV4_H */
