/*
 * include/cloudauth/cloudauth_trace.h
 * Cloud storage authentication: traces.
 *
 * Copyright 2026 Aleksandar Lazic <al-haproxy@none.at>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#ifndef _CLOUDAUTH_TRACE_H
#define _CLOUDAUTH_TRACE_H

#include <haproxy/trace-t.h>

extern struct trace_source trace_cloudauth;

/* The events of the "cloudauth" trace source. The arguments of the traces
 * are, in this order: the stream or NULL, the profile or NULL, a detail as a
 * pointer to a struct ist or NULL, and a pointer to an HTTP status or NULL.
 * The credentials are secrets, so they must never be passed, nor any header,
 * query string, payload or buffer which may contain one.
 */
#define CLOUDAUTH_EV_REQ    (1ULL <<  0)  /* request authentication */
#define CLOUDAUTH_EV_STRIP  (1ULL <<  1)  /* client credential removed from a request */
#define CLOUDAUTH_EV_CRED   (1ULL <<  2)  /* credential updated or expired */
#define CLOUDAUTH_EV_FETCH  (1ULL <<  3)  /* credential fetched from a token source */

#define TRACE_SOURCE &trace_cloudauth

#endif /* _CLOUDAUTH_TRACE_H */
