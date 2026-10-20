/*
 * include/haproxy/cloudauth_s3.h
 * Cloud storage authentication: Amazon S3 and compatible storages provider,
 * functions and variables.
 *
 * Copyright 2026 Aleksandar Lazic <al-haproxy@none.at>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#ifndef _HAPROXY_CLOUDAUTH_S3_H
#define _HAPROXY_CLOUDAUTH_S3_H

#include <haproxy/cloudauth-t.h>
#include <haproxy/cloudauth_s3-t.h>

extern struct cloudauth_provider cloudauth_s3_provider;

#endif /* _HAPROXY_CLOUDAUTH_S3_H */
