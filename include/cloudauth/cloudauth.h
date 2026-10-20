/*
 * include/cloudauth/cloudauth.h
 * Cloud storage authentication: functions and variables.
 *
 * Copyright 2026 Aleksandar Lazic <al-haproxy@none.at>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#ifndef _CLOUDAUTH_H
#define _CLOUDAUTH_H

#include <haproxy/cfgparse.h>
#include <haproxy/istbuf.h>

#include <cloudauth/cloudauth-t.h>

/* Section type of the keywords of the "cloudauth" section. These keywords are
 * kept in a list of their own (see cloudauth_register_keywords()), so they do
 * not need a section type of HAProxy.
 */
#define CLOUDAUTH_CFG_SECTION  CFG_NONE

struct htx;
struct proxy;
struct stream;

extern struct list cloudauth_profiles;

void cloudauth_register_keywords(struct cfg_kw_list *kwl);

struct cloudauth_profile *cloudauth_find_profile(const char *name);
const char *cloudauth_signer_str(enum cloudauth_signer signer);
const char *cloudauth_cred_state_str(enum cloudauth_cred_state state);
const char *cloudauth_src_str(enum cloudauth_src src);
int cloudauth_set_token(struct cloudauth_profile *prof, struct ist token, unsigned int expire, char **err);
int cloudauth_find_input(const struct cloudauth_profile *prof, const char *name);
int cloudauth_set_input(struct cloudauth_profile *prof, int idx, const struct ist value, char **err);
enum cloudauth_cred_state cloudauth_cred_state(struct cloudauth_profile *prof);
void cloudauth_get_status(struct cloudauth_profile *prof, struct cloudauth_status *st);
struct cloudauth_profile *cloudauth_flt_profile(struct proxy *px);

void cloudauth_count_request(struct proxy *px, int failed);

void cloudauth_register_provider(struct cloudauth_provider *prov);
struct cloudauth_profile *cloudauth_cfg_profile(void);
int cloudauth_register_secret_env(const char *name);
int cloudauth_cfg_read_secret(const char *arg, struct ist *out, char **err);
void cloudauth_free_secret(struct ist *secret);

int cloudauth_fetch_add_hdr(struct cloudauth_fetch_req *req, const struct ist name, const struct ist value);
void cloudauth_fetch_release(struct cloudauth_profile *prof);
void cloudauth_fetch_now(struct cloudauth_profile *prof, int force);

int cloudauth_sign_bearer(const struct cloudauth_profile *prof, struct htx *htx);
int cloudauth_sign_request(struct cloudauth_profile *prof, const struct stream *strm, struct htx *htx,
                           const char **reason);
int cloudauth_authenticate(struct cloudauth_profile *prof, struct ist host, struct stream *strm,
                           struct htx *htx, const char **reason);

#endif /* _CLOUDAUTH_H */
