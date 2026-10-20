/*
 * Cloud storage authentication: sample fetches reporting the state of the
 * credential profiles, for the logs, the rules and the metrics.
 *
 * Copyright 2026 Aleksandar Lazic <al-haproxy@none.at>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <haproxy/api.h>
#include <haproxy/arg.h>
#include <haproxy/clock.h>
#include <haproxy/sample.h>
#include <haproxy/stream.h>

#include <cloudauth/cloudauth.h>

/* Returns the profile designated by the optional argument <args> of a sample
 * fetch, or by default the one of the cloudauth filter of the backend of the
 * stream of <smp>. Returns NULL if there is no such profile.
 */
static struct cloudauth_profile *smp_cloudauth_profile(const struct arg *args, const struct sample *smp)
{
	if (args && args[0].type == ARGT_STR)
		return cloudauth_find_profile(args[0].data.str.area);
	if (!smp->strm)
		return NULL;
	return cloudauth_flt_profile(smp->strm->be);
}

/* Fetches the name of the profile of the cloudauth filter of the backend */
static int smp_fetch_cloudauth_profile(const struct arg *args, struct sample *smp, const char *kw,
                                       void *private)
{
	struct cloudauth_profile *prof = smp_cloudauth_profile(NULL, smp);

	if (!prof)
		return 0;
	smp->data.type = SMP_T_STR;
	smp->flags = SMP_F_CONST;
	smp->data.u.str.area = prof->name;
	smp->data.u.str.data = strlen(prof->name);
	return 1;
}

/* Fetches the state of the credential of a profile: "missing", "valid" or
 * "expired".
 */
static int smp_fetch_cloudauth_cred_state(const struct arg *args, struct sample *smp, const char *kw,
                                          void *private)
{
	struct cloudauth_profile *prof = smp_cloudauth_profile(args, smp);
	struct cloudauth_status st;
	const char *state;

	if (!prof)
		return 0;
	cloudauth_get_status(prof, &st);
	state = cloudauth_cred_state_str(st.state);
	smp->data.type = SMP_T_STR;
	smp->flags = SMP_F_CONST | SMP_F_VOL_TEST;
	smp->data.u.str.area = (char *)state;
	smp->data.u.str.data = strlen(state);
	return 1;
}

/* Fetches the remaining validity of the credential of a profile, in seconds, 0
 * once expired. There is no sample if the credential is missing or does not
 * expire.
 */
static int smp_fetch_cloudauth_cred_ttl(const struct arg *args, struct sample *smp, const char *kw,
                                        void *private)
{
	struct cloudauth_profile *prof = smp_cloudauth_profile(args, smp);
	struct cloudauth_status st;

	if (!prof)
		return 0;
	cloudauth_get_status(prof, &st);
	if (!st.expire)
		return 0;
	smp->data.type = SMP_T_SINT;
	smp->flags = SMP_F_VOL_TEST;
	smp->data.u.sint = (st.expire > date.tv_sec) ? st.expire - date.tv_sec : 0;
	return 1;
}

/* Fetches whether the last fetch of the credential of a profile failed. It is
 * always false for the credentials which are not fetched by HAProxy.
 */
static int smp_fetch_cloudauth_fetch_failed(const struct arg *args, struct sample *smp, const char *kw,
                                            void *private)
{
	struct cloudauth_profile *prof = smp_cloudauth_profile(args, smp);
	struct cloudauth_status st;

	if (!prof)
		return 0;
	cloudauth_get_status(prof, &st);
	smp->data.type = SMP_T_BOOL;
	smp->flags = SMP_F_VOL_TEST;
	smp->data.u.sint = st.fetch_failed;
	return 1;
}

static struct sample_fetch_kw_list smp_kws = {ILH, {
	{ "cloudauth.profile",      smp_fetch_cloudauth_profile,      0,            NULL, SMP_T_STR,  SMP_USE_INTRN },
	{ "cloudauth.cred_state",   smp_fetch_cloudauth_cred_state,   ARG1(0,STR),  NULL, SMP_T_STR,  SMP_USE_INTRN },
	{ "cloudauth.cred_ttl",     smp_fetch_cloudauth_cred_ttl,     ARG1(0,STR),  NULL, SMP_T_SINT, SMP_USE_INTRN },
	{ "cloudauth.fetch_failed", smp_fetch_cloudauth_fetch_failed, ARG1(0,STR),  NULL, SMP_T_BOOL, SMP_USE_INTRN },
	{ /* END */ },
}};

INITCALL1(STG_REGISTER, sample_register_fetches, &smp_kws);

