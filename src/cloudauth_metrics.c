/*
 * Cloud storage authentication: sample fetches reporting the state of the
 * credential profiles, for the logs, the rules and the metrics, and the
 * metrics of the profiles in the Prometheus exporter.
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
#include <haproxy/stats.h>
#include <haproxy/stream.h>

#if defined(USE_PROMEX)
#include <promex/promex.h>
#endif

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


#if defined(USE_PROMEX)

/* The metrics of the profiles in the Prometheus exporter, which are reported
 * at every scrape, even when no request uses the profiles. Each time series
 * is labelled with the name of its profile.
 */
enum {
	CLOUDAUTH_PROMEX_CRED_VALID = 0,
	CLOUDAUTH_PROMEX_CRED_EXPIRES_IN,
	CLOUDAUTH_PROMEX_FETCH_FAILED,
	CLOUDAUTH_PROMEX_METRICS
};

static int cloudauth_promex_metric_info(unsigned int id, struct promex_metric *metric, struct ist *desc)
{
	switch (id) {
	case CLOUDAUTH_PROMEX_CRED_VALID:
		*metric = (struct promex_metric){ .n = ist("credential_valid"), .type = PROMEX_MT_GAUGE,
		                                  .flags = PROMEX_FL_MODULE_METRIC };
		*desc = ist("1 if the credential of the cloudauth profile is valid, otherwise 0.");
		break;
	case CLOUDAUTH_PROMEX_CRED_EXPIRES_IN:
		*metric = (struct promex_metric){ .n = ist("credential_expires_in_seconds"), .type = PROMEX_MT_GAUGE,
		                                  .flags = PROMEX_FL_MODULE_METRIC };
		*desc = ist("Remaining validity of the credential of the cloudauth profile, only reported for the credentials which expire.");
		break;
	case CLOUDAUTH_PROMEX_FETCH_FAILED:
		*metric = (struct promex_metric){ .n = ist("credential_fetch_failed"), .type = PROMEX_MT_GAUGE,
		                                  .flags = PROMEX_FL_MODULE_METRIC };
		*desc = ist("1 if the last fetch of the credential of the cloudauth profile failed, otherwise 0.");
		break;
	default:
		return -1;
	}
	return 1;
}

/* Returns the first profile from the list element <elt> included which has a
 * time series for the metric <id>, or NULL if there is none. Only the
 * credentials which expire have a remaining validity. The time series are
 * selected here rather than skipped by cloudauth_promex_fill_ts(), since the
 * exporter does not move to the next one when a time series is skipped.
 */
static struct cloudauth_profile *cloudauth_promex_ts(struct list *elt, unsigned int id)
{
	struct cloudauth_profile *prof;
	struct cloudauth_status st;

	for (; elt != &cloudauth_profiles; elt = elt->n) {
		prof = LIST_ELEM(elt, struct cloudauth_profile *, list);
		if (id != CLOUDAUTH_PROMEX_CRED_EXPIRES_IN)
			return prof;
		cloudauth_get_status(prof, &st);
		if (st.expire)
			return prof;
	}
	return NULL;
}

/* The time series of a metric are the profiles, in their order of declaration */
static void *cloudauth_promex_start_ts(void *unused, unsigned int id)
{
	return cloudauth_promex_ts(cloudauth_profiles.n, id);
}

static void *cloudauth_promex_next_ts(void *unused, void *metric_ctx, unsigned int id)
{
	struct cloudauth_profile *prof = metric_ctx;

	return cloudauth_promex_ts(prof->list.n, id);
}

static int cloudauth_promex_fill_ts(void *unused, void *metric_ctx, unsigned int id,
                                    struct promex_label *labels, struct field *field)
{
	struct cloudauth_profile *prof = metric_ctx;
	struct cloudauth_status st;

	labels[0].name  = ist("profile");
	labels[0].value = ist(prof->name);

	cloudauth_get_status(prof, &st);
	switch (id) {
	case CLOUDAUTH_PROMEX_CRED_VALID:
		*field = mkf_u32(FN_GAUGE, st.state == CLOUDAUTH_CRED_VALID);
		break;
	case CLOUDAUTH_PROMEX_CRED_EXPIRES_IN:
		/* 0 as well if the credential no longer expires since its time
		 * series was selected.
		 */
		*field = mkf_u32(FN_GAUGE, (st.expire > date.tv_sec) ? st.expire - date.tv_sec : 0);
		break;
	case CLOUDAUTH_PROMEX_FETCH_FAILED:
		*field = mkf_u32(FN_GAUGE, st.fetch_failed);
		break;
	default:
		return -1;
	}
	return 1;
}

static struct promex_module cloudauth_promex_module = {
	.name        = IST("cloudauth"),
	.metric_info = cloudauth_promex_metric_info,
	.start_ts    = cloudauth_promex_start_ts,
	.next_ts     = cloudauth_promex_next_ts,
	.fill_ts     = cloudauth_promex_fill_ts,
	.nb_metrics  = CLOUDAUTH_PROMEX_METRICS,
};

INITCALL1(STG_REGISTER, promex_register_module, &cloudauth_promex_module);

#endif /* USE_PROMEX */
