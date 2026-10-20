/*
 * Cloud storage authentication: credential profiles.
 *
 * Copyright 2026 Aleksandar Lazic <al-haproxy@none.at>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 * A credential profile is declared by a "cloudauth" section. It describes how
 * the requests sent to the servers referencing it are authenticated. It is
 * used by the cloudauth filter.
 */

#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <import/mjson.h>

#include <haproxy/api.h>
#include <haproxy/applet.h>
#include <haproxy/base64.h>
#include <haproxy/cfgparse.h>
#include <haproxy/cli.h>
#include <haproxy/clock.h>
#include <haproxy/errors.h>
#include <haproxy/filters.h>
#include <haproxy/global.h>
#include <haproxy/http_htx.h>
#include <haproxy/htx.h>
#include <haproxy/init.h>
#include <haproxy/jwt.h>
#include <haproxy/log.h>
#include <haproxy/proxy.h>
#include <haproxy/sample.h>
#include <haproxy/server.h>
#include <haproxy/stats.h>
#include <haproxy/task.h>
#include <haproxy/ticks.h>
#include <haproxy/tools.h>
#include <haproxy/trace.h>

#include <cloudauth/cloudauth.h>
#include <cloudauth/cloudauth_common.h>
#include <cloudauth/cloudauth_sigv4.h>
#include <cloudauth/cloudauth_trace.h>

/* cloudauth stats module, for the backends and the servers */
enum {
	CLOUDAUTH_ST_REQ_SIGNED = 0,
	CLOUDAUTH_ST_REQ_FAILED,
	/* the number of counters must always be placed last */
	CLOUDAUTH_ST_COUNT
};

static struct stat_col cloudauth_stats[] = {
	[CLOUDAUTH_ST_REQ_SIGNED] = { .name = "cloudauth_req_signed",
	                              .desc = "Total number of requests authenticated by cloudauth" },
	[CLOUDAUTH_ST_REQ_FAILED] = { .name = "cloudauth_req_failed",
	                              .desc = "Total number of requests which could not be authenticated by cloudauth" },
};

static struct cloudauth_counters {
	long long req_signed;
	long long req_failed;
} cloudauth_counters;

/* Fills <stats> with the counters of <ctr> for stats module <mod>, all of them
 * or only <selected_field> if not NULL. Returns 0 if the selected field does
 * not exist, otherwise 1.
 */
static int cloudauth_fill_stats(struct stats_module *mod, struct extra_counters *ctr,
                                struct field *stats, unsigned int *selected_field)
{
	unsigned int current_field = (selected_field != NULL ? *selected_field : 0);

	for (; current_field < CLOUDAUTH_ST_COUNT; current_field++) {
		struct field metric = { 0 };
		struct cloudauth_counters *counters;

		if (!ctr)
			goto store_metric;

		counters = EXTRA_COUNTERS_BASE(ctr, mod);

		switch (current_field) {
		case CLOUDAUTH_ST_REQ_SIGNED:
			metric = mkf_u64(FN_COUNTER, EXTRA_COUNTERS_AGGR(ctr, counters->req_signed));
			break;
		case CLOUDAUTH_ST_REQ_FAILED:
			metric = mkf_u64(FN_COUNTER, EXTRA_COUNTERS_AGGR(ctr, counters->req_failed));
			break;
		default:
			if (selected_field != NULL)
				return 0;
			continue;
		}
	store_metric:
		stats[current_field] = metric;
		if (selected_field != NULL)
			break;
	}
	return 1;
}

static struct stats_module cloudauth_stats_module = {
	.name          = "cloudauth",
	.fill_stats    = cloudauth_fill_stats,
	.stats         = cloudauth_stats,
	.stats_count   = CLOUDAUTH_ST_COUNT,
	.counters      = &cloudauth_counters,
	.counters_size = sizeof(cloudauth_counters),
	.domain_flags  = MK_STATS_PROXY_DOMAIN(STATS_PX_CAP_BE | STATS_PX_CAP_SRV),
	.clearable     = 1,
};

INITCALL1(STG_REGISTER, stats_register_module, &cloudauth_stats_module);

/* Counts a request sent to server <srv>, authenticated or not depending on
 * <failed>, for the server and its backend.
 */
void cloudauth_count_request(struct server *srv, int failed)
{
	struct cloudauth_counters *srv_ctr, *px_ctr;

	srv_ctr = EXTRA_COUNTERS_GET(srv->extra_counters, &cloudauth_stats_module);
	px_ctr = EXTRA_COUNTERS_GET(srv->proxy->extra_counters_be, &cloudauth_stats_module);
	if (failed) {
		_HA_ATOMIC_INC(&srv_ctr->req_failed);
		_HA_ATOMIC_INC(&px_ctr->req_failed);
	}
	else {
		_HA_ATOMIC_INC(&srv_ctr->req_signed);
		_HA_ATOMIC_INC(&px_ctr->req_signed);
	}
}

/* All the declared profiles */
struct list cloudauth_profiles = LIST_HEAD_INIT(cloudauth_profiles);

/* The profile being parsed */
static struct cloudauth_profile *cur_profile;

/* The registered storage providers. The list is only modified by the INITCALLs
 * and only browsed while the configuration is parsed, both before the threads
 * are started, so it needs no lock. The profiles point to their provider.
 */
static struct list cloudauth_providers = LIST_HEAD_INIT(cloudauth_providers);

static const char * const cloudauth_signer_names[CLOUDAUTH_SIGNER_ENTRIES] = {
	[CLOUDAUTH_SIGNER_NONE]      = "none",
	[CLOUDAUTH_SIGNER_BEARER]    = "bearer",
	[CLOUDAUTH_SIGNER_SAS]       = "sas",
	[CLOUDAUTH_SIGNER_SHAREDKEY] = "sharedkey",
	[CLOUDAUTH_SIGNER_SIGV4]     = "sigv4",
};

static const char * const cloudauth_cred_state_names[] = {
	[CLOUDAUTH_CRED_MISSING] = "missing",
	[CLOUDAUTH_CRED_VALID]   = "valid",
	[CLOUDAUTH_CRED_EXPIRED] = "expired",
};

/* Returns the name of the credential state <state> */
const char *cloudauth_cred_state_str(enum cloudauth_cred_state state)
{
	if (state > CLOUDAUTH_CRED_EXPIRED)
		return "unknown";
	return cloudauth_cred_state_names[state];
}

static const char * const cloudauth_src_names[] = {
	[CLOUDAUTH_SRC_NONE] = "none",
	[CLOUDAUTH_SRC_ENV]  = "env",
	[CLOUDAUTH_SRC_FILE] = "file",
	[CLOUDAUTH_SRC_CLI]  = "cli",
	[CLOUDAUTH_SRC_FETCH] = "fetch",
};

/* Returns the name of the credential source <src> */
const char *cloudauth_src_str(enum cloudauth_src src)
{
	if (src > CLOUDAUTH_SRC_FETCH)
		return "unknown";
	return cloudauth_src_names[src];
}

/* Returns the name of signer <signer> */
const char *cloudauth_signer_str(enum cloudauth_signer signer)
{
	if (signer >= CLOUDAUTH_SIGNER_ENTRIES)
		return "unknown";
	return cloudauth_signer_names[signer];
}

/* Registers storage provider <prov>. Called by the provider modules from an
 * INITCALL at the STG_REGISTER stage.
 */
void cloudauth_register_provider(struct cloudauth_provider *prov)
{
	const struct cloudauth_source *src;
	int i;

	BUG_ON(!prov->sign && (prov->signers & ~(1U << CLOUDAUTH_SIGNER_SIGV4)),
	       "a cloudauth provider must have a sign() callback");
	BUG_ON(!(prov->signers & (1U << CLOUDAUTH_SIGNER_SIGV4)) != !prov->sigv4,
	       "a cloudauth provider supports the sigv4 signer if and only if it has a variant of it");
	for (src = prov->sources; src && src->name; src++) {
		BUG_ON(!src->request || !src->response,
		       "a cloudauth token source must have request() and response() callbacks");
		for (i = 0; src->inputs && src->inputs[i]; i++)
			BUG_ON(i >= CLOUDAUTH_MAX_INPUTS, "a cloudauth token source has too many inputs");
	}
	LIST_APPEND(&cloudauth_providers, &prov->list);
}

/* Returns the provider named <name>, or NULL if it is not registered */
static const struct cloudauth_provider *cloudauth_find_provider(const char *name)
{
	const struct cloudauth_provider *prov;

	list_for_each_entry(prov, &cloudauth_providers, list) {
		if (strcmp(prov->name, name) == 0)
			return prov;
	}
	return NULL;
}

/* Returns the profile whose section is being parsed, or NULL outside of a
 * "cloudauth" section. It is used by the keyword parsers of the providers.
 */
struct cloudauth_profile *cloudauth_cfg_profile(void)
{
	return cur_profile;
}

/* The names of the environment variables carrying secrets, removed from the
 * environment once the configuration is parsed.
 */
struct cloudauth_secret_env {
	char *name;
	struct list list;
};

static struct list cloudauth_secret_envs = LIST_HEAD_INIT(cloudauth_secret_envs);

/* Registers the environment variable <name> as carrying a secret, so that it
 * is wiped and removed from the environment once the configuration is parsed:
 * this way, it cannot be read anymore by the "env" sample fetch, nor by Lua.
 * The master process keeps its own copy, since it does not parse the sections
 * using it, so it is still available after a reload. Returns 0 on success, -1
 * on memory allocation failure.
 */
int cloudauth_register_secret_env(const char *name)
{
	struct cloudauth_secret_env *env;

	list_for_each_entry(env, &cloudauth_secret_envs, list) {
		if (strcmp(env->name, name) == 0)
			return 0;
	}

	env = calloc(1, sizeof(*env));
	if (!env)
		return -1;
	env->name = strdup(name);
	if (!env->name) {
		free(env);
		return -1;
	}
	LIST_APPEND(&cloudauth_secret_envs, &env->list);
	return 0;
}

/* Wipes and removes the environment variables carrying secrets, then releases
 * their names.
 */
static void cloudauth_scrub_secret_envs(void)
{
	struct cloudauth_secret_env *env, *back;
	char *value;

	list_for_each_entry_safe(env, back, &cloudauth_secret_envs, list) {
		value = getenv(env->name);
		if (value) {
			ha_memset_s(value, 0, strlen(value));
			unsetenv(env->name);
		}
		LIST_DELETE(&env->list);
		ha_free(&env->name);
		free(env);
	}
}

/* Returns the profile named <name>, or NULL if it does not exist */
struct cloudauth_profile *cloudauth_find_profile(const char *name)
{
	struct cloudauth_profile *prof;

	list_for_each_entry(prof, &cloudauth_profiles, list) {
		if (strcmp(prof->name, name) == 0)
			return prof;
	}
	return NULL;
}

/* Wipes and releases the token of credential <cred> */
static void cloudauth_cred_release(struct cloudauth_cred *cred)
{
	if (isttest(cred->token)) {
		ha_memset_s(istptr(cred->token), 0, istlen(cred->token));
		istfree(&cred->token);
	}
	cred->expire = 0;
}

/* Returns the state of the credential of profile <prof>. The lock of the
 * profile must be held.
 */
static enum cloudauth_cred_state __cloudauth_cred_state(const struct cloudauth_profile *prof)
{
	if (!isttest(prof->cred.token))
		return CLOUDAUTH_CRED_MISSING;
	if (prof->cred.expire && date.tv_sec >= prof->cred.expire)
		return CLOUDAUTH_CRED_EXPIRED;
	return CLOUDAUTH_CRED_VALID;
}

/* Returns the state of the credential of profile <prof> */
enum cloudauth_cred_state cloudauth_cred_state(struct cloudauth_profile *prof)
{
	enum cloudauth_cred_state state;

	HA_RWLOCK_RDLOCK(OTHER_LOCK, &prof->lock);
	state = __cloudauth_cred_state(prof);
	HA_RWLOCK_RDUNLOCK(OTHER_LOCK, &prof->lock);
	return state;
}

/* Returns the expiration date ("exp" claim) of <token> if it is a JWT, or 0 if
 * it is not a JWT or has no valid "exp" claim. <token> must not be empty. The
 * signature is not checked: the token is only used to authenticate HAProxy,
 * the expiration date only serves to stop using it in time.
 */
static unsigned int cloudauth_jwt_exp(const struct ist token)
{
	struct jwt_item items[JWT_ELT_MAX];
	struct buffer jwt = ist2buf(token);
	struct buffer *claims;
	unsigned int ret = 0;
	ullong exp;
	int len;

	if (jwt_tokenize(&jwt, items, JWT_ELT_MAX) != 0)
		return 0;

	claims = alloc_trash_chunk();
	if (!claims)
		return 0;

	len = base64urldec(items[JWT_ELT_CLAIMS].start, items[JWT_ELT_CLAIMS].length,
	                   claims->area, claims->size);
	if (len <= 0)
		goto out;

	/* the "exp" claim is a NumericDate, a number of seconds since the Epoch
	 * which may have a fractional part, ignored here.
	 */
	if (cloudauth_json_uint(claims->area, len, "$.exp", &exp) < 0)
		goto out;

	/* the dates are stored as unsigned 32-bit wall clock seconds */
	if (exp >= 1 && exp <= UINT_MAX)
		ret = exp;

  out:
	ha_memset_s(claims->area, 0, claims->size);
	free_trash_chunk(claims);
	return ret;
}

/* Checks that <token> may be used by the signer of profile <prof>: the form of
 * the token of the "sigv4" signer for the variant of the provider, then what
 * is up to the provider. The check is skipped while the provider or the
 * signer is not known yet, or if the provider does not support the signer, in
 * which case it is performed or reported once the section is parsed. Returns 0
 * on success, otherwise -1 with <err> filled. The token is never reported.
 */
static int cloudauth_check_token(const struct cloudauth_profile *prof, const struct ist token, char **err)
{
	if (prof->signer == CLOUDAUTH_SIGNER_SIGV4 && prof->provider && prof->provider->sigv4) {
		if (cloudauth_sigv4_check_token(token, prof->provider->sigv4, err) < 0)
			return -1;
	}
	if (!prof->provider || !prof->provider->check_token || prof->signer == CLOUDAUTH_SIGNER_NONE)
		return 0;
	return prof->provider->check_token(prof, token, err);
}

/* Replaces the token of profile <prof> by <token>, expiring at <expire> (wall
 * clock, in seconds). If <expire> is zero, the expiration date of the token is
 * used if it is a JWT, otherwise it never expires. The token is sent in a
 * header or in the query string, so it must not be empty and must only contain
 * visible characters, and it must suit the signer of the profile. Returns 0 on
 * success, otherwise -1 with <err> filled. The previous token is kept on error.
 */
int cloudauth_set_token(struct cloudauth_profile *prof, struct ist token, unsigned int expire, char **err)
{
	struct ist copy;
	ssize_t pos;

	TRACE_ENTER(CLOUDAUTH_EV_CRED, NULL, prof);

	if (!istlen(token)) {
		memprintf(err, "empty token");
		goto error;
	}
	pos = cloudauth_ist_check(token, isgraph);
	if (pos >= 0) {
		memprintf(err, "invalid character at position %ld in the token", (long)pos);
		goto error;
	}
	if (cloudauth_check_token(prof, token, err) < 0)
		goto error;

	if (!expire)
		expire = cloudauth_jwt_exp(token);

	copy = istdup(token);
	if (!isttest(copy)) {
		memprintf(err, "out of memory");
		goto error;
	}

	HA_RWLOCK_WRLOCK(OTHER_LOCK, &prof->lock);
	cloudauth_cred_release(&prof->cred);
	prof->cred.token = copy;
	prof->cred.expire = expire;
	prof->cred.updated = date.tv_sec;
	prof->cred.expired_reported = 0;
	HA_RWLOCK_WRUNLOCK(OTHER_LOCK, &prof->lock);

	/* let the task watch the new expiration date */
	if (prof->expire_task)
		task_wakeup(prof->expire_task, TASK_WOKEN_OTHER);
	TRACE_LEAVE(CLOUDAUTH_EV_CRED, NULL, prof);
	return 0;

  error:
	TRACE_DEVEL("leaving on error", CLOUDAUTH_EV_CRED, NULL, prof);
	return -1;
}

/* Returns the index of the input <name> of the token source of profile <prof>,
 * or -1 if it has no such input.
 */
int cloudauth_find_input(const struct cloudauth_profile *prof, const char *name)
{
	const char * const *inputs;
	int i;

	if (prof->token_src != CLOUDAUTH_SRC_FETCH || !prof->fetch.source->inputs)
		return -1;
	inputs = prof->fetch.source->inputs;
	for (i = 0; inputs[i]; i++) {
		if (strcmp(inputs[i], name) == 0)
			return i;
	}
	return -1;
}

/* Returns the state of input <in>, with the lock of its profile held */
static enum cloudauth_cred_state __cloudauth_input_state(const struct cloudauth_input *in)
{
	if (!isttest(in->value))
		return CLOUDAUTH_CRED_MISSING;
	if (in->expire && in->expire <= (unsigned int)date.tv_sec)
		return CLOUDAUTH_CRED_EXPIRED;
	return CLOUDAUTH_CRED_VALID;
}

/* Replaces the input of index <idx> of profile <prof> by a copy of <value>.
 * It must only contain visible characters, and it is rejected if it is a JWT
 * which already expired. Returns 0 on success, otherwise -1 with <err> filled,
 * the previous input being kept. The input is never reported.
 */
int cloudauth_set_input(struct cloudauth_profile *prof, int idx, const struct ist value, char **err)
{
	struct cloudauth_input *in = &prof->inputs[idx];
	struct ist copy, old;
	unsigned int expire;
	ssize_t pos;

	TRACE_ENTER(CLOUDAUTH_EV_CRED, NULL, prof);

	if (!istlen(value)) {
		memprintf(err, "empty input");
		goto error;
	}
	pos = cloudauth_ist_check(value, isgraph);
	if (pos >= 0) {
		memprintf(err, "invalid character at position %ld in the input", (long)pos);
		goto error;
	}
	expire = cloudauth_jwt_exp(value);
	if (expire && expire <= (unsigned int)date.tv_sec) {
		memprintf(err, "the input already expired");
		goto error;
	}

	copy = istdup(value);
	if (!isttest(copy)) {
		memprintf(err, "out of memory");
		goto error;
	}

	HA_RWLOCK_WRLOCK(OTHER_LOCK, &prof->lock);
	old = in->value;
	in->value = copy;
	in->expire = expire;
	in->updated = date.tv_sec;
	HA_RWLOCK_WRUNLOCK(OTHER_LOCK, &prof->lock);

	cloudauth_free_secret(&old);
	TRACE_LEAVE(CLOUDAUTH_EV_CRED, NULL, prof);
	return 0;

  error:
	TRACE_DEVEL("leaving on error", CLOUDAUTH_EV_CRED, NULL, prof);
	return -1;
}

/* Wipes and releases the inputs of profile <prof> */
static void cloudauth_inputs_release(struct cloudauth_profile *prof)
{
	int i;

	for (i = 0; i < CLOUDAUTH_MAX_INPUTS; i++)
		cloudauth_free_secret(&prof->inputs[i].value);
}

/* Adds the "Authorization: Bearer <token>" header to the request in <htx>.
 * The lock of the profile must be held. Returns 0 on success, -1 on failure.
 */
int cloudauth_sign_bearer(const struct cloudauth_profile *prof, struct htx *htx)
{
	struct buffer *val = get_trash_chunk();
	int ret = 0;

	if (!chunk_strcpy(val, "Bearer "))
		ret = -1;
	else if (!chunk_istcat(val, prof->cred.token))
		ret = -1;
	else if (!http_add_header(htx, ist("authorization"), ist2(val->area, val->data), 0))
		ret = -1;

	/* do not leave the token in the trash */
	ha_memset_s(val->area, 0, val->data);
	val->data = 0;
	return ret;
}

/* Authenticates the request in <htx> of the stream <strm> with the credential
 * of profile <prof>. The headers which may carry credentials must have been
 * removed first. Returns 0 on success, otherwise -1 with <reason> set to a
 * static string describing the failure, which never contains the credential.
 */
int cloudauth_sign_request(struct cloudauth_profile *prof, const struct stream *strm, struct htx *htx,
                           const char **reason)
{
	int ret = -1;

	TRACE_ENTER(CLOUDAUTH_EV_REQ, strm, prof);

	HA_RWLOCK_RDLOCK(OTHER_LOCK, &prof->lock);
	switch (__cloudauth_cred_state(prof)) {
	case CLOUDAUTH_CRED_MISSING:
		*reason = "no credential";
		goto out;
	case CLOUDAUTH_CRED_EXPIRED:
		*reason = "credential expired";
		goto out;
	case CLOUDAUTH_CRED_VALID:
		break;
	}

	/* the sigv4 signer reports its own reasons */
	if (prof->provider && prof->signer == CLOUDAUTH_SIGNER_SIGV4) {
		ret = cloudauth_sigv4_sign(prof, strm, htx, prof->provider->sigv4, reason);
		goto out;
	}

	/* without provider, only the bearer signer is accepted */
	if (!prof->provider)
		ret = cloudauth_sign_bearer(prof, htx);
	else
		ret = prof->provider->sign(prof, strm, htx);
	if (ret < 0)
		*reason = "cannot add the credential to the request";
  out:
	HA_RWLOCK_RDUNLOCK(OTHER_LOCK, &prof->lock);
	if (ret < 0)
		TRACE_DEVEL("leaving on error", CLOUDAUTH_EV_REQ, strm, prof);
	else
		TRACE_LEAVE(CLOUDAUTH_EV_REQ, strm, prof);
	return ret;
}

/* The headers which may carry credentials for a cloud storage */
static const struct ist cloudauth_cred_hdrs[] = {
	IST("authorization"),
	IST("x-auth-token"),
};

/* The prefixes of the headers which may carry credentials or be signed */
static const struct ist cloudauth_cred_hdr_pfx[] = {
	IST("x-amz-"),
	IST("x-ms-"),
	IST("x-goog-"),
};

/* Removes all the headers that may carry credentials from the request in
 * <htx>, so that the client cannot impersonate HAProxy nor interfere with the
 * signature. It also removes the ones set for a previous server. The names of
 * the removed headers are traced for the stream <strm> and the profile <prof>.
 */
static void cloudauth_strip_cred_headers(struct htx *htx, const struct stream *strm,
                                         const struct cloudauth_profile *prof)
{
	struct http_hdr_ctx ctx;
	struct ist name;
	int i;

	for (i = 0; i < sizeof(cloudauth_cred_hdrs) / sizeof(*cloudauth_cred_hdrs); i++) {
		ctx.blk = NULL;
		while (http_find_header(htx, cloudauth_cred_hdrs[i], &ctx, 1)) {
			name = htx_get_blk_name(htx, ctx.blk);
			TRACE_STATE("client credential header removed", CLOUDAUTH_EV_STRIP, strm, prof, &name);
			http_remove_header(htx, &ctx);
		}
	}
	for (i = 0; i < sizeof(cloudauth_cred_hdr_pfx) / sizeof(*cloudauth_cred_hdr_pfx); i++) {
		ctx.blk = NULL;
		while (http_find_pfx_header(htx, cloudauth_cred_hdr_pfx[i], &ctx, 1)) {
			name = htx_get_blk_name(htx, ctx.blk);
			TRACE_STATE("client credential header removed", CLOUDAUTH_EV_STRIP, strm, prof, &name);
			http_remove_header(htx, &ctx);
		}
	}
}

/* The query string parameters which may carry credentials: the Azure shared
 * access signatures, the pre-signed URLs of S3 (signature V2) and Google Cloud
 * Storage, and the OAuth access tokens accepted by the Google APIs.
 */
static const struct ist cloudauth_cred_params[] = {
	IST("sv"), IST("ss"), IST("srt"), IST("sp"), IST("se"), IST("st"),
	IST("spr"), IST("sip"), IST("si"), IST("sr"), IST("sig"), IST("sdd"),
	IST("ses"), IST("skoid"), IST("sktid"), IST("skt"), IST("ske"),
	IST("sks"), IST("skv"), IST("saoid"), IST("suoid"), IST("scid"),
	IST("sduoid"), IST("rscc"), IST("rscd"), IST("rsce"), IST("rscl"),
	IST("rsct"), IST("tn"), IST("spk"), IST("srk"), IST("epk"), IST("erk"),
	IST("awsaccesskeyid"), IST("signature"), IST("expires"),
	IST("googleaccessid"),
	IST("access_token"),
};

/* The prefixes of the query string parameters which may carry credentials:
 * the pre-signed URLs of S3 (signature V4) and Google Cloud Storage (V4).
 */
static const struct ist cloudauth_cred_param_pfx[] = {
	IST("x-amz-"),
	IST("x-goog-"),
};

/* Returns non-zero if the query string parameter named <n> (URL-decoded) may
 * carry credentials.
 */
static int cloudauth_is_cred_param(const struct ist n)
{
	int i;

	for (i = 0; i < sizeof(cloudauth_cred_params) / sizeof(*cloudauth_cred_params); i++) {
		if (isteqi(n, cloudauth_cred_params[i]))
			return 1;
	}
	for (i = 0; i < sizeof(cloudauth_cred_param_pfx) / sizeof(*cloudauth_cred_param_pfx); i++) {
		if (istmatchi(n, cloudauth_cred_param_pfx[i]))
			return 1;
	}
	return 0;
}

/* Removes all the query string parameters that may carry credentials from the
 * request in <htx>, for the same reasons as the headers. The names are
 * compared once URL-decoded, and the parameters whose name cannot be decoded
 * are removed too. The names of the removed parameters are traced for the
 * stream <strm> and the profile <prof>. Returns 1 on success, 0 on failure.
 */
static int cloudauth_strip_cred_query(struct htx *htx, const struct stream *strm,
                                      const struct cloudauth_profile *prof)
{
	struct buffer *query = NULL, *work = NULL;
	struct ist path, params, param, name;
	int removed = 0, ret = 0, strip;

	path = cloudauth_req_path(htx);
	params = istfind(path, '?');
	if (!istlen(params))
		return 1;

	query = alloc_trash_chunk();
	if (!query)
		goto out;
	work = alloc_trash_chunk();
	if (!work)
		goto out;

	/* the kept parameters, with the leading question mark expected by
	 * http_replace_req_query(). They carry no credential, so the trash may
	 * be used.
	 */
	if (!chunk_memcat(query, "?", 1))
		goto out;

	params = istnext(params);
	while (istlen(params)) {
		param = istsplit(&params, '&');
		if (!istlen(param))
			continue;

		/* the name is not set if it cannot be decoded, and the
		 * parameter is then removed
		 */
		name = IST_NULL;
		chunk_reset(work);
		strip = 1;
		if (cloudauth_url_decode(work, iststop(param, '='), &name) == 0)
			strip = cloudauth_is_cred_param(name);
		if (strip) {
			TRACE_STATE("client credential parameter removed", CLOUDAUTH_EV_STRIP, strm, prof, &name);
			removed++;
			continue;
		}

		/* the kept parameters are separated by '&' after the '?' */
		if (query->data > 1) {
			if (!chunk_memcat(query, "&", 1))
				goto out;
		}
		if (!chunk_istcat(query, param))
			goto out;
	}

	/* an emptied query string leaves a question mark after the path */
	ret = 1;
	if (removed)
		ret = http_replace_req_query(htx, ist2(query->area, query->data));

  out:
	free_trash_chunk(work);
	free_trash_chunk(query);
	return ret;
}

/* Sets the Host header of the request in <htx> to <host>, and the authority of
 * the URI if it has one. Returns 1 on success, 0 on failure.
 */
static int cloudauth_set_host(struct htx *htx, const struct ist host)
{
	struct http_hdr_ctx ctx;

	ctx.blk = NULL;
	while (http_find_header(htx, ist("host"), &ctx, 1))
		http_remove_header(htx, &ctx);
	return http_add_header(htx, ist("host"), host, 1);
}

/* The SNI expression automatically set by HAProxy on the HTTPS servers without
 * "sni" (see srv_configure_auto_sni()). It is the Host header sent by the
 * client, which must never select the storage account or bucket.
 */
#define CLOUDAUTH_AUTO_SNI_EXPR "req.hdr(host),field(1,:)"

/* Returns non-zero if server <srv> uses the automatic SNI */
static int cloudauth_srv_auto_sni(const struct server *srv)
{
	return srv->sni_expr && strcmp(srv->sni_expr, CLOUDAUTH_AUTO_SNI_EXPR) == 0;
}

/* Returns the host name the requests sent to server <srv> are destined to:
 * the SNI of the server if any, otherwise the host name of its address. Without
 * TLS, the SNI is not sent but still names the server. The SNI expression is
 * evaluated for session <sess> and stream <strm>. The client Host header is
 * never used, unless explicitly configured with "sni". Returns an empty ist
 * with <reason> set if there is no host name.
 */
static struct ist cloudauth_srv_host(struct server *srv, struct session *sess, struct stream *strm,
                                     const char **reason)
{
	struct sample *smp;

	if (cloudauth_srv_auto_sni(srv))
		goto no_host;

	if (srv->ssl_ctx.sni) {
		smp = sample_fetch_as_type(srv->proxy, sess, strm, SMP_OPT_DIR_REQ | SMP_OPT_FINAL,
		                           srv->ssl_ctx.sni, SMP_T_STR);
		if (!smp || !smp->data.u.str.data) {
			*reason = "the 'sni' expression of the server gave no host name";
			return IST_NULL;
		}
		return ist2(smp->data.u.str.area, smp->data.u.str.data);
	}

	if (srv->hostname)
		return ist(srv->hostname);

  no_host:
	*reason = "the server has neither a host name nor an explicit 'sni'";
	return IST_NULL;
}

/* Authenticates the request in <htx> for server <srv>, which must use a
 * credential profile: the headers and the query string parameters which may
 * carry credentials are removed, the Host header is set, then the request is
 * signed. <sess> and <strm> are used to evaluate the SNI of the server. Returns
 * 0 on success, otherwise -1 with <reason> set to a static string describing
 * the failure.
 */
int cloudauth_authenticate(struct server *srv, struct session *sess, struct stream *strm,
                           struct htx *htx, const char **reason)
{
	struct cloudauth_profile *prof = srv->cloudauth->profile;
	struct ist host, detail;
	int ret = -1;

	TRACE_ENTER(CLOUDAUTH_EV_REQ, strm, prof);

	*reason = NULL;
	cloudauth_strip_cred_headers(htx, strm, prof);
	if (!cloudauth_strip_cred_query(htx, strm, prof)) {
		*reason = "cannot remove the credentials from the query string";
		goto out;
	}

	host = cloudauth_srv_host(srv, sess, strm, reason);
	if (!isttest(host))
		goto out;
	if (!cloudauth_set_host(htx, host)) {
		*reason = "cannot set the Host header";
		goto out;
	}
	TRACE_STATE("Host header set", CLOUDAUTH_EV_REQ, strm, prof, &host);

	/* must be last, the signature may cover the other headers */
	ret = cloudauth_sign_request(prof, strm, htx, reason);

  out:
	if (ret < 0) {
		detail = *reason ? ist(*reason) : IST_NULL;
		TRACE_ERROR("request not authenticated", CLOUDAUTH_EV_REQ, strm, prof, &detail);
		TRACE_DEVEL("leaving on error", CLOUDAUTH_EV_REQ, strm, prof);
	}
	else {
		TRACE_USER("request authenticated", CLOUDAUTH_EV_REQ, strm, prof);
		TRACE_LEAVE(CLOUDAUTH_EV_REQ, strm, prof);
	}
	return ret;
}

/* Releases profile <prof>, which may be NULL or partially initialized */
static void cloudauth_free_profile(struct cloudauth_profile *prof)
{
	if (!prof)
		return;
	task_destroy(prof->expire_task);
	cloudauth_fetch_release(prof);
	cloudauth_cred_release(&prof->cred);
	cloudauth_inputs_release(prof);
	HA_RWLOCK_DESTROY(&prof->lock);
	if (prof->provider && prof->provider->release)
		prof->provider->release(prof);
	ha_free(&prof->token_src_arg);
	ha_free(&prof->fetch.endpoint);
	ha_free(&prof->fetch.scopes);
	ha_free(&prof->region);
	ha_free(&prof->name);
	ha_free(&prof->file);
	free(prof);
}

/* Parses the "cloudauth" section header and dispatches its keywords */
static int cfg_parse_cloudauth(const char *file, int linenum, char **args, int kwm)
{
	struct cfg_kw_list *kwl;
	struct cloudauth_profile *prof;
	const char *best;
	const char *errptr;
	char *errmsg = NULL;
	int err_code = 0;
	int index, rc;

	if (!experimental_directives_allowed) {
		ha_alert("parsing [%s:%d]: section '%s' is experimental, must be allowed via a global 'expose-experimental-directives'\n",
		         file, linenum, cursection);
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}
	mark_tainted(TAINTED_CONFIG_EXP_KW_DECLARED);

	if (strcmp(args[0], "cloudauth") == 0) {
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;

		if (!*args[1]) {
			ha_alert("parsing [%s:%d]: section '%s' requires a name.\n", file, linenum, cursection);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		errptr = invalid_char(args[1]);
		if (errptr) {
			ha_alert("parsing [%s:%d]: character '%c' is not permitted in '%s' name '%s'.\n",
			         file, linenum, *errptr, args[0], args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		prof = cloudauth_find_profile(args[1]);
		if (prof) {
			ha_alert("parsing [%s:%d]: cloudauth section '%s' already exists (%s:%d).\n",
			         file, linenum, args[1], prof->file, prof->line);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		prof = calloc(1, sizeof(*prof));
		if (!prof)
			goto oom;
		prof->name = strdup(args[1]);
		if (!prof->name)
			goto oom;
		prof->file = strdup(file);
		if (!prof->file)
			goto oom;
		prof->line = linenum;
		HA_RWLOCK_INIT(&prof->lock);
		LIST_APPEND(&cloudauth_profiles, &prof->list);
		cur_profile = prof;
		goto out;
	}

	list_for_each_entry(kwl, &cfg_keywords.list, list) {
		for (index = 0; kwl->kw[index].kw != NULL; index++) {
			if (kwl->kw[index].section != CFG_CLOUDAUTH)
				continue;
			if (strcmp(kwl->kw[index].kw, args[0]) != 0)
				continue;

			if (check_kw_experimental(&kwl->kw[index], file, linenum, &errmsg)) {
				ha_alert("%s\n", errmsg);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}

			rc = kwl->kw[index].parse(args, CFG_CLOUDAUTH, NULL, NULL, file, linenum, &errmsg);
			if (rc & ERR_ALERT)
				ha_alert("parsing [%s:%d] : %s\n", file, linenum, errmsg);
			else if (rc & ERR_WARN)
				ha_warning("parsing [%s:%d] : %s\n", file, linenum, errmsg);
			err_code |= rc;
			goto out;
		}
	}

	best = cfg_find_best_match(args[0], &cfg_keywords.list, CFG_CLOUDAUTH);
	if (best)
		ha_alert("parsing [%s:%d] : unknown keyword '%s' in '%s' section; did you mean '%s' maybe ?\n",
		         file, linenum, args[0], cursection, best);
	else
		ha_alert("parsing [%s:%d] : unknown keyword '%s' in '%s' section\n", file, linenum, args[0], cursection);
	err_code |= ERR_ALERT | ERR_FATAL;
	goto out;

  oom:
	cloudauth_free_profile(prof);
	ha_alert("parsing [%s:%d]: out of memory.\n", file, linenum);
	err_code |= ERR_ALERT | ERR_FATAL;
  out:
	if (err_code & ERR_FATAL)
		err_code |= ERR_ABORT;
	free(errmsg);
	return err_code;
}

/* Checks the profile once its section is fully parsed */
static int cfg_postsection_cloudauth(void)
{
	struct cloudauth_profile *prof = cur_profile;
	char *errmsg = NULL;
	int err_code = 0;

	cur_profile = NULL;
	if (!prof)
		return 0;

	if (prof->signer == CLOUDAUTH_SIGNER_NONE) {
		ha_alert("parsing [%s:%d]: cloudauth section '%s' : missing 'signer'.\n",
		         prof->file, prof->line, prof->name);
		err_code |= ERR_ALERT | ERR_FATAL;
	}
	else if (!prof->provider && prof->signer != CLOUDAUTH_SIGNER_BEARER) {
		ha_alert("parsing [%s:%d]: cloudauth section '%s' : the '%s' signer requires a 'provider'.\n",
		         prof->file, prof->line, prof->name, cloudauth_signer_str(prof->signer));
		err_code |= ERR_ALERT | ERR_FATAL;
	}
	else if (prof->provider && !(prof->provider->signers & (1U << prof->signer))) {
		ha_alert("parsing [%s:%d]: cloudauth section '%s' : provider '%s' does not support the '%s' signer.\n",
		         prof->file, prof->line, prof->name, prof->provider->name,
		         cloudauth_signer_str(prof->signer));
		err_code |= ERR_ALERT | ERR_FATAL;
	}
	if (prof->region && prof->signer != CLOUDAUTH_SIGNER_SIGV4) {
		ha_alert("parsing [%s:%d]: cloudauth section '%s' : 'region' is only used by the 'sigv4' signer.\n",
		         prof->file, prof->line, prof->name);
		err_code |= ERR_ALERT | ERR_FATAL;
	}
	else if (!prof->region && prof->signer == CLOUDAUTH_SIGNER_SIGV4 && prof->provider &&
	         prof->provider->sigv4 && !prof->provider->sigv4->region) {
		ha_alert("parsing [%s:%d]: cloudauth section '%s' : the 'sigv4' signer of provider '%s' requires 'region'.\n",
		         prof->file, prof->line, prof->name, prof->provider->name);
		err_code |= ERR_ALERT | ERR_FATAL;
	}
	if (prof->token_src == CLOUDAUTH_SRC_NONE) {
		ha_alert("parsing [%s:%d]: cloudauth section '%s' : missing 'token'.\n",
		         prof->file, prof->line, prof->name);
		err_code |= ERR_ALERT | ERR_FATAL;
	}
	else if (prof->token_src == CLOUDAUTH_SRC_FETCH && prof->signer != CLOUDAUTH_SIGNER_NONE &&
	         !(prof->fetch.source->signers & (1U << prof->signer))) {
		ha_alert("parsing [%s:%d]: cloudauth section '%s' : the token source '%s' cannot be used with the '%s' signer.\n",
		         prof->file, prof->line, prof->name, prof->fetch.source->name,
		         cloudauth_signer_str(prof->signer));
		err_code |= ERR_ALERT | ERR_FATAL;
	}
	if (prof->token_src != CLOUDAUTH_SRC_FETCH &&
	    (prof->fetch.timeout || prof->fetch.refresh || prof->fetch.max_backoff)) {
		ha_alert("parsing [%s:%d]: cloudauth section '%s' : 'fetch-timeout', 'fetch-refresh' and 'fetch-max-backoff' "
		         "require a token fetched by HAProxy ('token <source>').\n",
		         prof->file, prof->line, prof->name);
		err_code |= ERR_ALERT | ERR_FATAL;
	}
	if (prof->token_src != CLOUDAUTH_SRC_FETCH && (prof->fetch.endpoint || prof->fetch.scopes)) {
		ha_alert("parsing [%s:%d]: cloudauth section '%s' : 'token-endpoint' and 'token-scopes' "
		         "require a token fetched by HAProxy ('token <source>').\n",
		         prof->file, prof->line, prof->name);
		err_code |= ERR_ALERT | ERR_FATAL;
	}
	else if (prof->fetch.endpoint && !(prof->fetch.source->flags & CLOUDAUTH_SRC_F_ENDPOINT)) {
		ha_alert("parsing [%s:%d]: cloudauth section '%s' : the token source '%s' does not support 'token-endpoint'.\n",
		         prof->file, prof->line, prof->name, prof->fetch.source->name);
		err_code |= ERR_ALERT | ERR_FATAL;
	}
	else if (prof->fetch.scopes && !(prof->fetch.source->flags & CLOUDAUTH_SRC_F_SCOPES)) {
		ha_alert("parsing [%s:%d]: cloudauth section '%s' : the token source '%s' does not support 'token-scopes'.\n",
		         prof->file, prof->line, prof->name, prof->fetch.source->name);
		err_code |= ERR_ALERT | ERR_FATAL;
	}
	if (err_code)
		return err_code;

	if (prof->token_src == CLOUDAUTH_SRC_FETCH) {
		if (!prof->fetch.timeout)
			prof->fetch.timeout = CLOUDAUTH_FETCH_TIMEOUT;
		if (!prof->fetch.refresh)
			prof->fetch.refresh = CLOUDAUTH_FETCH_REFRESH;
		if (!prof->fetch.max_backoff)
			prof->fetch.max_backoff = CLOUDAUTH_FETCH_MAX_BACKOFF;
	}

	if (prof->provider && prof->provider->check && prof->provider->check(prof, &errmsg) < 0) {
		ha_alert("parsing [%s:%d]: cloudauth section '%s' : %s.\n",
		         prof->file, prof->line, prof->name, errmsg);
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}

	/* the token may have been loaded before the provider or the signer */
	if (isttest(prof->cred.token) && cloudauth_check_token(prof, prof->cred.token, &errmsg) < 0) {
		ha_alert("parsing [%s:%d]: cloudauth section '%s' : invalid token : %s.\n",
		         prof->file, prof->line, prof->name, errmsg);
		err_code |= ERR_ALERT | ERR_FATAL;
	}
  out:
	free(errmsg);
	return err_code;
}

/* Parses the "signer" keyword */
static int cfg_parse_cloudauth_signer(char **args, int section_type, struct proxy *curpx,
                                      const struct proxy *defpx, const char *file, int linenum,
                                      char **err)
{
	enum cloudauth_signer signer;

	if (!cur_profile)
		return ERR_ALERT | ERR_FATAL;

	if (!*args[1] || *args[2]) {
		memprintf(err, "'%s' expects exactly one argument.", args[0]);
		return ERR_ALERT | ERR_FATAL;
	}

	for (signer = CLOUDAUTH_SIGNER_BEARER; signer < CLOUDAUTH_SIGNER_ENTRIES; signer++) {
		if (strcmp(args[1], cloudauth_signer_names[signer]) == 0)
			break;
	}
	if (signer == CLOUDAUTH_SIGNER_ENTRIES) {
		memprintf(err, "'%s' : unknown signer '%s', expects 'bearer', 'sas', 'sharedkey' or 'sigv4'.",
		          args[0], args[1]);
		return ERR_ALERT | ERR_FATAL;
	}
	cur_profile->signer = signer;
	return 0;
}

/* Longest delay accepted by "fetch-refresh" and "fetch-max-backoff", in
 * seconds: one day, the credentials are expected to be refreshed more often.
 */
#define CLOUDAUTH_FETCH_MAX_DELAY 86400

/* Parses the keywords setting the delays of the fetching of the credential,
 * which require a token source:
 *    fetch-timeout <time>      : timeout of the response, in milliseconds
 *    fetch-refresh <time>      : refresh delay if the expiration is unknown
 *    fetch-max-backoff <time>  : maximum delay between attempts after failures
 * The last two ones are in seconds, at most one day.
 */
static int cfg_parse_cloudauth_fetch_delay(char **args, int section_type, struct proxy *curpx,
                                           const struct proxy *defpx, const char *file, int linenum,
                                           char **err)
{
	unsigned int *delay, unit, max;
	const char *res;

	if (!cur_profile)
		return ERR_ALERT | ERR_FATAL;

	if (!*args[1] || *args[2]) {
		memprintf(err, "'%s' expects exactly one argument.", args[0]);
		return ERR_ALERT | ERR_FATAL;
	}

	if (strcmp(args[0], "fetch-timeout") == 0) {
		delay = &cur_profile->fetch.timeout;
		unit = TIME_UNIT_MS;
		max = INT_MAX;
	}
	else if (strcmp(args[0], "fetch-refresh") == 0) {
		delay = &cur_profile->fetch.refresh;
		unit = TIME_UNIT_S;
		max = CLOUDAUTH_FETCH_MAX_DELAY;
	}
	else {
		delay = &cur_profile->fetch.max_backoff;
		unit = TIME_UNIT_S;
		max = CLOUDAUTH_FETCH_MAX_DELAY;
	}

	if (*delay) {
		memprintf(err, "'%s' may only be set once.", args[0]);
		return ERR_ALERT | ERR_FATAL;
	}

	res = parse_time_err(args[1], delay, unit);
	if (res == PARSE_TIME_OVER || (!res && *delay > max)) {
		memprintf(err, "'%s' : delay '%s' is too large.", args[0], args[1]);
		return ERR_ALERT | ERR_FATAL;
	}
	if (res == PARSE_TIME_UNDER || (!res && !*delay)) {
		memprintf(err, "'%s' : delay '%s' is too small, expects at least 1%s.",
		          args[0], args[1], unit == TIME_UNIT_MS ? "ms" : "s");
		return ERR_ALERT | ERR_FATAL;
	}
	if (res) {
		memprintf(err, "'%s' : unexpected character '%c' in delay '%s'.", args[0], *res, args[1]);
		return ERR_ALERT | ERR_FATAL;
	}
	return 0;
}

/* Parses the "token-endpoint" keyword: the URL of the token endpoint of the
 * token source, to use instead of its default one.
 */
static int cfg_parse_cloudauth_token_endpoint(char **args, int section_type, struct proxy *curpx,
                                              const struct proxy *defpx, const char *file, int linenum,
                                              char **err)
{
	if (!cur_profile)
		return ERR_ALERT | ERR_FATAL;
	return cloudauth_cfg_str(args, &cur_profile->fetch.endpoint, 0, cloudauth_is_http_url, "URL",
	                         "'http://' or 'https://'", err);
}

/* Returns non-zero if <scope> is an OAuth 2.0 scope: visible ASCII characters
 * except the double quote and the backslash (RFC 6749, section 3.3).
 */
static int cloudauth_is_scope(const char *scope)
{
	const char *p;

	if (!*scope)
		return 0;
	for (p = scope; *p; p++) {
		if (*p < 0x21 || *p > 0x7e || *p == '"' || *p == '\\')
			return 0;
	}
	return 1;
}

/* Parses the "token-scopes" keyword: the OAuth 2.0 scopes of the tokens
 * requested from the token source, instead of its default ones. They are kept
 * separated by spaces, the token sources sending them as they expect.
 */
static int cfg_parse_cloudauth_token_scopes(char **args, int section_type, struct proxy *curpx,
                                            const struct proxy *defpx, const char *file, int linenum,
                                            char **err)
{
	size_t len = 0;
	int i;

	if (!cur_profile)
		return ERR_ALERT | ERR_FATAL;

	if (!*args[1]) {
		memprintf(err, "'%s' expects at least one scope.", args[0]);
		return ERR_ALERT | ERR_FATAL;
	}
	if (cur_profile->fetch.scopes) {
		memprintf(err, "'%s' may only be set once.", args[0]);
		return ERR_ALERT | ERR_FATAL;
	}

	for (i = 1; *args[i]; i++) {
		if (!cloudauth_is_scope(args[i])) {
			memprintf(err, "'%s' : invalid scope '%s'.", args[0], args[i]);
			return ERR_ALERT | ERR_FATAL;
		}
		len += strlen(args[i]) + (i > 1);
		if (len > CLOUDAUTH_MAX_SCOPES_LEN) {
			memprintf(err, "'%s' : the scopes are longer than %d characters.", args[0], CLOUDAUTH_MAX_SCOPES_LEN);
			return ERR_ALERT | ERR_FATAL;
		}
		if (i == 1)
			memprintf(&cur_profile->fetch.scopes, "%s", args[i]);
		else
			memprintf(&cur_profile->fetch.scopes, "%s %s", cur_profile->fetch.scopes, args[i]);
		if (!cur_profile->fetch.scopes) {
			memprintf(err, "out of memory");
			return ERR_ALERT | ERR_FATAL;
		}
	}
	return 0;
}

/* Returns non-zero if <region> is a valid region for the "sigv4" signer: up to
 * CLOUDAUTH_MAX_REGION_LEN letters, digits, dashes or underscores, since it is
 * written as is in the credential scope of the signatures.
 */
static int cloudauth_is_region(const char *region)
{
	size_t len = strlen(region);

	if (!len || len > CLOUDAUTH_MAX_REGION_LEN)
		return 0;
	return strspn(region, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_") == len;
}

/* Parses the "region" keyword: the region of the storage, signed by the
 * "sigv4" signer, instead of the default one of the provider.
 */
static int cfg_parse_cloudauth_region(char **args, int section_type, struct proxy *curpx,
                                      const struct proxy *defpx, const char *file, int linenum,
                                      char **err)
{
	if (!cur_profile)
		return ERR_ALERT | ERR_FATAL;
	return cloudauth_cfg_str(args, &cur_profile->region, 0, cloudauth_is_region, "region",
	                         "letters, digits, dashes or underscores", err);
}

/* Parses the "provider" keyword: the name of a registered storage provider.
 * Its own keywords may only be used after it.
 */
static int cfg_parse_cloudauth_provider(char **args, int section_type, struct proxy *curpx,
                                        const struct proxy *defpx, const char *file, int linenum,
                                        char **err)
{
	const struct cloudauth_provider *prov;

	if (!cur_profile)
		return ERR_ALERT | ERR_FATAL;

	if (!*args[1] || *args[2]) {
		memprintf(err, "'%s' expects exactly one argument.", args[0]);
		return ERR_ALERT | ERR_FATAL;
	}
	if (cur_profile->provider) {
		memprintf(err, "'%s' may only be set once.", args[0]);
		return ERR_ALERT | ERR_FATAL;
	}

	prov = cloudauth_find_provider(args[1]);
	if (!prov) {
		memprintf(err, "'%s' : unknown provider '%s', the supported ones are :", args[0], args[1]);
		list_for_each_entry(prov, &cloudauth_providers, list)
			memprintf(err, "%s '%s'", *err, prov->name);
		if (LIST_ISEMPTY(&cloudauth_providers))
			memprintf(err, "%s none (see the USE_CLOUDAUTH_* build options)", *err);
		memprintf(err, "%s.", *err);
		return ERR_ALERT | ERR_FATAL;
	}

	cur_profile->provider = prov;
	if (prov->init && prov->init(cur_profile, err) < 0)
		return ERR_ALERT | ERR_FATAL;
	return 0;
}

/* Maximum size of a secret read from a file */
#define CLOUDAUTH_MAX_SECRET_FILE 65536

/* Reads the secret of file <path> into <out>, which is allocated. The trailing
 * spaces and line feeds are ignored. A warning is emitted if the file may be
 * read by other users. Returns a combination of ERR_* flags, with <err> filled
 * on error or warning. The secret is never reported.
 */
static int cloudauth_read_secret_file(const char *path, struct ist *out, char **err)
{
	struct stat st;
	char *buf = NULL;
	ssize_t len;
	int fd, err_code = 0;

	fd = open(path, O_RDONLY);
	if (fd == -1) {
		memprintf(err, "cannot read file '%s' : %s", path, strerror(errno));
		err_code = ERR_ALERT | ERR_FATAL;
		goto out;
	}
	if (fstat(fd, &st) == -1) {
		memprintf(err, "cannot read file '%s' : %s", path, strerror(errno));
		err_code = ERR_ALERT | ERR_FATAL;
		goto out;
	}
	if (!S_ISREG(st.st_mode) || st.st_size > CLOUDAUTH_MAX_SECRET_FILE) {
		memprintf(err, "file '%s' is not a regular file or is larger than %d bytes",
		          path, CLOUDAUTH_MAX_SECRET_FILE);
		err_code = ERR_ALERT | ERR_FATAL;
		goto out;
	}

	buf = malloc(st.st_size + 1);
	if (!buf) {
		memprintf(err, "out of memory");
		err_code = ERR_ALERT | ERR_FATAL;
		goto out;
	}
	len = read(fd, buf, st.st_size);
	if (len != st.st_size) {
		memprintf(err, "cannot read file '%s'", path);
		err_code = ERR_ALERT | ERR_FATAL;
		goto out;
	}

	while (len > 0 && isspace((unsigned char)buf[len - 1]))
		len--;
	if (!len) {
		memprintf(err, "file '%s' is empty", path);
		err_code = ERR_ALERT | ERR_FATAL;
		goto out;
	}

	*out = istdup(ist2(buf, len));
	if (!isttest(*out)) {
		memprintf(err, "out of memory");
		err_code = ERR_ALERT | ERR_FATAL;
		goto out;
	}

	if (st.st_mode & (S_IRWXG | S_IRWXO)) {
		memprintf(err, "file '%s' may be accessed by other users, its permissions should be restricted to its owner",
		          path);
		err_code = ERR_WARN;
	}

  out:
	if (buf) {
		ha_memset_s(buf, 0, st.st_size);
		free(buf);
	}
	if (fd != -1)
		close(fd);
	return err_code;
}

/* Reads the secret <arg> into <out>, which is allocated, when the
 * configuration is parsed. <arg> is either "env:<variable>", the variable
 * being then removed from the environment once the configuration is parsed,
 * or "file:<path>". Secrets are never accepted in the configuration itself.
 * Returns a combination of ERR_* flags, with <err> filled on error or warning.
 * On success, the caller must wipe <out> with ha_memset_s() before releasing
 * it. The secret is never reported.
 */
int cloudauth_cfg_read_secret(const char *arg, struct ist *out, char **err)
{
	const char *value;

	*out = IST_NULL;
	if (strncmp(arg, "env:", 4) == 0 && arg[4]) {
		value = getenv(arg + 4);
		if (!value || !*value) {
			memprintf(err, "environment variable '%s' is not set or empty", arg + 4);
			return ERR_ALERT | ERR_FATAL;
		}
		if (cloudauth_register_secret_env(arg + 4) < 0) {
			memprintf(err, "out of memory");
			return ERR_ALERT | ERR_FATAL;
		}
		*out = istdup(ist(value));
		if (!isttest(*out)) {
			memprintf(err, "out of memory");
			return ERR_ALERT | ERR_FATAL;
		}
		return 0;
	}
	if (strncmp(arg, "file:", 5) == 0 && arg[5])
		return cloudauth_read_secret_file(arg + 5, out, err);

	/* never echo the argument, it may be a secret */
	memprintf(err, "expects 'env:<variable>' or 'file:<path>', secrets are not accepted in the configuration");
	return ERR_ALERT | ERR_FATAL;
}

/* Wipes and releases the secret <secret> */
void cloudauth_free_secret(struct ist *secret)
{
	if (isttest(*secret))
		ha_memset_s(istptr(*secret), 0, istlen(*secret));
	istfree(secret);
}

/* Returns the token source named <name> of the provider of profile <prof>, or
 * NULL if there is none.
 */
static const struct cloudauth_source *cloudauth_find_source(const struct cloudauth_profile *prof, const char *name)
{
	const struct cloudauth_source *src;

	if (!prof->provider || !prof->provider->sources)
		return NULL;
	for (src = prof->provider->sources; src->name; src++) {
		if (strcmp(src->name, name) == 0)
			return src;
	}
	return NULL;
}

/* Returns non-zero if <arg> designates a secret read when the configuration
 * is parsed: "env:<variable>" or "file:<path>".
 */
static int cloudauth_is_secret_arg(const char *arg)
{
	return (strncmp(arg, "env:", 4) == 0 && arg[4]) || (strncmp(arg, "file:", 5) == 0 && arg[5]);
}

/* Reads the <nb> parts of the token of the "sigv4" signer, args[1] to
 * args[<nb>], each one being "env:<variable>" or "file:<path>", and joins them
 * with colons into <out>, which is allocated, so that the token is
 * "<access-key-id>:<secret>" or "<access-key-id>:<secret>:<session-token>",
 * as when it is injected from the CLI. A part must not contain a colon.
 * Returns a combination of ERR_* flags, with <err> filled on error or warning.
 * On success, the caller must release <out> with cloudauth_free_secret().
 */
static int cloudauth_cfg_read_token_parts(char **args, int nb, struct ist *out, char **err)
{
	struct buffer *token;
	struct ist part = IST_NULL;
	char *msg = NULL;
	int i, ret, err_code = 0;

	*out = IST_NULL;
	token = alloc_trash_chunk();
	if (!token)
		goto oom;

	for (i = 1; i <= nb; i++) {
		ret = cloudauth_cfg_read_secret(args[i], &part, &msg);
		err_code |= ret;
		if (ret & ERR_CODE) {
			memprintf(err, "%s", msg);
			goto out;
		}
		/* keep the warnings, such as the permissions of a file */
		if (ret)
			memprintf(err, "%s%s%s", *err ? *err : "", *err ? ", " : "", msg);
		ha_free(&msg);

		if (istchr(part, ':')) {
			memprintf(err, "the part read from '%s' must not contain ':'", args[i]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		/* the parts are joined with colons */
		if (i > 1) {
			if (!chunk_memcat(token, ":", 1))
				goto full;
		}
		if (!chunk_istcat(token, part))
			goto full;
		cloudauth_free_secret(&part);
	}

	*out = istdup(ist2(token->area, token->data));
	if (!isttest(*out))
		goto oom;
	goto out;

  oom:
	memprintf(err, "out of memory");
	err_code |= ERR_ALERT | ERR_FATAL;
	goto out;
  full:
	memprintf(err, "the token does not fit in a buffer");
	err_code |= ERR_ALERT | ERR_FATAL;
  out:
	free(msg);
	cloudauth_free_secret(&part);
	if (token)
		ha_memset_s(token->area, 0, token->size);
	free_trash_chunk(token);
	return err_code;
}

/* Parses the "token" keyword:
 *    token env:<variable> | file:<path> | cli | <source>
 *    token <access-key-id> <secret> [<session-token>]   (sigv4 signer)
 * The token itself is never accepted in the configuration. It is loaded when
 * the keyword is parsed, that is before any chroot, or fetched from the token
 * source <source> of the provider, which must be set first. With the "sigv4"
 * signer, which must then be set first, the parts of the access key may be
 * read from distinct variables or files, each one being "env:<variable>" or
 * "file:<path>", and are joined as the token injected from the CLI.
 */
static int cfg_parse_cloudauth_token(char **args, int section_type, struct proxy *curpx,
                                     const struct proxy *defpx, const char *file, int linenum,
                                     char **err)
{
	const struct cloudauth_source *source, *src;
	struct ist secret;
	int err_code = 0;
	int nb, i;

	if (!cur_profile)
		return ERR_ALERT | ERR_FATAL;

	for (nb = 0; *args[nb + 1]; nb++)
		;
	if (!nb) {
		memprintf(err, "'%s' expects at least one argument.", args[0]);
		return ERR_ALERT | ERR_FATAL;
	}
	if (nb > 1 && cur_profile->signer != CLOUDAUTH_SIGNER_SIGV4) {
		memprintf(err, "'%s' expects exactly one argument, except after 'signer sigv4'.", args[0]);
		return ERR_ALERT | ERR_FATAL;
	}
	if (nb > 3) {
		memprintf(err, "'%s' expects at most 3 arguments with the 'sigv4' signer "
		          "(<access-key-id> <secret> [<session-token>]).", args[0]);
		return ERR_ALERT | ERR_FATAL;
	}
	if (cur_profile->token_src != CLOUDAUTH_SRC_NONE) {
		memprintf(err, "'%s' may only be set once.", args[0]);
		return ERR_ALERT | ERR_FATAL;
	}
	for (i = 1; nb > 1 && i <= nb; i++) {
		if (!cloudauth_is_secret_arg(args[i])) {
			/* never echo the argument, it may be a secret */
			memprintf(err, "'%s' expects 'env:<variable>' or 'file:<path>' for each part of the access key, "
			          "secrets are not accepted in the configuration.", args[0]);
			return ERR_ALERT | ERR_FATAL;
		}
	}

	source = cloudauth_find_source(cur_profile, args[1]);
	if (cloudauth_is_secret_arg(args[1])) {
		cur_profile->token_src = strncmp(args[1], "env:", 4) == 0 ? CLOUDAUTH_SRC_ENV : CLOUDAUTH_SRC_FILE;
		/* reported as "<src>:<arg>", the other parts following it */
		memprintf(&cur_profile->token_src_arg, "%s", strchr(args[1], ':') + 1);
		for (i = 2; cur_profile->token_src_arg && i <= nb; i++)
			memprintf(&cur_profile->token_src_arg, "%s %s", cur_profile->token_src_arg, args[i]);
		if (!cur_profile->token_src_arg) {
			memprintf(err, "out of memory");
			return ERR_ALERT | ERR_FATAL;
		}
		if (nb > 1)
			err_code = cloudauth_cfg_read_token_parts(args, nb, &secret, err);
		else
			err_code = cloudauth_cfg_read_secret(args[1], &secret, err);
		if (err_code & ERR_CODE) {
			memprintf(err, "'%s' : %s.", args[0], *err);
			return err_code;
		}
		if (cloudauth_set_token(cur_profile, secret, 0, err) < 0) {
			if (nb > 1)
				memprintf(err, "'%s' : invalid token in '%.*s:%s' : %s.", args[0],
				          (int)(strchr(args[1], ':') - args[1]), args[1], cur_profile->token_src_arg, *err);
			else
				memprintf(err, "'%s' : invalid token in '%s' : %s.", args[0], args[1], *err);
			err_code = ERR_ALERT | ERR_FATAL;
		}
		else if (err_code)
			memprintf(err, "'%s' : %s.", args[0], *err);
		cloudauth_free_secret(&secret);
		return err_code;
	}
	else if (strcmp(args[1], "cli") == 0) {
		cur_profile->token_src = CLOUDAUTH_SRC_CLI;
	}
	else if (source) {
		cur_profile->token_src = CLOUDAUTH_SRC_FETCH;
		cur_profile->fetch.source = source;
		cur_profile->token_src_arg = strdup(source->name);
		if (!cur_profile->token_src_arg) {
			memprintf(err, "out of memory");
			return ERR_ALERT | ERR_FATAL;
		}
		if (source->init && source->init(cur_profile, err) < 0)
			return ERR_ALERT | ERR_FATAL;
	}
	else if (cur_profile->provider && cur_profile->provider->sources) {
		/* never echo the argument, it may be a secret */
		memprintf(err, "'%s' expects 'env:<variable>', 'file:<path>', 'cli' or a token source of provider '%s' (",
		          args[0], cur_profile->provider->name);
		for (src = cur_profile->provider->sources; src->name; src++)
			memprintf(err, "%s%s'%s'", *err, src == cur_profile->provider->sources ? "" : ", ", src->name);
		memprintf(err, "%s), secrets are not accepted in the configuration.", *err);
		return ERR_ALERT | ERR_FATAL;
	}
	else {
		/* never echo the argument, it may be a secret */
		memprintf(err, "'%s' expects 'env:<variable>', 'file:<path>' or 'cli', secrets are not accepted in the configuration.",
		          args[0]);
		return ERR_ALERT | ERR_FATAL;
	}
	return 0;
}

/* Parses the "input" keyword:
 *    input <name> env:<variable> | file:<path>
 * which loads the input <name> of the token source of the profile, which must
 * be selected first, when the configuration is parsed. The input may then be
 * replaced from the CLI.
 */
static int cfg_parse_cloudauth_input(char **args, int section_type, struct proxy *curpx,
                                     const struct proxy *defpx, const char *file, int linenum,
                                     char **err)
{
	const char * const *inputs;
	struct ist secret;
	int idx, i, err_code;

	if (!cur_profile)
		return ERR_ALERT | ERR_FATAL;

	if (!*args[1] || !*args[2] || *args[3]) {
		memprintf(err, "'%s' expects <name> and 'env:<variable>' or 'file:<path>'.", args[0]);
		return ERR_ALERT | ERR_FATAL;
	}
	if (cur_profile->token_src != CLOUDAUTH_SRC_FETCH || !cur_profile->fetch.source->inputs) {
		memprintf(err, "'%s' requires a token source using inputs first ('token <source>').", args[0]);
		return ERR_ALERT | ERR_FATAL;
	}

	idx = cloudauth_find_input(cur_profile, args[1]);
	if (idx < 0) {
		inputs = cur_profile->fetch.source->inputs;
		memprintf(err, "'%s' : unknown input '%s' of the token source '%s', expects ", args[0], args[1],
		          cur_profile->fetch.source->name);
		for (i = 0; inputs[i]; i++)
			memprintf(err, "%s%s'%s'", *err, i ? ", " : "", inputs[i]);
		memprintf(err, "%s.", *err);
		return ERR_ALERT | ERR_FATAL;
	}
	if (isttest(cur_profile->inputs[idx].value)) {
		memprintf(err, "'%s' : input '%s' may only be set once.", args[0], args[1]);
		return ERR_ALERT | ERR_FATAL;
	}

	err_code = cloudauth_cfg_read_secret(args[2], &secret, err);
	if (err_code & ERR_CODE) {
		memprintf(err, "'%s' : %s.", args[0], *err);
		return err_code;
	}
	if (cloudauth_set_input(cur_profile, idx, secret, err) < 0) {
		memprintf(err, "'%s' : invalid input '%s' in '%s' : %s.", args[0], args[1], args[2], *err);
		err_code = ERR_ALERT | ERR_FATAL;
	}
	else if (err_code)
		memprintf(err, "'%s' : %s.", args[0], *err);
	cloudauth_free_secret(&secret);
	return err_code;
}

/* Releases the cloudauth settings of server <srv>. Called when the server is
 * released.
 */
void cloudauth_srv_free(struct server *srv)
{
	if (!srv->cloudauth)
		return;
	ha_free(&srv->cloudauth->profile_name);
	ha_free(&srv->cloudauth);
}

/* Resolves the profile referenced by server <srv> and checks the server may
 * use it. Returns 0 on success, otherwise -1 with <err> filled.
 */
static int cloudauth_srv_resolve(struct server *srv, char **err)
{
	struct cloudauth_srv *conf = srv->cloudauth;
	struct filter_instance *inst;

	conf->profile = cloudauth_find_profile(conf->profile_name);
	if (!conf->profile) {
		memprintf(err, "unknown cloudauth profile '%s'", conf->profile_name);
		return -1;
	}

	if (srv->proxy->mode != PR_MODE_HTTP) {
		memprintf(err, "'cloudauth' requires an HTTP backend");
		return -1;
	}

	/* without the filter, the requests would be sent unauthenticated and
	 * with the client credentials.
	 */
	inst = flt_find_instance(srv->proxy, &flt_cloudauth_cls, NULL);
	if (!inst || !inst->enabled) {
		memprintf(err, "'cloudauth' requires an enabled cloudauth filter in backend '%s' "
		          "(see 'filter-config cloudauth enabled')", srv->proxy->id);
		return -1;
	}
	return 0;
}

/* Parses the "cloudauth" server keyword:
 *    cloudauth <profile>
 * For the servers declared in the configuration, the profile is resolved once
 * the configuration is parsed, because it may be declared after the server.
 * The dynamic servers are resolved immediately.
 */
static int srv_parse_cloudauth(char **args, int *cur_arg, struct proxy *px, struct server *srv, char **err)
{
	const char *name = args[*cur_arg + 1];

	if (!experimental_directives_allowed) {
		memprintf(err, "'%s' is experimental, must be allowed via a global 'expose-experimental-directives'",
		          args[*cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}
	mark_tainted(TAINTED_CONFIG_EXP_KW_DECLARED);

	if (!*name) {
		memprintf(err, "'%s' expects a cloudauth profile name", args[*cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}
	if (srv->cloudauth) {
		memprintf(err, "'%s' may only be set once", args[*cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	srv->cloudauth = calloc(1, sizeof(*srv->cloudauth));
	if (!srv->cloudauth)
		goto oom;
	srv->cloudauth->profile_name = strdup(name);
	if (!srv->cloudauth->profile_name)
		goto oom;

	/* By default, HAProxy uses the client Host header as SNI, which would
	 * let the client select the storage account or bucket. Use the host
	 * name of the server address instead. It is replaced by a "sni" set
	 * after this keyword. Without TLS, it only names the server.
	 */
	if (srv->hostname && !srv->sni_expr && !(srv->ssl_ctx.options & SRV_SSL_O_NO_AUTO_SNI)) {
		memprintf(&srv->sni_expr, "str(%s)", srv->hostname);
		if (!srv->sni_expr) {
			memprintf(err, "out of memory");
			return ERR_ALERT | ERR_FATAL;
		}
	}

	if (!(srv->flags & SRV_F_DYNAMIC))
		return 0;
	if (cloudauth_srv_resolve(srv, err) < 0)
		return ERR_ALERT | ERR_FATAL;
	return 0;

  oom:
	cloudauth_srv_free(srv);
	memprintf(err, "out of memory");
	return ERR_ALERT | ERR_FATAL;
}

/* Resolves the profiles of the servers declared in the configuration */
static int cloudauth_srv_postcheck(struct server *srv)
{
	char *err = NULL;

	if (!srv->cloudauth || srv->cloudauth->profile)
		return ERR_NONE;

	if (cloudauth_srv_resolve(srv, &err) < 0) {
		ha_alert("parsing [%s:%d] : server '%s' in backend '%s' : %s.\n",
		         srv->conf.file, srv->conf.line, srv->id, srv->proxy->id, err);
		free(err);
		return ERR_ALERT | ERR_FATAL;
	}

	/* the dynamic servers are only checked at runtime */
	if (cloudauth_srv_auto_sni(srv) || (!srv->sni_expr && !srv->hostname)) {
		ha_alert("parsing [%s:%d] : server '%s' in backend '%s' : 'cloudauth' requires either a host name "
		         "as server address or an explicit 'sni', the client Host header is never used by default.\n",
		         srv->conf.file, srv->conf.line, srv->id, srv->proxy->id);
		return ERR_ALERT | ERR_FATAL;
	}
	return ERR_NONE;
}

/* Context of the "show cloudauth" command */
struct show_cloudauth_ctx {
	struct cloudauth_profile *next;  /* next profile to dump, NULL once done */
	struct cloudauth_profile *only;  /* only dump this profile if not NULL */
	int header_done;                 /* the header line was dumped */
};

/* Appends to <out> the date <t> (wall clock, in seconds) in ISO 8601 UTC format,
 * or "-" if it is not set.
 */
static void cloudauth_append_date(struct buffer *out, unsigned int t)
{
	char str[CLOUDAUTH_ISO_DATE_SIZE];

	if (!t)
		chunk_appendf(out, "-");
	else if (!cloudauth_iso_date(t, str, sizeof(str)))
		chunk_appendf(out, "-");
	else
		chunk_appendf(out, "%s", str);
}

/* Appends to <out> the line describing profile <prof>. The credential is
 * never reported.
 */
static void cloudauth_dump_profile(struct buffer *out, struct cloudauth_profile *prof)
{
	char error[CLOUDAUTH_FETCH_ERROR_SIZE];
	enum cloudauth_cred_state state, in_state[CLOUDAUTH_MAX_INPUTS];
	unsigned int expire, updated, next, in_expire[CLOUDAUTH_MAX_INPUTS];
	const char * const *inputs = NULL;
	int i;

	if (prof->token_src == CLOUDAUTH_SRC_FETCH)
		inputs = prof->fetch.source->inputs;

	HA_RWLOCK_RDLOCK(OTHER_LOCK, &prof->lock);
	state = __cloudauth_cred_state(prof);
	expire = prof->cred.expire;
	updated = prof->cred.updated;
	next = prof->fetch.next;
	memcpy(error, prof->fetch.error, sizeof(error));
	for (i = 0; inputs && inputs[i]; i++) {
		in_state[i] = __cloudauth_input_state(&prof->inputs[i]);
		in_expire[i] = prof->inputs[i].expire;
	}
	HA_RWLOCK_RDUNLOCK(OTHER_LOCK, &prof->lock);

	chunk_appendf(out, "%s\t%s\t%s\t%s%s%s\t%s\t", prof->name,
	              prof->provider ? prof->provider->name : "-",
	              cloudauth_signer_str(prof->signer),
	              cloudauth_src_str(prof->token_src),
	              prof->token_src_arg ? ":" : "",
	              prof->token_src_arg ? prof->token_src_arg : "",
	              cloudauth_cred_state_str(state));

	cloudauth_append_date(out, expire);
	if (expire && state == CLOUDAUTH_CRED_VALID)
		chunk_appendf(out, "\t%us\t", expire - (unsigned int)date.tv_sec);
	else
		chunk_appendf(out, "\t-\t");
	cloudauth_append_date(out, updated);

	/* only the fetched credentials have a next fetch */
	chunk_appendf(out, "\t");
	cloudauth_append_date(out, prof->token_src == CLOUDAUTH_SRC_FETCH ? next : 0);
	chunk_appendf(out, "\t%s\t", *error ? error : "-");

	/* the inputs of the token source, as <name>:<state>:<expiration> */
	if (!inputs || !inputs[0])
		chunk_appendf(out, "-");
	for (i = 0; inputs && inputs[i]; i++) {
		chunk_appendf(out, "%s%s:%s:", i ? "," : "", inputs[i], cloudauth_cred_state_str(in_state[i]));
		cloudauth_append_date(out, in_expire[i]);
	}
	chunk_appendf(out, "\n");
}

/* Parses "show cloudauth [<profile>]" */
static int cli_parse_show_cloudauth(char **args, char *payload, struct appctx *appctx, void *private)
{
	struct show_cloudauth_ctx *ctx = applet_reserve_svcctx(appctx, sizeof(*ctx));

	if (!cli_has_level(appctx, ACCESS_LVL_OPER))
		return 1;

	if (*args[2]) {
		ctx->only = cloudauth_find_profile(args[2]);
		if (!ctx->only)
			return cli_err(appctx, "No such cloudauth profile.\n");
		ctx->next = ctx->only;
	}
	else if (!LIST_ISEMPTY(&cloudauth_profiles))
		ctx->next = LIST_NEXT(&cloudauth_profiles, struct cloudauth_profile *, list);
	return 0;
}

/* Dumps the profiles. The profiles are never released at runtime, so the
 * position may be kept between two calls. Returns 1 when done, 0 if it must
 * be called again.
 */
static int cli_io_handler_show_cloudauth(struct appctx *appctx)
{
	struct show_cloudauth_ctx *ctx = appctx->svcctx;

	if (!ctx->header_done) {
		chunk_reset(&trash);
		chunk_appendf(&trash, "# name\tprovider\tsigner\tsource\tstate\texpiration date (UTC)\texpires in"
		              "\tlast update (UTC)\tnext fetch (UTC)\tlast error\tinputs\n");
		if (applet_putchk(appctx, &trash) == -1)
			return 0;
		ctx->header_done = 1;
	}

	while (ctx->next) {
		chunk_reset(&trash);
		cloudauth_dump_profile(&trash, ctx->next);
		if (applet_putchk(appctx, &trash) == -1)
			return 0;

		if (ctx->only || ctx->next->list.n == &cloudauth_profiles)
			ctx->next = NULL;
		else
			ctx->next = LIST_NEXT(&ctx->next->list, struct cloudauth_profile *, list);
	}
	return 1;
}

/* Parses "set cloudauth input <profile> <name>" with the input passed as
 * payload, then requests a new fetch if the credential of the profile is not
 * valid or the last fetch failed. The payload is never echoed.
 */
static int cli_parse_set_cloudauth_input(char **args, char *payload, struct appctx *appctx, void *private)
{
	struct cloudauth_profile *prof;
	struct ist detail;
	char *err = NULL;
	size_t len;
	int idx;

	if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
		return 1;

	if (!*args[3])
		return cli_err(appctx, "Missing profile name.\n");
	prof = cloudauth_find_profile(args[3]);
	if (!prof)
		return cli_err(appctx, "No such cloudauth profile.\n");
	if (!*args[4])
		return cli_err(appctx, "Missing input name.\n");
	idx = cloudauth_find_input(prof, args[4]);
	if (idx < 0)
		return cli_err(appctx, "No such input for this profile.\n");
	if (!payload)
		return cli_err(appctx, "Missing input, it must be passed as payload ('<<').\n");

	len = strlen(payload);
	while (len > 0 && isspace((unsigned char)payload[len - 1]))
		len--;

	if (cloudauth_set_input(prof, idx, ist2(payload, len), &err) < 0) {
		ha_memset_s(payload, 0, strlen(payload));
		return cli_dynerr(appctx, memprintf(&err, "Invalid input: %s.\n", err));
	}
	ha_memset_s(payload, 0, strlen(payload));

	detail = ist(prof->fetch.source->inputs[idx]);
	TRACE_USER("input updated from the CLI", CLOUDAUTH_EV_CRED, NULL, prof, &detail);
	send_log(NULL, LOG_NOTICE, "cloudauth: profile '%s': input '%s' updated from the CLI.\n",
	         prof->name, prof->fetch.source->inputs[idx]);

	cloudauth_fetch_now(prof, 0);
	return cli_msg(appctx, LOG_INFO, "Input updated.\n");
}

/* Parses "update cloudauth credential <profile>", which fetches the credential
 * of the profile at once from its token source, even if it is still valid.
 * The fetch is asynchronous, its result is reported by "show cloudauth".
 */
static int cli_parse_update_cloudauth_credential(char **args, char *payload, struct appctx *appctx, void *private)
{
	struct cloudauth_profile *prof;

	if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
		return 1;

	if (!*args[3])
		return cli_err(appctx, "Missing profile name.\n");
	prof = cloudauth_find_profile(args[3]);
	if (!prof)
		return cli_err(appctx, "No such cloudauth profile.\n");
	if (prof->token_src != CLOUDAUTH_SRC_FETCH)
		return cli_err(appctx, "The credential of this profile is not fetched by HAProxy.\n");
	if (HA_ATOMIC_LOAD(&prof->fetch.state) != CLOUDAUTH_FETCH_IDLE)
		return cli_msg(appctx, LOG_INFO, "A fetch is already in progress.\n");

	TRACE_USER("fetch requested from the CLI", CLOUDAUTH_EV_FETCH, NULL, prof);
	cloudauth_fetch_now(prof, 1);
	return cli_msg(appctx, LOG_INFO, "Fetch requested, see \"show cloudauth\" for its result.\n");
}

/* Parses "set cloudauth credential <profile> [expires-in <delay> | expires-at <date>]"
 * with the credential passed as payload. The payload is never echoed.
 */
static int cli_parse_set_cloudauth_credential(char **args, char *payload, struct appctx *appctx, void *private)
{
	struct cloudauth_profile *prof;
	struct ist detail;
	unsigned int expire = 0;
	unsigned int delay;
	const char *res;
	char *err = NULL;
	char *end;
	size_t len;
	ullong val;

	if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
		return 1;

	if (!*args[3])
		return cli_err(appctx, "Missing profile name.\n");
	prof = cloudauth_find_profile(args[3]);
	if (!prof)
		return cli_err(appctx, "No such cloudauth profile.\n");
	if (prof->token_src == CLOUDAUTH_SRC_FETCH)
		return cli_err(appctx, "The credential of this profile is fetched by HAProxy.\n");

	if (*args[4]) {
		if (!*args[5] || *args[6])
			return cli_err(appctx, "Expects 'expires-in <delay>' or 'expires-at <date>' after the profile name.\n");

		if (strcmp(args[4], "expires-in") == 0) {
			res = parse_time_err(args[5], &delay, TIME_UNIT_S);
			if (res == PARSE_TIME_OVER)
				return cli_err(appctx, "Invalid delay, too large.\n");
			if (res == PARSE_TIME_UNDER || (!res && !delay))
				return cli_err(appctx, "Invalid delay, it must be at least one second.\n");
			if (res)
				return cli_err(appctx, "Invalid delay, expects a number of seconds or a time with a unit (ms, s, m, h, d).\n");
			val = date.tv_sec;
			val += delay;
		}
		else if (strcmp(args[4], "expires-at") == 0) {
			errno = 0;
			val = strtoull(args[5], &end, 10);
			if (errno || *end || !val)
				return cli_err(appctx, "Invalid date, expects a number of seconds since the Epoch.\n");
		}
		else
			return cli_err(appctx, "Expects 'expires-in <delay>' or 'expires-at <date>' after the profile name.\n");

		if (val > UINT_MAX)
			return cli_err(appctx, "Invalid expiration, too far in the future.\n");
		if (val <= date.tv_sec)
			return cli_err(appctx, "Invalid expiration, the credential would already be expired.\n");
		expire = val;
	}

	if (!payload)
		return cli_err(appctx, "Missing credential, it must be passed as payload ('<<').\n");

	len = strlen(payload);
	while (len > 0 && isspace((unsigned char)payload[len - 1]))
		len--;

	if (cloudauth_set_token(prof, ist2(payload, len), expire, &err) < 0) {
		ha_memset_s(payload, 0, strlen(payload));
		return cli_dynerr(appctx, memprintf(&err, "Invalid credential: %s.\n", err));
	}
	ha_memset_s(payload, 0, strlen(payload));

	HA_RWLOCK_RDLOCK(OTHER_LOCK, &prof->lock);
	expire = prof->cred.expire;
	HA_RWLOCK_RDUNLOCK(OTHER_LOCK, &prof->lock);
	chunk_reset(&trash);
	cloudauth_append_date(&trash, expire);
	detail = expire ? ist2(trash.area, trash.data) : ist("never");
	TRACE_USER("credential updated from the CLI, expires", CLOUDAUTH_EV_CRED, NULL, prof, &detail);
	send_log(NULL, LOG_NOTICE, "cloudauth: profile '%s': credential updated from the CLI, expires: %s.\n",
	         prof->name, expire ? trash.area : "never");
	return cli_msg(appctx, LOG_INFO, "Credential updated.\n");
}

/* Task reporting the expiration of the credential of a profile. It wakes up
 * at the expiration date, and is woken up when the credential is replaced.
 */
static struct task *cloudauth_expire_task(struct task *t, void *context, unsigned int state)
{
	struct cloudauth_profile *prof = context;
	unsigned int expire;
	int report = 0;

	TRACE_ENTER(CLOUDAUTH_EV_CRED, NULL, prof);

	HA_RWLOCK_WRLOCK(OTHER_LOCK, &prof->lock);
	expire = prof->cred.expire;
	if (__cloudauth_cred_state(prof) == CLOUDAUTH_CRED_EXPIRED && !prof->cred.expired_reported) {
		prof->cred.expired_reported = 1;
		report = 1;
	}
	HA_RWLOCK_WRUNLOCK(OTHER_LOCK, &prof->lock);

	if (report) {
		TRACE_ERROR("credential expired", CLOUDAUTH_EV_CRED, NULL, prof);
		send_log(NULL, LOG_WARNING, "cloudauth: profile '%s': credential expired, the requests cannot be authenticated anymore.\n",
		         prof->name);
	}

	/* wake up at the expiration date, at least once a day to stay in the
	 * ticks range.
	 */
	if (expire && expire > date.tv_sec)
		t->expire = tick_add(now_ms, MS_TO_TICKS(MIN(expire - (unsigned int)date.tv_sec, 86400U) * 1000U));
	else
		t->expire = TICK_ETERNITY;
	TRACE_LEAVE(CLOUDAUTH_EV_CRED, NULL, prof);
	return t;
}

/* Starts the expiration tasks of the profiles and reports the profiles which
 * cannot authenticate the requests on startup.
 */
static int cloudauth_post_check(void)
{
	struct cloudauth_profile *prof;

	list_for_each_entry(prof, &cloudauth_profiles, list) {
		switch (cloudauth_cred_state(prof)) {
		case CLOUDAUTH_CRED_MISSING:
			/* the fetched ones are reported once fetched */
			if (prof->token_src == CLOUDAUTH_SRC_FETCH)
				break;
			ha_notice("cloudauth: profile '%s': no credential yet, it must be injected from the CLI.\n",
			          prof->name);
			break;
		case CLOUDAUTH_CRED_EXPIRED:
			ha_warning("cloudauth: profile '%s': the credential is already expired.\n", prof->name);
			prof->cred.expired_reported = 1;
			break;
		case CLOUDAUTH_CRED_VALID:
			break;
		}

		prof->expire_task = task_new_anywhere();
		if (!prof->expire_task) {
			ha_alert("cloudauth: profile '%s': out of memory.\n", prof->name);
			return ERR_ALERT | ERR_FATAL;
		}
		prof->expire_task->process = cloudauth_expire_task;
		prof->expire_task->context = prof;
		task_wakeup(prof->expire_task, TASK_WOKEN_INIT);
	}

	/* the configuration is parsed, the secrets are not needed anymore in
	 * the environment.
	 */
	cloudauth_scrub_secret_envs();
	return ERR_NONE;
}

/* Releases all the profiles on exit */
static void cloudauth_deinit(void)
{
	struct cloudauth_profile *prof, *back;

	list_for_each_entry_safe(prof, back, &cloudauth_profiles, list) {
		LIST_DELETE(&prof->list);
		cloudauth_free_profile(prof);
	}
	cloudauth_scrub_secret_envs();
}

static struct cfg_kw_list cfg_kws = { ILH, {
	{ CFG_CLOUDAUTH, "fetch-max-backoff", cfg_parse_cloudauth_fetch_delay },
	{ CFG_CLOUDAUTH, "fetch-refresh",     cfg_parse_cloudauth_fetch_delay },
	{ CFG_CLOUDAUTH, "fetch-timeout",     cfg_parse_cloudauth_fetch_delay },
	{ CFG_CLOUDAUTH, "input",             cfg_parse_cloudauth_input },
	{ CFG_CLOUDAUTH, "provider",          cfg_parse_cloudauth_provider },
	{ CFG_CLOUDAUTH, "region",            cfg_parse_cloudauth_region },
	{ CFG_CLOUDAUTH, "signer",            cfg_parse_cloudauth_signer },
	{ CFG_CLOUDAUTH, "token",             cfg_parse_cloudauth_token },
	{ CFG_CLOUDAUTH, "token-endpoint",    cfg_parse_cloudauth_token_endpoint },
	{ CFG_CLOUDAUTH, "token-scopes",      cfg_parse_cloudauth_token_scopes },
	{ 0, NULL, NULL },
}};

INITCALL1(STG_REGISTER, cfg_register_keywords, &cfg_kws);

static struct srv_kw_list srv_kws = { "CLOUDAUTH", { }, {
	{ "cloudauth", srv_parse_cloudauth, 1, 0, 1 }, /* credential profile used to authenticate the requests */
	{ NULL, NULL, 0, 0, 0 },
}};

INITCALL1(STG_REGISTER, srv_register_keywords, &srv_kws);

static struct cli_kw_list cli_kws = {{ }, {
	{ { "show", "cloudauth", NULL }, "show cloudauth [<profile>]              : show the state of the cloudauth credential profiles",
	  cli_parse_show_cloudauth, cli_io_handler_show_cloudauth, NULL, NULL, 0 },
	{ { "set", "cloudauth", "credential", NULL }, "set cloudauth credential <profile> [...] : set the credential of a cloudauth profile (payload)",
	  cli_parse_set_cloudauth_credential, NULL, NULL, NULL, 0 },
	{ { "set", "cloudauth", "input", NULL },      "set cloudauth input <profile> <name>     : set an input of a cloudauth profile (payload)",
	  cli_parse_set_cloudauth_input, NULL, NULL, NULL, 0 },
	{ { "update", "cloudauth", "credential", NULL }, "update cloudauth credential <profile>    : fetch the credential of a cloudauth profile now",
	  cli_parse_update_cloudauth_credential, NULL, NULL, NULL, 0 },
	{ { NULL }, NULL, NULL, NULL }
}};

INITCALL1(STG_REGISTER, cli_register_kw, &cli_kws);
REGISTER_POST_SERVER_CHECK(cloudauth_srv_postcheck);
REGISTER_CONFIG_SECTION("cloudauth", cfg_parse_cloudauth, cfg_postsection_cloudauth);
REGISTER_POST_CHECK(cloudauth_post_check);
REGISTER_POST_DEINIT(cloudauth_deinit);
