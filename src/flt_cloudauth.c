/*
 * Cloud storage request authentication filter.
 *
 * Copyright 2026 Aleksandar Lazic <al-haproxy@none.at>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 * The requests passing through a backend using the filter are authenticated
 * with the credential profile of the filter instance, in the 'http_headers'
 * filter callback of the request, once all the HTTP rules were evaluated:
 *
 *    filter-config cloudauth enabled profile <name> host <host>
 *
 * The signature only depends on the profile and on the Host header, which is
 * set by the filter, so it remains valid for every server of the backend, on
 * redispatches and L7 retries too.
 */

#include <ctype.h>

#include <haproxy/api.h>
#include <haproxy/filters.h>
#include <haproxy/global.h>
#include <haproxy/http_ana.h>
#include <haproxy/htx.h>
#include <haproxy/proxy.h>
#include <haproxy/sample.h>
#include <haproxy/stream.h>
#include <haproxy/tools.h>
#include <haproxy/vars.h>

#include <cloudauth/cloudauth.h>

static const char *cloudauth_filter_cls_name = "cloudauth";
static const char *cloudauth_flt_id = "cloudauth filter";

static struct filter_class flt_cloudauth_cls;

/* Releases the filter configuration <conf>, which may be NULL or partially
 * filled.
 */
static void cloudauth_flt_free_conf(struct cloudauth_flt_conf *conf)
{
	if (!conf)
		return;
	ha_free(&conf->profile_name);
	ha_free(&conf->host);
	free(conf);
}

/* Returns non-zero if <host> is a valid host name, possibly followed by a port
 * or made of an IPv6 address between brackets. It only checks the characters,
 * the storage rejects the requests sent to an unknown host anyway.
 */
static int cloudauth_flt_valid_host(const char *host)
{
	const char *p;

	if (!*host)
		return 0;
	for (p = host; *p; p++) {
		if (isalnum((unsigned char)*p))
			continue;
		if (!strchr(".-:[]", *p))
			return 0;
	}
	return 1;
}

/* Stores the reason why the request could not be authenticated with profile
 * <prof> in the "txn.cloudauth.error" variable of stream <s>, so that it may
 * be logged. It never contains the credential.
 */
static void cloudauth_set_error(struct stream *s, const struct cloudauth_profile *prof,
                                const char *reason)
{
	struct buffer *msg = get_trash_chunk();
	struct sample smp;

	chunk_printf(msg, "profile '%s' : %s", prof->name, reason);

	memset(&smp, 0, sizeof(smp));
	smp_set_owner(&smp, s->be, s->sess, s, SMP_OPT_FINAL);
	smp.data.type = SMP_T_STR;
	smp.data.u.str = *msg;
	vars_set_by_name("txn.cloudauth.error", strlen("txn.cloudauth.error"), &smp);
}

/* Resolves the profile of the filter configuration <fconf> of proxy <px> and
 * checks the proxy may use the filter. Returns the number of errors.
 */
static int cloudauth_flt_check(struct proxy *px, struct flt_conf *fconf)
{
	struct cloudauth_flt_conf *conf = fconf->conf;

	if (px->mode != PR_MODE_HTTP) {
		ha_alert("config : proxy '%s' : the cloudauth filter requires an HTTP proxy.\n", px->id);
		return 1;
	}
	if (!(px->cap & PR_CAP_BE)) {
		ha_alert("config : proxy '%s' : the cloudauth filter may only be used in a backend.\n", px->id);
		return 1;
	}

	conf->profile = cloudauth_find_profile(conf->profile_name);
	if (!conf->profile) {
		ha_alert("config : proxy '%s' : unknown cloudauth profile '%s'.\n", px->id, conf->profile_name);
		return 1;
	}
	return 0;
}

/* Releases the filter configuration <fconf> of proxy <px> */
static void cloudauth_flt_deinit(struct proxy *px, struct flt_conf *fconf)
{
	cloudauth_flt_free_conf(fconf->conf);
	fconf->conf = NULL;
}

static int cloudauth_flt_attach(struct stream *s, struct filter *filter)
{
	/* Only HTTP streams are concerned */
	if (!IS_HTX_STRM(s))
		return 0;
	return 1;
}

/* Authenticates the request once its headers were analyzed. On failure, the
 * request is rejected with a 503 before any connection to a server. Returns 1
 * on success, otherwise -1.
 */
static int cloudauth_flt_http_headers(struct stream *s, struct filter *filter,
                                      struct http_msg *msg)
{
	struct cloudauth_flt_conf *conf = FLT_CONF(filter);
	struct htx *htx = htxbuf(&msg->chn->buf);
	const char *reason;

	if (msg->chn->flags & CF_ISRESP)
		return 1;

	if (cloudauth_authenticate(conf->profile, ist(conf->host), s, htx, &reason) < 0) {
		cloudauth_count_request(s->be, 1);
		cloudauth_set_error(s, conf->profile, reason);
		if (!(s->flags & SF_ERR_MASK))
			s->flags |= SF_ERR_INTERNAL;
		/* When a filter fails with a status set, HAProxy closes the
		 * stream without any response, so the error message is sent
		 * here. It is already forwarded once HAProxy closes the stream.
		 */
		s->txn.http->status = 503;
		http_reply_and_close(s, s->txn.http->status, http_error_message(s));
		return -1;
	}
	cloudauth_count_request(s->be, 0);
	return 1;
}

static struct flt_ops cloudauth_flt_ops = {
	.check        = cloudauth_flt_check,
	.deinit       = cloudauth_flt_deinit,
	.attach       = cloudauth_flt_attach,
	.http_headers = cloudauth_flt_http_headers,
};

/* Parses the arguments of a "cloudauth" filter instance of proxy <px> :
 *    filter-config cloudauth [enabled] profile <name> host <host>
 * Returns 0 on success, < 0 on error with <err> filled.
 */
static int cloudauth_flt_parse_instance(char **args, struct proxy *px,
                                        struct filter_instance *inst, char **err)
{
	struct cloudauth_flt_conf *conf;
	int cur_arg = 0;

	if (!experimental_directives_allowed) {
		memprintf(err, "'filter-config %s' is experimental, must be allowed via a global 'expose-experimental-directives'",
		          cloudauth_filter_cls_name);
		return -1;
	}
	mark_tainted(TAINTED_CONFIG_EXP_KW_DECLARED);

	conf = calloc(1, sizeof(*conf));
	if (!conf)
		goto oom;

	while (args[cur_arg] && *args[cur_arg]) {
		if (strcmp(args[cur_arg], "profile") == 0) {
			if (!args[cur_arg + 1] || !*args[cur_arg + 1]) {
				memprintf(err, "'filter-config %s' : '%s' expects a cloudauth profile name",
				          cloudauth_filter_cls_name, args[cur_arg]);
				goto error;
			}
			free(conf->profile_name);
			conf->profile_name = strdup(args[cur_arg + 1]);
			if (!conf->profile_name)
				goto oom;
		}
		else if (strcmp(args[cur_arg], "host") == 0) {
			if (!args[cur_arg + 1] || !cloudauth_flt_valid_host(args[cur_arg + 1])) {
				memprintf(err, "'filter-config %s' : '%s' expects a host name",
				          cloudauth_filter_cls_name, args[cur_arg]);
				goto error;
			}
			free(conf->host);
			conf->host = strdup(args[cur_arg + 1]);
			if (!conf->host)
				goto oom;
		}
		else {
			memprintf(err, "'filter-config %s' : unknown keyword '%s'",
			          cloudauth_filter_cls_name, args[cur_arg]);
			goto error;
		}
		cur_arg += 2;
	}

	if (!conf->profile_name) {
		memprintf(err, "'filter-config %s' : missing 'profile <name>'", cloudauth_filter_cls_name);
		goto error;
	}

	/* The Host header of the client must never select the storage account
	 * or bucket, so the host is mandatory.
	 */
	if (!conf->host) {
		memprintf(err, "'filter-config %s' : missing 'host <host>'", cloudauth_filter_cls_name);
		goto error;
	}

	inst->fconf->id    = cloudauth_flt_id;
	inst->fconf->ops   = &cloudauth_flt_ops;
	inst->fconf->conf  = conf;
	inst->fconf->flags |= FLT_CFG_FL_HTX;
	return 0;

  oom:
	memprintf(err, "'filter-config %s' : out of memory", cloudauth_filter_cls_name);
  error:
	cloudauth_flt_free_conf(conf);
	return -1;
}

/* Registers the filter class. The requests are authenticated after all the
 * other filters, which may still change them, so the class is placed after the
 * last built-in one on the request side. It does not process the responses.
 * The functions of the filter API report their own failures.
 */
static void cloudauth_flt_register_class(void)
{
	if (filter_register_class(&flt_cloudauth_cls, cloudauth_filter_cls_name,
	                          cloudauth_flt_parse_instance) < 0)
		return;
	filter_place_class(&flt_cloudauth_cls, FLT_SIDE_REQ, "fcgi", FLT_POS_AFTER);
}

INITCALL0(STG_REGISTER, cloudauth_flt_register_class);
REGISTER_BUILD_OPTS("Built with the cloudauth filter.");
