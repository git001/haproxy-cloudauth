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
 * The requests sent to the servers using a credential profile (see the
 * "cloudauth" server keyword) are authenticated in the 'http_pre_send' filter
 * callback, once the server is known.
 */

#include <haproxy/api.h>
#include <haproxy/filters.h>
#include <haproxy/global.h>
#include <haproxy/http_ana.h>
#include <haproxy/http_htx.h>
#include <haproxy/htx.h>
#include <haproxy/proxy.h>
#include <haproxy/server.h>
#include <haproxy/sample.h>
#include <haproxy/stream.h>
#include <haproxy/tools.h>
#include <haproxy/vars.h>

#include <cloudauth/cloudauth.h>

const char *cloudauth_filter_cls_name = "cloudauth";
static const char *cloudauth_flt_id = "cloudauth filter";

static int cloudauth_flt_attach(struct stream *s, struct filter *filter)
{
	/* Only HTTP streams are concerned */
	if (!IS_HTX_STRM(s))
		return 0;
	return 1;
}

/* Stores the reason why the request sent to server <srv> could not be
 * authenticated in the "txn.cloudauth.error" variable of stream <s>, so that it
 * may be logged. It never contains the credential.
 */
static void cloudauth_set_error(struct stream *s, const struct server *srv, const char *reason)
{
	struct buffer *msg = get_trash_chunk();
	struct sample smp;

	chunk_printf(msg, "server '%s' profile '%s' : %s", srv->id, srv->cloudauth->profile->name, reason);

	memset(&smp, 0, sizeof(smp));
	smp_set_owner(&smp, s->be, s->sess, s, SMP_OPT_FINAL);
	smp.data.type = SMP_T_STR;
	smp.data.u.str = *msg;
	vars_set_by_name("txn.cloudauth.error", strlen("txn.cloudauth.error"), &smp);
}

/* Called just before the request is sent to the server. It is called again
 * for each new attempt, possibly for another server, so everything set for a
 * previous server is replaced.
 */
static int cloudauth_flt_http_pre_send(struct stream *s, struct filter *filter,
                                       struct http_msg *msg)
{
	struct htx *htx = htxbuf(&msg->chn->buf);
	struct server *srv = objt_server(s->target);

	if (!srv)
		return 1;

	if (cloudauth_srv_enabled(srv)) {
		const char *reason;

		if (cloudauth_authenticate(srv, s->sess, s, htx, &reason) < 0) {
			cloudauth_count_request(srv, 1);
			cloudauth_set_error(s, srv, reason);
			/* Retrying cannot fix a credential issue and would only
			 * open useless connections to the storage, so disable
			 * the connection retries, as it is done for a bad server
			 * certificate.
			 */
			s->conn_retries = s->max_retries;
			return -1;
		}
		cloudauth_count_request(srv, 0);
	}
	return 1;
}

static struct flt_ops cloudauth_flt_ops = {
	.attach        = cloudauth_flt_attach,
	.http_pre_send = cloudauth_flt_http_pre_send,
};

/* Parses the arguments of a "cloudauth" filter instance :
 *    filter-config cloudauth [enabled]
 * Returns 0 on success, < 0 on error.
 */
int cloudauth_flt_parse_instance(char **args, struct proxy *px, struct filter_instance *inst, char **err)
{
	if (!experimental_directives_allowed) {
		memprintf(err, "'filter-config %s' is experimental, must be allowed via a global 'expose-experimental-directives'",
		          cloudauth_filter_cls_name);
		return -1;
	}
	mark_tainted(TAINTED_CONFIG_EXP_KW_DECLARED);

	if (args[0] && *args[0]) {
		memprintf(err, "'filter-config %s' : unknown keyword '%s'",
		          cloudauth_filter_cls_name, args[0]);
		return -1;
	}

	inst->fconf->id    = cloudauth_flt_id;
	inst->fconf->ops   = &cloudauth_flt_ops;
	inst->fconf->flags |= FLT_CFG_FL_HTX;
	return 0;
}
