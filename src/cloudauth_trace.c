/*
 * Cloud storage authentication: traces.
 *
 * Copyright 2026 Aleksandar Lazic <al-haproxy@none.at>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 * The "cloudauth" trace source reports the authentication of the requests,
 * the client credentials removed from them, and the updates and fetches of
 * the credentials. Only metadata are reported, never the credentials, nor the
 * headers, query strings or payloads which may carry one, so that the traces
 * may be enabled in production.
 */

#include <haproxy/api.h>
#include <haproxy/chunk.h>
#include <haproxy/cloudauth-t.h>
#include <haproxy/cloudauth_trace.h>
#include <haproxy/init.h>
#include <haproxy/trace.h>

static void cloudauth_trace(enum trace_level level, uint64_t mask, const struct trace_source *src,
                            const struct ist where, const struct ist func,
                            const void *a1, const void *a2, const void *a3, const void *a4);

static const struct trace_event cloudauth_trace_events[] = {
	{ .mask = CLOUDAUTH_EV_REQ,   .name = "cloudauth_req",   .desc = "request authentication" },
	{ .mask = CLOUDAUTH_EV_STRIP, .name = "cloudauth_strip", .desc = "client credential removed" },
	{ .mask = CLOUDAUTH_EV_CRED,  .name = "cloudauth_cred",  .desc = "credential updated or expired" },
	{ .mask = CLOUDAUTH_EV_FETCH, .name = "cloudauth_fetch", .desc = "credential fetching" },
	{ }
};

static const struct name_desc cloudauth_trace_lockon_args[4] = {
	/* arg1 */ { /* already used by the stream */ },
	/* arg2 */ { .name = "profile", .desc = "credential profile" },
	/* arg3 */ { },
	/* arg4 */ { }
};

struct trace_source trace_cloudauth = {
	.name = IST("cloudauth"),
	.desc = "Cloud storage authentication",
	.arg_def = TRC_ARG1_STRM,  /* the first argument is always a stream, or NULL */
	.default_cb = cloudauth_trace,
	.known_events = cloudauth_trace_events,
	.lockon_args = cloudauth_trace_lockon_args,
	.report_events = ~0,  /* report everything by default */
};

INITCALL1(STG_REGISTER, trace_register_source, &trace_cloudauth);

/* Appends to the trace the profile <a2>, the HTTP status <a4> and the detail
 * <a3>, those which are set. They never carry a credential.
 */
static void cloudauth_trace(enum trace_level level, uint64_t mask, const struct trace_source *src,
                            const struct ist where, const struct ist func,
                            const void *a1, const void *a2, const void *a3, const void *a4)
{
	const struct cloudauth_profile *prof = a2;
	const struct ist *detail = a3;
	const int *status = a4;

	if (!prof && !status && !detail)
		return;

	chunk_appendf(&trace_buf, " :");
	if (prof)
		chunk_appendf(&trace_buf, " profile=%s", prof->name);
	if (status)
		chunk_appendf(&trace_buf, " status=%d", *status);
	if (detail && isttest(*detail))
		chunk_appendf(&trace_buf, " (%.*s)", (int)istlen(*detail), istptr(*detail));
}
