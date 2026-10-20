/*
 * Cloud storage authentication: fetching of the credentials.
 *
 * Copyright 2026 Aleksandar Lazic <al-haproxy@none.at>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 * The credentials of the profiles using a token source of their provider
 * ("token <source>") are fetched by HAProxy with the HTTP client, then
 * refreshed before they expire. Each such profile has its own task, which
 * sends one request at a time and retries with an exponential backoff on
 * failure. The requests and the responses carry secrets, so their buffers are
 * wiped before being released, and they are never logged.
 */

#include <haproxy/api.h>
#include <haproxy/chunk.h>
#include <haproxy/clock.h>
#include <haproxy/errors.h>
#include <haproxy/http_client.h>
#include <haproxy/log.h>
#include <haproxy/task.h>
#include <haproxy/ticks.h>
#include <haproxy/tools.h>
#include <haproxy/trace.h>

#include <cloudauth/cloudauth.h>
#include <cloudauth/cloudauth_common.h>
#include <cloudauth/cloudauth_trace.h>

/* The proxy of the HTTP client, only created if a profile fetches its
 * credential.
 */
static struct proxy *cloudauth_fetch_px;

/* Appends to the request <req> the header <name>, which must be a constant,
 * with the value <value>, which is copied. Returns 0 on success, -1 if there
 * is no more room.
 */
int cloudauth_fetch_add_hdr(struct cloudauth_fetch_req *req, const struct ist name, const struct ist value)
{
	char *v = b_tail(req->values);

	if (req->nb_hdrs == CLOUDAUTH_FETCH_MAX_HDRS)
		return -1;
	if (!chunk_istcat(req->values, value))
		return -1;
	req->hdrs[req->nb_hdrs].n = name;
	req->hdrs[req->nb_hdrs].v = ist2(v, istlen(value));
	req->nb_hdrs++;
	return 0;
}

/* Called by the HTTP client at the end of the response, or when the request
 * failed, possibly from another thread.
 */
static void cloudauth_fetch_end(struct httpclient *hc)
{
	struct cloudauth_profile *prof = hc->caller;

	/* the profile is being released */
	if (!prof)
		return;

	TRACE_ENTER(CLOUDAUTH_EV_FETCH, NULL, prof);
	BUG_ON(HA_ATOMIC_LOAD(&prof->fetch.state) != CLOUDAUTH_FETCH_SENT,
	       "the end of a cloudauth fetch was reported without a request in progress");
	HA_ATOMIC_STORE(&prof->fetch.state, CLOUDAUTH_FETCH_ENDED);
	task_wakeup(prof->fetch.task, TASK_WOKEN_MSG);
	TRACE_LEAVE(CLOUDAUTH_EV_FETCH, NULL, prof);
}

/* Wipes the buffers of the HTTP client <hc>, which may carry secrets */
static void cloudauth_fetch_wipe(struct httpclient *hc)
{
	if (hc->req.buf.size)
		ha_memset_s(hc->req.buf.area, 0, hc->req.buf.size);
	if (hc->res.buf.size)
		ha_memset_s(hc->res.buf.area, 0, hc->res.buf.size);
}

/* Wipes and releases the chunks of the request <req> */
static void cloudauth_fetch_req_release(struct cloudauth_fetch_req *req)
{
	struct buffer *chunks[3] = { req->url, req->body, req->values };
	int i;

	for (i = 0; i < 3; i++) {
		if (chunks[i])
			ha_memset_s(chunks[i]->area, 0, chunks[i]->size);
		free_trash_chunk(chunks[i]);
	}
}

/* Wipes and releases what the previous request of the fetch in progress of
 * profile <prof> kept for the next one, which may be a secret.
 */
static void cloudauth_fetch_free_carry(struct cloudauth_profile *prof)
{
	if (prof->fetch.carry)
		ha_memset_s(prof->fetch.carry->area, 0, prof->fetch.carry->size);
	free_trash_chunk(prof->fetch.carry);
	prof->fetch.carry = NULL;
}

/* Ends the fetch in progress of profile <prof>, successful or not: what its
 * requests kept is released, and the next fetch starts with the first
 * request.
 */
static void cloudauth_fetch_end_steps(struct cloudauth_profile *prof)
{
	cloudauth_fetch_free_carry(prof);
	prof->fetch.step = 0;
}

/* Copies into <req> the inputs of the token source of profile <prof>, which
 * must all be valid. Returns 0 on success, otherwise -1 with <err> filled.
 */
static int cloudauth_fetch_copy_inputs(struct cloudauth_profile *prof, struct cloudauth_fetch_req *req, char **err)
{
	const char * const *inputs = prof->fetch.source->inputs;
	const struct cloudauth_input *in;
	const char *reason = NULL;
	char *v;
	int i;

	if (!inputs)
		return 0;

	HA_RWLOCK_RDLOCK(OTHER_LOCK, &prof->lock);
	for (i = 0; inputs[i]; i++) {
		in = &prof->inputs[i];
		if (!isttest(in->value)) {
			reason = "is missing";
			break;
		}
		if (in->expire && in->expire <= (unsigned int)date.tv_sec) {
			reason = "expired";
			break;
		}
		v = b_tail(req->values);
		if (!chunk_istcat(req->values, in->value)) {
			reason = "does not fit in a buffer";
			break;
		}
		req->inputs[i] = ist2(v, istlen(in->value));
	}
	HA_RWLOCK_RDUNLOCK(OTHER_LOCK, &prof->lock);

	if (reason) {
		memprintf(err, "the input '%s' %s", inputs[i], reason);
		return -1;
	}
	return 0;
}

/* Sends the request fetching the credential of profile <prof>. Returns 0 on
 * success, otherwise -1 with <err> filled.
 */
static int cloudauth_fetch_send(struct cloudauth_profile *prof, char **err)
{
	struct cloudauth_fetch_req req = { .meth = HTTP_METH_GET };
	struct httpclient *hc = NULL;
	struct ist source, payload;
	int ret = -1;

	TRACE_ENTER(CLOUDAUTH_EV_FETCH, NULL, prof);

	/* only one request at a time */
	BUG_ON(prof->fetch.hc);

	req.url = alloc_trash_chunk();
	if (!req.url)
		goto oom;
	req.body = alloc_trash_chunk();
	if (!req.body)
		goto oom;
	req.values = alloc_trash_chunk();
	if (!req.values)
		goto oom;

	if (cloudauth_fetch_copy_inputs(prof, &req, err) < 0)
		goto out;
	if (prof->fetch.source->request(prof, &req, err) < 0)
		goto out;

	hc = httpclient_new_from_proxy(cloudauth_fetch_px, prof, req.meth, ist2(req.url->area, req.url->data));
	if (!hc)
		goto oom;
	/* without payload, the request is bodyless instead of being sent with an
	 * empty chunked payload
	 */
	payload = b_data(req.body) ? ist2(req.body->area, req.body->data) : IST_NULL;
	if (httpclient_req_gen(hc, hc->req.url, hc->req.meth, req.hdrs, payload) != ERR_NONE) {
		memprintf(err, "cannot build the request");
		goto out;
	}

	/* the response is only parsed once complete */
	hc->options |= HTTPCLIENT_O_RES_ACCUM;
	hc->ops.res_end = cloudauth_fetch_end;
	httpclient_set_timeout(hc, prof->fetch.timeout);

	prof->fetch.hc = hc;
	HA_ATOMIC_STORE(&prof->fetch.state, CLOUDAUTH_FETCH_SENT);
	if (!httpclient_start(hc)) {
		HA_ATOMIC_STORE(&prof->fetch.state, CLOUDAUTH_FETCH_IDLE);
		prof->fetch.hc = NULL;
		memprintf(err, "cannot start the HTTP client");
		goto out;
	}
	source = ist(prof->fetch.source->name);
	TRACE_USER("credential requested from the token source", CLOUDAUTH_EV_FETCH, NULL, prof, &source);
	hc = NULL;
	ret = 0;
	goto out;

  oom:
	memprintf(err, "out of memory");
  out:
	if (hc) {
		cloudauth_fetch_wipe(hc);
		httpclient_destroy(hc);
	}
	cloudauth_fetch_req_release(&req);
	if (ret < 0)
		TRACE_DEVEL("leaving on error", CLOUDAUTH_EV_FETCH, NULL, prof);
	else
		TRACE_LEAVE(CLOUDAUTH_EV_FETCH, NULL, prof);
	return ret;
}

/* Records the successful fetch of the credential of profile <prof>, and
 * schedules its refresh once half of its lifetime has elapsed. The first fetch
 * and the first one after failures are logged.
 */
static void cloudauth_fetch_success(struct cloudauth_profile *prof)
{
	char str[CLOUDAUTH_ISO_DATE_SIZE];
	struct ist detail;
	unsigned int now = date.tv_sec;
	unsigned int expire, failures;
	int fetched;

	cloudauth_fetch_end_steps(prof);

	HA_RWLOCK_WRLOCK(OTHER_LOCK, &prof->lock);
	expire = prof->cred.expire;
	failures = prof->fetch.failures;
	fetched = prof->fetch.fetched;
	prof->fetch.failures = 0;
	prof->fetch.fetched = 1;
	prof->fetch.error[0] = 0;
	if (!expire)
		prof->fetch.next = now + prof->fetch.refresh;
	else if (expire > now)
		prof->fetch.next = now + MAX((expire - now) / 2, 1U);
	else
		prof->fetch.next = now + 1;
	HA_RWLOCK_WRUNLOCK(OTHER_LOCK, &prof->lock);

	if (!expire)
		strlcpy2(str, "unknown", sizeof(str));
	else if (!cloudauth_iso_date(expire, str, sizeof(str)))
		strlcpy2(str, "unknown", sizeof(str));
	detail = ist(str);
	TRACE_USER("credential fetched, expires", CLOUDAUTH_EV_FETCH, NULL, prof, &detail);

	if (fetched && !failures)
		return;

	send_log(NULL, LOG_NOTICE, "cloudauth: profile '%s': credential fetched from '%s', expires: %s.\n",
	         prof->name, prof->fetch.source->name, str);
}

/* Records the failure <err> to fetch the credential of profile <prof>, and
 * schedules a new attempt with an exponential backoff: after 1 second, then
 * after a delay doubled each time, up to the maximum backoff of the profile.
 * Only the first failure of a series is logged.
 */
static void cloudauth_fetch_failure(struct cloudauth_profile *prof, const char *err)
{
	unsigned int failures, delay;
	struct ist detail;

	cloudauth_fetch_end_steps(prof);
	if (!err)
		err = "unknown error";
	detail = ist(err);
	TRACE_ERROR("cannot fetch the credential", CLOUDAUTH_EV_FETCH, NULL, prof, &detail);

	HA_RWLOCK_WRLOCK(OTHER_LOCK, &prof->lock);
	failures = ++prof->fetch.failures;
	/* 2^31 seconds is more than any maximum backoff */
	delay = MIN(1U << MIN(failures - 1, 31U), prof->fetch.max_backoff);
	prof->fetch.next = (unsigned int)date.tv_sec + delay;
	strlcpy2(prof->fetch.error, err, sizeof(prof->fetch.error));
	HA_RWLOCK_WRUNLOCK(OTHER_LOCK, &prof->lock);

	if (failures == 1)
		send_log(NULL, LOG_WARNING, "cloudauth: profile '%s': cannot fetch the credential from '%s': %s, retrying in %us.\n",
		         prof->name, prof->fetch.source->name, err, delay);
}

/* Processes the end of the request fetching the credential of profile <prof>,
 * then releases the HTTP client.
 */
static void cloudauth_fetch_done(struct cloudauth_profile *prof)
{
	struct httpclient *hc = prof->fetch.hc;
	struct buffer *token;
	unsigned int expire = 0;
	char *err = NULL;
	char str[16];
	struct ist detail;
	int status, ret = -1;

	TRACE_ENTER(CLOUDAUTH_EV_FETCH, NULL, prof);
	BUG_ON(!hc);

	token = alloc_trash_chunk();
	if (!token) {
		memprintf(&err, "out of memory");
		goto out;
	}

	/* the HTTP client reports a failed request with a null status */
	if (!hc->res.status) {
		memprintf(&err, "no response from the token endpoint");
		goto out;
	}
	status = hc->res.status;
	TRACE_PROTO("response of the token endpoint", CLOUDAUTH_EV_FETCH, NULL, prof, NULL, &status);
	ret = prof->fetch.source->response(prof, hc->res.status, &hc->res.buf, token, &expire, &err);
	if (ret < 0)
		goto out;
	if (ret > 0) {
		/* another request is needed, <token> is kept for it */
		if (prof->fetch.step + 1 >= CLOUDAUTH_FETCH_MAX_STEPS) {
			memprintf(&err, "the token source needs more than %d requests", CLOUDAUTH_FETCH_MAX_STEPS);
			ret = -1;
			goto out;
		}
		cloudauth_fetch_free_carry(prof);
		prof->fetch.carry = token;
		token = NULL;
		prof->fetch.step++;
		goto out;
	}
	ret = -1;
	if (cloudauth_set_token(prof, ist2(token->area, token->data), expire, &err) < 0)
		goto out;
	ret = 0;

  out:
	if (token)
		ha_memset_s(token->area, 0, token->size);
	free_trash_chunk(token);
	cloudauth_fetch_wipe(hc);
	httpclient_destroy(hc);
	prof->fetch.hc = NULL;
	HA_ATOMIC_STORE(&prof->fetch.state, CLOUDAUTH_FETCH_IDLE);

	if (ret > 0) {
		/* the task sends the next request at once */
		snprintf(str, sizeof(str), "%d", prof->fetch.step);
		detail = ist(str);
		TRACE_STATE("next request of the fetch", CLOUDAUTH_EV_FETCH, NULL, prof, &detail);
		HA_RWLOCK_WRLOCK(OTHER_LOCK, &prof->lock);
		prof->fetch.next = date.tv_sec;
		HA_RWLOCK_WRUNLOCK(OTHER_LOCK, &prof->lock);
	}
	else if (ret == 0)
		cloudauth_fetch_success(prof);
	else
		cloudauth_fetch_failure(prof, err);
	free(err);
	if (ret < 0)
		TRACE_DEVEL("leaving on error", CLOUDAUTH_EV_FETCH, NULL, prof);
	else
		TRACE_LEAVE(CLOUDAUTH_EV_FETCH, NULL, prof);
}

/* The task fetching the credential of the profile <context>, then refreshing
 * it. It processes the end of the request in progress if any, then sends a new
 * one when it is time to.
 */
static struct task *cloudauth_fetch_task(struct task *t, void *context, unsigned int state)
{
	struct cloudauth_profile *prof = context;
	unsigned int next;
	char *err = NULL;

	TRACE_ENTER(CLOUDAUTH_EV_FETCH, NULL, prof);

	switch (HA_ATOMIC_LOAD(&prof->fetch.state)) {
	case CLOUDAUTH_FETCH_SENT:
		/* the end of the request wakes the task up */
		t->expire = TICK_ETERNITY;
		TRACE_LEAVE(CLOUDAUTH_EV_FETCH, NULL, prof);
		return t;
	case CLOUDAUTH_FETCH_ENDED:
		cloudauth_fetch_done(prof);
		break;
	case CLOUDAUTH_FETCH_IDLE:
		break;
	}

	HA_RWLOCK_RDLOCK(OTHER_LOCK, &prof->lock);
	next = prof->fetch.next;
	HA_RWLOCK_RDUNLOCK(OTHER_LOCK, &prof->lock);

	if ((unsigned int)date.tv_sec >= next) {
		if (cloudauth_fetch_send(prof, &err) == 0) {
			t->expire = TICK_ETERNITY;
			TRACE_LEAVE(CLOUDAUTH_EV_FETCH, NULL, prof);
			return t;
		}
		cloudauth_fetch_failure(prof, err);
		ha_free(&err);

		HA_RWLOCK_RDLOCK(OTHER_LOCK, &prof->lock);
		next = prof->fetch.next;
		HA_RWLOCK_RDUNLOCK(OTHER_LOCK, &prof->lock);
	}

	/* at least once a day to stay in the ticks range */
	t->expire = tick_add(now_ms, MS_TO_TICKS(MIN(next - (unsigned int)date.tv_sec, 86400U) * 1000U));
	TRACE_LEAVE(CLOUDAUTH_EV_FETCH, NULL, prof);
	return t;
}

/* Requests a new fetch of the credential of profile <prof> now if <force> is
 * set, or if the credential is not valid or the last fetch failed, for
 * instance once one of its inputs was updated. A request in progress is not
 * interrupted, the next one being scheduled once it ends.
 */
void cloudauth_fetch_now(struct cloudauth_profile *prof, int force)
{
	enum cloudauth_cred_state state = cloudauth_cred_state(prof);
	int wakeup = 0;

	if (!prof->fetch.task)
		return;

	HA_RWLOCK_WRLOCK(OTHER_LOCK, &prof->lock);
	if (force || state != CLOUDAUTH_CRED_VALID || prof->fetch.failures) {
		prof->fetch.next = date.tv_sec;
		wakeup = 1;
	}
	HA_RWLOCK_WRUNLOCK(OTHER_LOCK, &prof->lock);

	if (wakeup)
		task_wakeup(prof->fetch.task, TASK_WOKEN_OTHER);
}

/* Releases the fetching of the credential of profile <prof>. A request in
 * progress is stopped.
 */
void cloudauth_fetch_release(struct cloudauth_profile *prof)
{
	task_destroy(prof->fetch.task);
	prof->fetch.task = NULL;
	cloudauth_fetch_end_steps(prof);

	if (HA_ATOMIC_LOAD(&prof->fetch.state) != CLOUDAUTH_FETCH_IDLE) {
		cloudauth_fetch_wipe(prof->fetch.hc);
		httpclient_stop_and_destroy(prof->fetch.hc);
		prof->fetch.hc = NULL;
		HA_ATOMIC_STORE(&prof->fetch.state, CLOUDAUTH_FETCH_IDLE);
	}
}

/* Creates the proxy of the HTTP client if a profile fetches its credential.
 * It is done before the configuration checks, since it may create the default
 * resolvers section.
 */
static int cloudauth_fetch_pre_check(void)
{
	struct cloudauth_profile *prof;

	list_for_each_entry(prof, &cloudauth_profiles, list) {
		if (prof->token_src != CLOUDAUTH_SRC_FETCH)
			continue;

		cloudauth_fetch_px = httpclient_create_proxy("<CLOUDAUTH>");
		if (!cloudauth_fetch_px) {
			ha_alert("cloudauth: cannot initialize the HTTP client fetching the credentials.\n");
			return ERR_ALERT | ERR_FATAL;
		}
		break;
	}
	return ERR_NONE;
}

/* Starts the tasks fetching the credentials. They are shared tasks, which are
 * heavier to schedule, but they only run a few times per credential lifetime.
 */
static int cloudauth_fetch_post_check(void)
{
	struct cloudauth_profile *prof;

	list_for_each_entry(prof, &cloudauth_profiles, list) {
		if (prof->token_src != CLOUDAUTH_SRC_FETCH)
			continue;

		prof->fetch.task = task_new_anywhere();
		if (!prof->fetch.task) {
			ha_alert("cloudauth: profile '%s': out of memory.\n", prof->name);
			return ERR_ALERT | ERR_FATAL;
		}
		prof->fetch.task->process = cloudauth_fetch_task;
		prof->fetch.task->context = prof;
		task_wakeup(prof->fetch.task, TASK_WOKEN_INIT);
	}
	return ERR_NONE;
}

REGISTER_PRE_CHECK(cloudauth_fetch_pre_check);
REGISTER_POST_CHECK(cloudauth_fetch_post_check);
