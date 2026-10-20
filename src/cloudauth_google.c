/*
 * Cloud storage authentication: Google Cloud Storage provider.
 *
 * Copyright 2026 Aleksandar Lazic <al-haproxy@none.at>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 * The requests are authenticated with an OAuth 2.0 access token (bearer), or
 * signed with an HMAC key (sigv4), only accepted by the XML API, with the
 * "GOOG4" variant of Signature Version 4. The access tokens may be fetched by HAProxy from the metadata server of Google Cloud
 * ("token metadata-server"), for the service account attached to the
 * workload: Compute Engine, GKE with or without Workload Identity, Cloud
 * Run... It may also be requested from the token endpoint of Google with an
 * assertion signed with the key of a service account ("token
 * service-account"), whose credential file is read at parse time. Finally,
 * the token of a workload identity in another identity provider, such as a
 * Kubernetes service account token, may be exchanged for an access token with
 * the Security Token Service of Google ("token workload-identity", workload
 * identity federation).
 */

#include <import/mjson.h>

#include <haproxy/api.h>
#include <haproxy/cfgparse.h>
#include <haproxy/chunk.h>
#include <haproxy/clock.h>
#include <haproxy/errors.h>
#include <haproxy/global.h>
#include <haproxy/http.h>
#include <haproxy/init.h>
#include <haproxy/tools.h>
#include <haproxy/trace.h>

#include <cloudauth/cloudauth.h>
#include <cloudauth/cloudauth_common.h>
#include <cloudauth/cloudauth_google.h>
#include <cloudauth/cloudauth_sigv4-t.h>
#include <cloudauth/cloudauth_trace.h>

/* Returns the Google settings of profile <prof> */
static inline struct cloudauth_google_ctx *cloudauth_google_ctx(const struct cloudauth_profile *prof)
{
	return prof->provider_ctx;
}

/* The variant of Signature Version 4 of Google Cloud Storage (V4 signing
 * process with an HMAC key), whose region is "auto" by default. The HMAC keys
 * have no session token.
 */
static const struct cloudauth_sigv4 cloudauth_google_sigv4 = {
	.algorithm  = "GOOG4-HMAC-SHA256",
	.key_prefix = "GOOG4",
	.hash_hdr   = IST("x-goog-content-sha256"),
	.date_hdr   = IST("x-goog-date"),
	.token_hdr  = IST_NULL,
	.service    = "storage",
	.request    = "goog4_request",
	.region     = CLOUDAUTH_GOOGLE_REGION,
};

/* Authenticates the request in <htx> of the stream <strm> with the credential
 * of profile <prof>, whose lock is held. Returns 0 on success, -1 on failure.
 */
static int cloudauth_google_sign(const struct cloudauth_profile *prof, const struct stream *strm, struct htx *htx)
{
	TRACE_ENTER(CLOUDAUTH_EV_REQ, strm, prof);

	switch (prof->signer) {
	case CLOUDAUTH_SIGNER_BEARER:
		if (cloudauth_sign_bearer(prof, htx) < 0)
			goto error;
		break;
	default:
		goto error;
	}
	TRACE_LEAVE(CLOUDAUTH_EV_REQ, strm, prof);
	return 0;

  error:
	TRACE_DEVEL("leaving on error", CLOUDAUTH_EV_REQ, strm, prof);
	return -1;
}

/* Prepares in <req> the request of a token for profile <prof> to the metadata
 * server, with the requested scopes if any, which it expects separated by
 * commas. Returns 0 on success, otherwise -1 with <err> filled.
 */
static int cloudauth_google_metadata_request(const struct cloudauth_profile *prof, struct cloudauth_fetch_req *req,
                                             char **err)
{
	const char *endpoint = prof->fetch.endpoint ? prof->fetch.endpoint : CLOUDAUTH_GOOGLE_METADATA_ENDPOINT;
	struct ist detail = ist(endpoint);
	struct ist scopes, scope;

	TRACE_ENTER(CLOUDAUTH_EV_FETCH, NULL, prof);

	/* the endpoint carries no secret */
	TRACE_STATE("metadata server endpoint", CLOUDAUTH_EV_FETCH, NULL, prof, &detail);

	if (!chunk_strcat(req->url, endpoint))
		goto full;
	if (prof->fetch.scopes) {
		if (!chunk_strcat(req->url, strchr(endpoint, '?') ? "&scopes=" : "?scopes="))
			goto full;
		scopes = ist(prof->fetch.scopes);
		while (istlen(scopes)) {
			scope = istsplit(&scopes, ' ');
			if (cloudauth_url_encode_cat(req->url, scope) < 0)
				goto full;
			/* the separator of the metadata server is a comma */
			if (istlen(scopes)) {
				if (!chunk_strcat(req->url, "%2C"))
					goto full;
			}
		}
	}

	/* without this header, the metadata server rejects the request */
	if (cloudauth_fetch_add_hdr(req, ist("metadata-flavor"), ist("Google")) < 0)
		goto full;
	TRACE_LEAVE(CLOUDAUTH_EV_FETCH, NULL, prof);
	return 0;

  full:
	memprintf(err, "the request does not fit in a buffer");
	TRACE_DEVEL("leaving on error", CLOUDAUTH_EV_FETCH, NULL, prof);
	return -1;
}

/* Returns the URL of the token endpoint to which the assertions of the service
 * account of profile <prof> are sent, which is also their audience.
 */
static const char *cloudauth_google_sa_endpoint(const struct cloudauth_profile *prof)
{
	const struct cloudauth_google_ctx *ctx = cloudauth_google_ctx(prof);

	if (prof->fetch.endpoint)
		return prof->fetch.endpoint;
	if (ctx->sa_token_uri)
		return ctx->sa_token_uri;
	return CLOUDAUTH_GOOGLE_TOKEN_ENDPOINT;
}

/* Builds into <out> the assertion of the service account of profile <prof>: a
 * JWT signed with its private key (RS256), designating the key by its
 * identifier, whose claims are its e-mail address, the requested scopes
 * separated by spaces, the token endpoint and a lifetime of one hour. Returns
 * 0 on success, otherwise -1 with <err> filled.
 */
static int cloudauth_google_sa_assertion(const struct cloudauth_profile *prof, struct buffer *out, char **err)
{
	const struct cloudauth_google_ctx *ctx = cloudauth_google_ctx(prof);
	const char *scopes = prof->fetch.scopes ? prof->fetch.scopes : CLOUDAUTH_GOOGLE_SCOPE;
	unsigned int now = date.tv_sec;
	struct buffer *header = NULL, *claims = NULL;
	int len, ret = -1;

	header = alloc_trash_chunk();
	if (!header)
		goto oom;
	claims = alloc_trash_chunk();
	if (!claims)
		goto oom;

	if (ctx->sa_key_id)
		len = chunk_printf(header, "{\"alg\":\"RS256\",\"typ\":\"JWT\",\"kid\":\"%s\"}", ctx->sa_key_id);
	else
		len = chunk_printf(header, "{\"alg\":\"RS256\",\"typ\":\"JWT\"}");
	if (len < 0)
		goto full;
	len = chunk_printf(claims, "{\"iss\":\"%s\",\"scope\":\"%s\",\"aud\":\"%s\",\"exp\":%u,\"iat\":%u}",
	                   ctx->sa_email, scopes, cloudauth_google_sa_endpoint(prof),
	                   now + CLOUDAUTH_GOOGLE_ASSERTION_LIFETIME, now);
	if (len < 0)
		goto full;

	ret = cloudauth_jwt_sign(out, ist2(header->area, header->data), ist2(claims->area, claims->data),
	                         ctx->sa_key, JWS_ALG_RS256, err);
	goto out;

  oom:
	memprintf(err, "out of memory");
	goto out;
  full:
	memprintf(err, "the assertion does not fit in a buffer");
  out:
	free_trash_chunk(claims);
	free_trash_chunk(header);
	return ret;
}

/* Prepares in <req> the request of a token for profile <prof> to the token
 * endpoint of Google, with an assertion signed with the key of the service
 * account (RFC 7523 JWT bearer grant). A new assertion is signed for each
 * request. Returns 0 on success, otherwise -1 with <err> filled.
 */
static int cloudauth_google_sa_request(const struct cloudauth_profile *prof, struct cloudauth_fetch_req *req,
                                       char **err)
{
	const char *endpoint = cloudauth_google_sa_endpoint(prof);
	struct ist detail = ist(endpoint);
	struct buffer *jwt;
	int ret = -1;

	TRACE_ENTER(CLOUDAUTH_EV_FETCH, NULL, prof);

	/* the endpoint carries no secret */
	TRACE_STATE("token endpoint", CLOUDAUTH_EV_FETCH, NULL, prof, &detail);

	jwt = alloc_trash_chunk();
	if (!jwt) {
		memprintf(err, "out of memory");
		goto leave;
	}
	if (cloudauth_google_sa_assertion(prof, jwt, err) < 0)
		goto out;

	req->meth = HTTP_METH_POST;
	if (!chunk_strcat(req->url, endpoint))
		goto full;
	if (cloudauth_form_add(req->body, "grant_type", ist(CLOUDAUTH_GOOGLE_JWT_BEARER)) < 0)
		goto full;
	if (cloudauth_form_add(req->body, "assertion", ist2(jwt->area, jwt->data)) < 0)
		goto full;
	if (cloudauth_fetch_add_hdr(req, ist("content-type"), ist("application/x-www-form-urlencoded")) < 0)
		goto full;
	ret = 0;
	goto out;

  full:
	memprintf(err, "the request does not fit in a buffer");
  out:
	/* the assertion grants tokens until it expires */
	ha_memset_s(jwt->area, 0, jwt->size);
	free_trash_chunk(jwt);
  leave:
	if (ret < 0)
		TRACE_DEVEL("leaving on error", CLOUDAUTH_EV_FETCH, NULL, prof);
	else
		TRACE_LEAVE(CLOUDAUTH_EV_FETCH, NULL, prof);
	return ret;
}

/* Returns the URL of the Security Token Service to which the federated tokens
 * of profile <prof> are sent.
 */
static const char *cloudauth_google_wi_endpoint(const struct cloudauth_profile *prof)
{
	const struct cloudauth_google_ctx *ctx = cloudauth_google_ctx(prof);

	if (prof->fetch.endpoint)
		return prof->fetch.endpoint;
	if (ctx->wi_token_url)
		return ctx->wi_token_url;
	return CLOUDAUTH_GOOGLE_STS_ENDPOINT;
}

/* Prepares in <req> the request of a token for profile <prof> to the Security
 * Token Service of Google, exchanging the federated token of the workload for
 * an access token (RFC 8693 token exchange). Returns 0 on success, otherwise
 * -1 with <err> filled.
 */
static int cloudauth_google_wi_request(const struct cloudauth_profile *prof, struct cloudauth_fetch_req *req,
                                       char **err)
{
	const struct cloudauth_google_ctx *ctx = cloudauth_google_ctx(prof);
	const char *endpoint = cloudauth_google_wi_endpoint(prof);
	const char *scopes = prof->fetch.scopes ? prof->fetch.scopes : CLOUDAUTH_GOOGLE_SCOPE;
	struct ist detail = ist(endpoint);

	TRACE_ENTER(CLOUDAUTH_EV_FETCH, NULL, prof);

	/* the endpoint carries no secret */
	TRACE_STATE("security token service endpoint", CLOUDAUTH_EV_FETCH, NULL, prof, &detail);

	req->meth = HTTP_METH_POST;
	if (!chunk_strcat(req->url, endpoint))
		goto full;
	if (cloudauth_form_add(req->body, "grant_type", ist(CLOUDAUTH_GOOGLE_TOKEN_EXCHANGE)) < 0)
		goto full;
	if (cloudauth_form_add(req->body, "audience", ist(ctx->wi_audience)) < 0)
		goto full;
	if (cloudauth_form_add(req->body, "scope", ist(scopes)) < 0)
		goto full;
	if (cloudauth_form_add(req->body, "requested_token_type", ist(CLOUDAUTH_GOOGLE_ACCESS_TOKEN)) < 0)
		goto full;
	if (cloudauth_form_add(req->body, "subject_token", req->inputs[CLOUDAUTH_GOOGLE_INPUT_FEDERATED_TOKEN]) < 0)
		goto full;
	if (cloudauth_form_add(req->body, "subject_token_type", ist(ctx->wi_token_type)) < 0)
		goto full;
	if (cloudauth_fetch_add_hdr(req, ist("content-type"), ist("application/x-www-form-urlencoded")) < 0)
		goto full;
	TRACE_LEAVE(CLOUDAUTH_EV_FETCH, NULL, prof);
	return 0;

  full:
	memprintf(err, "the request does not fit in a buffer");
	TRACE_DEVEL("leaving on error", CLOUDAUTH_EV_FETCH, NULL, prof);
	return -1;
}

/* Extracts the token and its expiration date from the response of a token
 * endpoint, of status <status> and payload <body>, into <token> and <expire>.
 * The metadata server, the token endpoint and the Security Token Service of
 * Google answer with an OAuth 2.0 token response. Returns 0 on success, otherwise -1 with <err> filled.
 */
static int cloudauth_google_token_response(const struct cloudauth_profile *prof, int status, const struct buffer *body,
                                           struct buffer *token, unsigned int *expire, char **err)
{
	TRACE_ENTER(CLOUDAUTH_EV_FETCH, NULL, prof);

	if (status < 200 || status >= 300) {
		cloudauth_oauth_error(status, body, err);
		goto error;
	}
	if (cloudauth_oauth_token(body, token, expire, err) < 0)
		goto error;
	TRACE_LEAVE(CLOUDAUTH_EV_FETCH, NULL, prof);
	return 0;

  error:
	TRACE_DEVEL("leaving on error", CLOUDAUTH_EV_FETCH, NULL, prof);
	return -1;
}

/* The inputs of the "workload-identity" token source */
static const char * const cloudauth_google_wi_inputs[] = {
	[CLOUDAUTH_GOOGLE_INPUT_FEDERATED_TOKEN] = "federated-token",
	NULL
};

/* The token sources of the Google provider, indexed by enum cloudauth_google_src */
static const struct cloudauth_source cloudauth_google_sources[CLOUDAUTH_GOOGLE_SRC_ENTRIES + 1] = {
	[CLOUDAUTH_GOOGLE_SRC_METADATA] = {
		.name     = "metadata-server",
		.signers  = 1U << CLOUDAUTH_SIGNER_BEARER,
		.flags    = CLOUDAUTH_SRC_F_ENDPOINT | CLOUDAUTH_SRC_F_SCOPES,
		.request  = cloudauth_google_metadata_request,
		.response = cloudauth_google_token_response,
	},
	[CLOUDAUTH_GOOGLE_SRC_SA] = {
		.name     = "service-account",
		.signers  = 1U << CLOUDAUTH_SIGNER_BEARER,
		.flags    = CLOUDAUTH_SRC_F_ENDPOINT | CLOUDAUTH_SRC_F_SCOPES,
		.request  = cloudauth_google_sa_request,
		.response = cloudauth_google_token_response,
	},
	[CLOUDAUTH_GOOGLE_SRC_WI] = {
		.name     = "workload-identity",
		.signers  = 1U << CLOUDAUTH_SIGNER_BEARER,
		.inputs   = cloudauth_google_wi_inputs,
		.flags    = CLOUDAUTH_SRC_F_ENDPOINT | CLOUDAUTH_SRC_F_SCOPES,
		.request  = cloudauth_google_wi_request,
		.response = cloudauth_google_token_response,
	},
	[CLOUDAUTH_GOOGLE_SRC_ENTRIES] = { .name = NULL }
};

/* Returns non-zero if profile <prof> fetches its token from the Google token
 * source <src>.
 */
static int cloudauth_google_uses_src(const struct cloudauth_profile *prof, enum cloudauth_google_src src)
{
	return prof->token_src == CLOUDAUTH_SRC_FETCH && prof->fetch.source == &cloudauth_google_sources[src];
}

/* Allocates the Google settings of profile <prof>. Returns 0 on success,
 * otherwise -1 with <err> filled.
 */
static int cloudauth_google_init(struct cloudauth_profile *prof, char **err)
{
	prof->provider_ctx = calloc(1, sizeof(struct cloudauth_google_ctx));
	if (!prof->provider_ctx) {
		memprintf(err, "out of memory");
		return -1;
	}
	return 0;
}

/* Returns non-zero if <str> may be written in a JSON string without being
 * escaped: visible ASCII characters except the double quote and the
 * backslash.
 */
static int cloudauth_google_is_json_safe(const char *str)
{
	const char *p;

	for (p = str; *p; p++) {
		if (!isgraph((unsigned char)*p) || *p == '"' || *p == '\\')
			return 0;
	}
	return 1;
}

/* Copies into <out> of <size> bytes the string <name> of the JSON credential
 * file <json>. Returns its length, or -1 if it is missing, is not a string or
 * does not fit.
 */
static int cloudauth_google_json_str(const struct ist json, const char *name, char *out, int size)
{
	return mjson_get_string(istptr(json), istlen(json), name, out, size);
}

/* Loads into the Google settings <ctx> the service account of the credential
 * file in ctx->credentials: its e-mail address, the identifier and the RSA
 * private key of its key, and its token endpoint if set. The strings written
 * in the claims of the assertions must be safe in JSON. Returns 0 on success,
 * otherwise -1 with <err> filled, which never contains the private key.
 */
static int cloudauth_google_load_sa(struct cloudauth_google_ctx *ctx, char **err)
{
	struct buffer *work;
	EVP_PKEY *key = NULL;
	int len, ret = -1;

	work = alloc_trash_chunk();
	if (!work) {
		memprintf(err, "out of memory");
		return -1;
	}

	len = cloudauth_google_json_str(ctx->credentials, "$.type", work->area, work->size);
	if (len < 0 || strcmp(work->area, "service_account") != 0) {
		memprintf(err, "not the key of a service account (\"type\" is not \"service_account\")");
		goto out;
	}

	len = cloudauth_google_json_str(ctx->credentials, "$.client_email", work->area, work->size);
	if (len <= 0 || !cloudauth_google_is_json_safe(work->area)) {
		memprintf(err, "missing or invalid \"client_email\"");
		goto out;
	}
	ctx->sa_email = strdup(work->area);
	if (!ctx->sa_email)
		goto oom;

	len = cloudauth_google_json_str(ctx->credentials, "$.private_key_id", work->area, work->size);
	if (len > 0) {
		if (!cloudauth_google_is_json_safe(work->area)) {
			memprintf(err, "invalid \"private_key_id\"");
			goto out;
		}
		ctx->sa_key_id = strdup(work->area);
		if (!ctx->sa_key_id)
			goto oom;
	}

	len = cloudauth_google_json_str(ctx->credentials, "$.token_uri", work->area, work->size);
	if (len >= 0) {
		if (strncmp(work->area, "https://", 8) != 0 || !cloudauth_google_is_json_safe(work->area)) {
			memprintf(err, "invalid \"token_uri\", expects an HTTPS URL");
			goto out;
		}
		ctx->sa_token_uri = strdup(work->area);
		if (!ctx->sa_token_uri)
			goto oom;
	}

	len = cloudauth_google_json_str(ctx->credentials, "$.private_key", work->area, work->size);
	if (len > 0)
		key = cloudauth_pem_private_key(ist2(work->area, len), IST_NULL);
	if (!key) {
		memprintf(err, "no unencrypted PEM private key found in \"private_key\"");
		goto out;
	}
	if (EVP_PKEY_base_id(key) != EVP_PKEY_RSA) {
		memprintf(err, "the private key must be an RSA one");
		goto out;
	}
	ctx->sa_key = key;
	key = NULL;
	ret = 0;
	goto out;

  oom:
	memprintf(err, "out of memory");
  out:
	EVP_PKEY_free(key);
	/* the work chunk may contain the private key */
	ha_memset_s(work->area, 0, work->size);
	free_trash_chunk(work);
	return ret;
}

/* Copies into <out> the string <name> of the credential file in ctx->credentials,
 * using the work chunk <work>, if it is made of visible ASCII characters. It is
 * set to NULL if the string is missing and <optional> is set. Returns 0 on
 * success, -1 if the string is missing, empty or invalid, or -2 if it cannot
 * be copied.
 */
static int cloudauth_google_json_dup(const struct cloudauth_google_ctx *ctx, struct buffer *work, const char *name,
                                     int optional, char **out)
{
	int len;

	len = cloudauth_google_json_str(ctx->credentials, name, work->area, work->size);
	if (len < 0 && optional) {
		*out = NULL;
		return 0;
	}
	if (len <= 0 || cloudauth_ist_check(ist2(work->area, len), isgraph) >= 0)
		return -1;
	*out = strdup(work->area);
	if (!*out)
		return -2;
	return 0;
}

/* Loads into the Google settings <ctx> the workload identity federation of the
 * credential file in ctx->credentials: the workload identity pool provider,
 * the type of the federated token and the Security Token Service endpoint if
 * set. The service account impersonation is not supported. The location of the
 * federated token ("credential_source") is ignored, since the file system is
 * never accessed at runtime: it is the "federated-token" input. Returns 0 on
 * success, otherwise -1 with <err> filled.
 */
static int cloudauth_google_load_wi(struct cloudauth_google_ctx *ctx, char **err)
{
	struct buffer *work;
	int len, ret = -1;

	work = alloc_trash_chunk();
	if (!work) {
		memprintf(err, "out of memory");
		return -1;
	}

	len = cloudauth_google_json_str(ctx->credentials, "$.type", work->area, work->size);
	if (len < 0 || strcmp(work->area, "external_account") != 0) {
		memprintf(err, "not a workload identity federation (\"type\" is not \"external_account\")");
		goto out;
	}

	len = cloudauth_google_json_str(ctx->credentials, "$.service_account_impersonation_url", work->area, work->size);
	if (len >= 0) {
		memprintf(err, "the service account impersonation (\"service_account_impersonation_url\") is not supported, "
		          "the access must be granted to the workload identity");
		goto out;
	}

	switch (cloudauth_google_json_dup(ctx, work, "$.audience", 0, &ctx->wi_audience)) {
	case -1:
		memprintf(err, "missing or invalid \"audience\"");
		goto out;
	case -2:
		goto oom;
	}

	switch (cloudauth_google_json_dup(ctx, work, "$.subject_token_type", 0, &ctx->wi_token_type)) {
	case -1:
		memprintf(err, "missing or invalid \"subject_token_type\"");
		goto out;
	case -2:
		goto oom;
	}

	switch (cloudauth_google_json_dup(ctx, work, "$.token_url", 1, &ctx->wi_token_url)) {
	case -1:
		memprintf(err, "invalid \"token_url\", expects an HTTPS URL");
		goto out;
	case -2:
		goto oom;
	}
	if (ctx->wi_token_url && strncmp(ctx->wi_token_url, "https://", 8) != 0) {
		memprintf(err, "invalid \"token_url\", expects an HTTPS URL");
		goto out;
	}
	ret = 0;
	goto out;

  oom:
	memprintf(err, "out of memory");
  out:
	ha_memset_s(work->area, 0, work->size);
	free_trash_chunk(work);
	return ret;
}

/* Checks the Google settings of profile <prof> once its section is parsed.
 * Returns 0 on success, otherwise -1 with <err> filled.
 */
static int cloudauth_google_check(struct cloudauth_profile *prof, char **err)
{
	struct cloudauth_google_ctx *ctx = cloudauth_google_ctx(prof);
	int sa, wi, ret;

	sa = cloudauth_google_uses_src(prof, CLOUDAUTH_GOOGLE_SRC_SA);
	wi = cloudauth_google_uses_src(prof, CLOUDAUTH_GOOGLE_SRC_WI);
	if (isttest(ctx->credentials) && !sa && !wi) {
		memprintf(err, "'google-credentials' is only used by the 'service-account' and 'workload-identity' token sources");
		return -1;
	}
	if (!sa && !wi)
		return 0;
	if (!isttest(ctx->credentials)) {
		memprintf(err, "the '%s' token source requires 'google-credentials'", prof->fetch.source->name);
		return -1;
	}
	/* the token endpoint is also the audience of the assertions */
	if (sa && prof->fetch.endpoint && !cloudauth_google_is_json_safe(prof->fetch.endpoint)) {
		memprintf(err, "the 'token-endpoint' of the 'service-account' token source must not contain spaces, "
		          "double quotes nor backslashes");
		return -1;
	}

	/* the credential file is not needed anymore once loaded */
	if (sa)
		ret = cloudauth_google_load_sa(ctx, err);
	else
		ret = cloudauth_google_load_wi(ctx, err);
	cloudauth_free_secret(&ctx->credentials);
	if (ret < 0) {
		memprintf(err, "'google-credentials' : invalid credential file '%s' : %s", ctx->credentials_arg, *err);
		return -1;
	}
	return 0;
}

/* Releases the Google settings of profile <prof> */
static void cloudauth_google_release(struct cloudauth_profile *prof)
{
	struct cloudauth_google_ctx *ctx = prof->provider_ctx;

	if (!ctx)
		return;
	cloudauth_free_secret(&ctx->credentials);
	ha_free(&ctx->credentials_arg);
	EVP_PKEY_free(ctx->sa_key);
	ctx->sa_key = NULL;
	ha_free(&ctx->sa_email);
	ha_free(&ctx->sa_key_id);
	ha_free(&ctx->sa_token_uri);
	ha_free(&ctx->wi_audience);
	ha_free(&ctx->wi_token_type);
	ha_free(&ctx->wi_token_url);
	ha_free(&prof->provider_ctx);
}

struct cloudauth_provider cloudauth_google_provider = {
	.name        = "google",
	.signers     = (1U << CLOUDAUTH_SIGNER_BEARER) | (1U << CLOUDAUTH_SIGNER_SIGV4),
	.init        = cloudauth_google_init,
	.check       = cloudauth_google_check,
	.sign        = cloudauth_google_sign,
	.release     = cloudauth_google_release,
	.sources     = cloudauth_google_sources,
	.sigv4       = &cloudauth_google_sigv4,
};

INITCALL1(STG_REGISTER, cloudauth_register_provider, &cloudauth_google_provider);
REGISTER_BUILD_OPTS("Built with the cloudauth provider: google (Google Cloud Storage).");

/* Returns the Google settings of the profile being parsed, or NULL with <err>
 * filled if it does not use "provider google", <kw> being the keyword parsed.
 */
static struct cloudauth_google_ctx *cloudauth_google_cfg_ctx(const char *kw, char **err)
{
	struct cloudauth_profile *prof = cloudauth_cfg_profile();

	if (!prof || prof->provider != &cloudauth_google_provider) {
		memprintf(err, "'%s' requires 'provider google' first.", kw);
		return NULL;
	}
	return prof->provider_ctx;
}

/* Parses the "google-credentials" keyword: the credential file of a service
 * account or of a workload identity federation, in JSON, read from an environment variable or a file when the
 * configuration is parsed, never from the configuration itself. It is loaded
 * once the section is parsed, when its token source is known.
 */
static int cfg_parse_cloudauth_google_credentials(char **args, int section_type, struct proxy *curpx,
                                                  const struct proxy *defpx, const char *file, int linenum,
                                                  char **err)
{
	struct cloudauth_google_ctx *ctx = cloudauth_google_cfg_ctx(args[0], err);
	int err_code;

	if (!ctx)
		return ERR_ALERT | ERR_FATAL;

	if (!*args[1] || *args[2]) {
		memprintf(err, "'%s' expects exactly one argument.", args[0]);
		return ERR_ALERT | ERR_FATAL;
	}
	if (isttest(ctx->credentials)) {
		memprintf(err, "'%s' may only be set once.", args[0]);
		return ERR_ALERT | ERR_FATAL;
	}

	ctx->credentials_arg = strdup(args[1]);
	if (!ctx->credentials_arg) {
		memprintf(err, "out of memory");
		return ERR_ALERT | ERR_FATAL;
	}
	err_code = cloudauth_cfg_read_secret(args[1], &ctx->credentials, err);
	if (err_code)
		memprintf(err, "'%s' : %s.", args[0], *err);
	return err_code;
}

static struct cfg_kw_list cfg_kws = { ILH, {
	{ CLOUDAUTH_CFG_SECTION, "google-credentials", cfg_parse_cloudauth_google_credentials },
	{ 0, NULL, NULL },
}};

INITCALL1(STG_REGISTER, cloudauth_register_keywords, &cfg_kws);
