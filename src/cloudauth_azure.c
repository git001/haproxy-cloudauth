/*
 * Cloud storage authentication: Azure Blob Storage provider.
 *
 * Copyright 2026 Aleksandar Lazic <al-haproxy@none.at>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 * The requests are authenticated with a Microsoft Entra ID token (bearer), a
 * shared access signature appended to the query string (sas), or a Shared Key
 * signature computed over the request (sharedkey, see "Authorize with Shared
 * Key" in the Azure Storage REST API documentation). The "x-ms-version"
 * header is always sent, since Azure rejects the requests authenticated with a
 * token without it.
 *
 * The Microsoft Entra ID tokens may also be fetched by HAProxy from the
 * managed identity endpoints ("token managed-identity"): the Azure Instance
 * Metadata Service (IMDS) of the virtual machines and AKS nodes, or the
 * endpoint of App Service, Azure Functions and Container Apps, announced by
 * the IDENTITY_ENDPOINT and IDENTITY_HEADER environment variables. They may
 * also be requested from Microsoft Entra ID for an application, with its
 * client secret ("token client-secret", OAuth 2.0 client credentials grant),
 * or with the federated token of a workload trusted by the application
 * ("token workload-identity", workload identity federation), such as the
 * token of a Kubernetes service account, injected from the CLI, or with a
 * client assertion signed with the certificate of the application ("token
 * client-certificate").
 */

#include <haproxy/api.h>
#include <haproxy/base64.h>
#include <haproxy/cfgparse.h>
#include <haproxy/chunk.h>
#include <haproxy/clock.h>
#include <haproxy/errors.h>
#include <haproxy/http.h>
#include <haproxy/http_htx.h>
#include <haproxy/htx.h>
#include <haproxy/init.h>
#include <haproxy/openssl-compat.h>
#include <haproxy/tools.h>
#include <haproxy/trace.h>

#include <cloudauth/cloudauth.h>
#include <cloudauth/cloudauth_azure.h>
#include <cloudauth/cloudauth_common.h>
#include <cloudauth/cloudauth_trace.h>

/* The standard headers covered by a Shared Key signature, in their order in
 * the string to sign.
 */
static const struct ist cloudauth_azure_std_hdrs[] = {
	IST("content-encoding"),
	IST("content-language"),
	IST("content-length"),
	IST("content-md5"),
	IST("content-type"),
	IST("date"),
	IST("if-modified-since"),
	IST("if-match"),
	IST("if-none-match"),
	IST("if-unmodified-since"),
	IST("range"),
};

/* Returns the Azure settings of profile <prof> */
static inline struct cloudauth_azure_ctx *cloudauth_azure_ctx(const struct cloudauth_profile *prof)
{
	return prof->provider_ctx;
}

/* Returns the "x-ms-version" sent for profile <prof> */
static const char *cloudauth_azure_version(const struct cloudauth_profile *prof)
{
	const struct cloudauth_azure_ctx *ctx = cloudauth_azure_ctx(prof);

	return ctx->version ? ctx->version : CLOUDAUTH_AZURE_VERSION;
}

/* Adds the "x-ms-version" header of profile <prof> to the request in <htx>.
 * Returns 0 on success, -1 on failure.
 */
static int cloudauth_azure_set_version(const struct cloudauth_profile *prof, struct htx *htx)
{
	if (!http_add_header(htx, ist("x-ms-version"), ist(cloudauth_azure_version(prof)), 0))
		return -1;
	return 0;
}

/* Returns <token> without its leading question mark, if any */
static struct ist cloudauth_azure_sas(const struct ist token)
{
	if (istlen(token) && *istptr(token) == '?')
		return istnext(token);
	return token;
}

/* Checks that <token> is a shared access signature: a query string with at
 * least a "sig" parameter, optionally starting with a question mark. Returns 0
 * on success, otherwise -1 with <err> filled. The token is never reported.
 */
static int cloudauth_azure_check_sas(const struct ist token, char **err)
{
	struct ist sas = cloudauth_azure_sas(token);
	const char *chunks[4] = { istptr(sas), istend(sas), NULL, NULL };

	if (!http_find_url_param_pos(chunks, "sig", 3, '&', 0)) {
		memprintf(err, "the shared access signature has no 'sig' parameter");
		return -1;
	}
	return 0;
}

/* Checks that <token> is a storage account key, encoded in base64. Returns 0
 * on success, otherwise -1 with <err> filled. The token is never reported.
 */
static int cloudauth_azure_check_key(const struct ist token, char **err)
{
	char key[CLOUDAUTH_AZURE_MAX_KEY];
	int len;

	len = base64dec(istptr(token), istlen(token), key, sizeof(key));
	ha_memset_s(key, 0, sizeof(key));
	if (len <= 0) {
		memprintf(err, "the account key must be base64 encoded and at most %d bytes long",
		          CLOUDAUTH_AZURE_MAX_KEY);
		return -1;
	}
	return 0;
}

/* Appends to <sts> the value of the header <name> of the request in <htx>,
 * the occurrences being separated by commas, then a line feed. A zero
 * Content-Length is represented by an empty value. Returns 0 on success, -1
 * on failure.
 */
static int cloudauth_azure_add_std_hdr(struct htx *htx, const struct ist name, struct buffer *sts)
{
	struct http_hdr_ctx ctx;
	int first = 1;

	ctx.blk = NULL;
	while (http_find_header(htx, name, &ctx, 1)) {
		if (isteq(name, ist("content-length")) && isteq(ctx.value, ist("0")))
			continue;
		if (!first) {
			if (!chunk_memcat(sts, ",", 1))
				return -1;
		}
		if (!chunk_istcat(sts, ctx.value))
			return -1;
		first = 0;
	}
	if (!chunk_memcat(sts, "\n", 1))
		return -1;
	return 0;
}

/* Appends to <sts> the canonicalized resource of the request in <htx> for
 * profile <prof>: "/<account><path>", followed by one line per query string
 * parameter, "<name>:<value>", the names being URL-decoded, in lower case and
 * sorted, and the values of a same name being URL-decoded, sorted and comma
 * separated. Returns 0 on success, -1 on failure.
 */
static int cloudauth_azure_add_resource(const struct cloudauth_profile *prof, struct htx *htx,
                                        struct buffer *sts)
{
	struct cloudauth_qparam params[CLOUDAUTH_AZURE_MAX_PARAMS];
	struct buffer *work = NULL;
	struct ist path, query, param;
	size_t j;
	int nb = 0, i, ret = -1;

	path = cloudauth_req_path(htx);
	query = istfind(path, '?');
	path = ist2(istptr(path), istlen(path) - istlen(query));
	if (!istlen(path))
		path = ist("/");

	if (!chunk_memcat(sts, "/", 1))
		goto out;
	if (!chunk_strcat(sts, cloudauth_azure_ctx(prof)->account))
		goto out;
	if (!chunk_istcat(sts, path))
		goto out;

	work = alloc_trash_chunk();
	if (!work)
		goto out;

	if (istlen(query))
		query = istnext(query);
	while (istlen(query)) {
		param = istsplit(&query, '&');
		if (!istlen(param))
			continue;
		if (nb == CLOUDAUTH_AZURE_MAX_PARAMS)
			goto out;
		if (cloudauth_qparam_decode(work, param, &params[nb]) < 0)
			goto out;
		for (j = 0; j < istlen(params[nb].name); j++)
			istptr(params[nb].name)[j] = tolower((unsigned char)istptr(params[nb].name)[j]);
		nb++;
	}

	qsort(params, nb, sizeof(*params), cloudauth_qparam_cmp);
	for (i = 0; i < nb; i++) {
		if (i && isteq(params[i].name, params[i - 1].name)) {
			if (!chunk_memcat(sts, ",", 1))
				goto out;
		}
		else {
			if (!chunk_memcat(sts, "\n", 1))
				goto out;
			if (!chunk_istcat(sts, params[i].name))
				goto out;
			if (!chunk_memcat(sts, ":", 1))
				goto out;
		}

		if (!chunk_istcat(sts, params[i].value))
			goto out;
	}
	ret = 0;

  out:
	free_trash_chunk(work);
	return ret;
}

/* Signs the request in <htx> with the storage account key of profile <prof>:
 * the "x-ms-date" and "x-ms-version" headers are added, then the
 * "Authorization: SharedKey <account>:<signature>" header, the signature being
 * the base64-encoded HMAC-SHA256 of the string to sign. The client headers
 * starting with "x-ms-" were removed before, so the canonicalized headers are
 * only the ones added here. The lock of the profile must be held. <strm> is
 * the stream of the request, for the traces. Returns 0 on success, -1 on
 * failure.
 */
static int cloudauth_azure_sign_sharedkey(const struct cloudauth_profile *prof, const struct stream *strm,
                                          struct htx *htx)
{
	char key[CLOUDAUTH_AZURE_MAX_KEY];
	unsigned char mac[EVP_MAX_MD_SIZE];
	/* the HMAC encoded in base64, see CLOUDAUTH_B64_SIZE() */
	char sig[CLOUDAUTH_B64_SIZE(EVP_MAX_MD_SIZE)];
	char xms_date[CLOUDAUTH_HTTP_DATE_SIZE];
	struct buffer *sts = NULL;
	struct buffer *auth = NULL;
	struct http_hdr_ctx ctx;
	struct htx_sl *sl;
	unsigned int mac_len = 0;
	int key_len, i, ret = -1;

	TRACE_ENTER(CLOUDAUTH_EV_REQ, strm, prof);

	/* the date is carried by "x-ms-date", remove the client one so that the
	 * "Date" line of the string to sign is empty.
	 */
	ctx.blk = NULL;
	while (http_find_header(htx, ist("date"), &ctx, 1))
		http_remove_header(htx, &ctx);

	if (!cloudauth_http_date(date.tv_sec, xms_date, sizeof(xms_date)))
		goto out;
	if (!http_add_header(htx, ist("x-ms-date"), ist(xms_date), 0))
		goto out;
	if (cloudauth_azure_set_version(prof, htx) < 0)
		goto out;

	/* the start line may have moved while the headers were added */
	sl = http_get_stline(htx);
	if (!sl)
		goto out;

	sts = alloc_trash_chunk();
	if (!sts)
		goto out;
	auth = alloc_trash_chunk();
	if (!auth)
		goto out;

	if (!chunk_istcat(sts, htx_sl_req_meth(sl)))
		goto out;
	if (!chunk_memcat(sts, "\n", 1))
		goto out;
	for (i = 0; i < sizeof(cloudauth_azure_std_hdrs) / sizeof(*cloudauth_azure_std_hdrs); i++) {
		if (cloudauth_azure_add_std_hdr(htx, cloudauth_azure_std_hdrs[i], sts) < 0)
			goto out;
	}
	if (!chunk_strcat(sts, "x-ms-date:"))
		goto out;
	if (!chunk_strcat(sts, xms_date))
		goto out;
	if (!chunk_strcat(sts, "\nx-ms-version:"))
		goto out;
	if (!chunk_strcat(sts, cloudauth_azure_version(prof)))
		goto out;
	if (!chunk_memcat(sts, "\n", 1))
		goto out;
	if (cloudauth_azure_add_resource(prof, htx, sts) < 0)
		goto out;

	key_len = base64dec(istptr(prof->cred.token), istlen(prof->cred.token), key, sizeof(key));
	if (key_len <= 0)
		goto out;
	if (!HMAC(EVP_sha256(), key, key_len, (unsigned char *)sts->area, sts->data, mac, &mac_len))
		goto out;
	if (a2base64((char *)mac, mac_len, sig, sizeof(sig)) < 0)
		goto out;

	if (!chunk_strcat(auth, "SharedKey "))
		goto out;
	if (!chunk_strcat(auth, cloudauth_azure_ctx(prof)->account))
		goto out;
	if (!chunk_memcat(auth, ":", 1))
		goto out;
	if (!chunk_strcat(auth, sig))
		goto out;
	if (!http_add_header(htx, ist("authorization"), ist2(auth->area, auth->data), 0))
		goto out;
	ret = 0;

  out:
	/* do not leave the key on the stack */
	ha_memset_s(key, 0, sizeof(key));
	free_trash_chunk(auth);
	free_trash_chunk(sts);
	if (ret < 0)
		TRACE_DEVEL("leaving on error", CLOUDAUTH_EV_REQ, strm, prof);
	else
		TRACE_LEAVE(CLOUDAUTH_EV_REQ, strm, prof);
	return ret;
}

/* Authenticates the request in <htx> of the stream <strm> with the credential
 * of profile <prof>, whose lock is held. Returns 0 on success, -1 on failure.
 */
static int cloudauth_azure_sign(const struct cloudauth_profile *prof, const struct stream *strm, struct htx *htx)
{
	TRACE_ENTER(CLOUDAUTH_EV_REQ, strm, prof);

	switch (prof->signer) {
	case CLOUDAUTH_SIGNER_BEARER:
		if (cloudauth_azure_set_version(prof, htx) < 0)
			goto error;
		if (cloudauth_sign_bearer(prof, htx) < 0)
			goto error;
		break;
	case CLOUDAUTH_SIGNER_SAS:
		if (cloudauth_azure_set_version(prof, htx) < 0)
			goto error;
		if (!cloudauth_append_query(htx, cloudauth_azure_sas(prof->cred.token)))
			goto error;
		break;
	case CLOUDAUTH_SIGNER_SHAREDKEY:
		if (cloudauth_azure_sign_sharedkey(prof, strm, htx) < 0)
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

/* Checks that <token> may be used by the signer of profile <prof>. Returns 0
 * on success, otherwise -1 with <err> filled.
 */
static int cloudauth_azure_check_token(const struct cloudauth_profile *prof, const struct ist token, char **err)
{
	switch (prof->signer) {
	case CLOUDAUTH_SIGNER_SAS:
		return cloudauth_azure_check_sas(token, err);
	case CLOUDAUTH_SIGNER_SHAREDKEY:
		return cloudauth_azure_check_key(token, err);
	default:
		return 0;
	}
}

/* Selects the managed identity endpoint of profile <prof>: the App Service one
 * if the IDENTITY_ENDPOINT and IDENTITY_HEADER environment variables are set,
 * otherwise IMDS. The secret header is removed from the environment once the
 * configuration is parsed. Returns 0 on success, otherwise -1 with <err>
 * filled.
 */
static int cloudauth_azure_mi_init(struct cloudauth_profile *prof, char **err)
{
	struct cloudauth_azure_ctx *ctx = cloudauth_azure_ctx(prof);
	const char *endpoint = getenv("IDENTITY_ENDPOINT");
	const char *header = getenv("IDENTITY_HEADER");

	if (!endpoint || !*endpoint || !header || !*header)
		return 0;

	ctx->identity_endpoint = strdup(endpoint);
	if (!ctx->identity_endpoint)
		goto oom;
	ctx->identity_header = istdup(ist(header));
	if (!isttest(ctx->identity_header))
		goto oom;
	if (cloudauth_register_secret_env("IDENTITY_HEADER") < 0)
		goto oom;
	return 0;

  oom:
	memprintf(err, "out of memory");
	return -1;
}

/* Prepares in <req> the request of a token for profile <prof> to its managed
 * identity endpoint. The client ID of a user-assigned identity is passed with
 * the same parameter name to both endpoints. Returns 0 on success, otherwise
 * -1 with <err> filled.
 */
static int cloudauth_azure_mi_request(const struct cloudauth_profile *prof, struct cloudauth_fetch_req *req, char **err)
{
	const struct cloudauth_azure_ctx *ctx = cloudauth_azure_ctx(prof);
	const char *endpoint, *version;
	struct ist detail;
	int app_service;

	TRACE_ENTER(CLOUDAUTH_EV_FETCH, NULL, prof);

	/* an explicit IMDS endpoint ("token-endpoint") has precedence */
	app_service = !prof->fetch.endpoint && ctx->identity_endpoint;
	if (app_service) {
		endpoint = ctx->identity_endpoint;
		version = "2019-08-01";
	}
	else {
		endpoint = prof->fetch.endpoint ? prof->fetch.endpoint : CLOUDAUTH_AZURE_IMDS_ENDPOINT;
		version = "2018-02-01";
	}
	/* the endpoints carry no secret, the one of App Service is in a header */
	detail = ist(endpoint);
	if (app_service)
		TRACE_STATE("App Service endpoint", CLOUDAUTH_EV_FETCH, NULL, prof, &detail);
	else
		TRACE_STATE("IMDS endpoint", CLOUDAUTH_EV_FETCH, NULL, prof, &detail);

	if (!chunk_strcat(req->url, endpoint))
		goto full;
	if (!chunk_strcat(req->url, strchr(endpoint, '?') ? "&" : "?"))
		goto full;
	if (!chunk_strcat(req->url, "api-version="))
		goto full;
	if (!chunk_strcat(req->url, version))
		goto full;
	if (!chunk_strcat(req->url, "&resource="))
		goto full;
	if (!chunk_strcat(req->url, CLOUDAUTH_AZURE_RESOURCE))
		goto full;

	if (ctx->client_id) {
		if (!chunk_strcat(req->url, "&client_id="))
			goto full;
		if (!chunk_strcat(req->url, ctx->client_id))
			goto full;
	}

	if (app_service) {
		if (cloudauth_fetch_add_hdr(req, ist("x-identity-header"), ctx->identity_header) < 0)
			goto full;
	}
	else if (cloudauth_fetch_add_hdr(req, ist("metadata"), ist("true")) < 0)
		goto full;
	TRACE_LEAVE(CLOUDAUTH_EV_FETCH, NULL, prof);
	return 0;

  full:
	memprintf(err, "the request does not fit in a buffer");
	TRACE_DEVEL("leaving on error", CLOUDAUTH_EV_FETCH, NULL, prof);
	return -1;
}

/* Appends to <out> the URL of the Microsoft Entra ID token endpoint of the
 * tenant of the application of profile <prof>. Returns 0 on success, -1 if
 * there is no more room.
 */
static int cloudauth_azure_token_url(const struct cloudauth_profile *prof, struct buffer *out)
{
	const struct cloudauth_azure_ctx *ctx = cloudauth_azure_ctx(prof);
	const char *host = ctx->authority_host ? ctx->authority_host : CLOUDAUTH_AZURE_AUTHORITY_HOST;

	if (!chunk_strcat(out, host))
		return -1;
	if (!chunk_memcat(out, "/", 1))
		return -1;
	if (!chunk_strcat(out, ctx->tenant_id))
		return -1;
	if (!chunk_strcat(out, "/oauth2/v2.0/token"))
		return -1;
	return 0;
}

/* Prepares in <req> the request of a token for profile <prof> to the
 * Microsoft Entra ID token endpoint of its tenant (OAuth 2.0 client
 * credentials grant). The application is authenticated by the form field
 * <name1> of value <value1>, and by the field <name2> of value <value2> if
 * <name2> is not NULL, which are sent in the payload since they are secrets.
 * Returns 0 on success, otherwise -1 with <err> filled.
 */
static int cloudauth_azure_entra_request(const struct cloudauth_profile *prof, struct cloudauth_fetch_req *req,
                                         const char *name1, const struct ist value1,
                                         const char *name2, const struct ist value2, char **err)
{
	const struct cloudauth_azure_ctx *ctx = cloudauth_azure_ctx(prof);
	const char *host = ctx->authority_host ? ctx->authority_host : CLOUDAUTH_AZURE_AUTHORITY_HOST;
	struct ist detail = ist(host);

	TRACE_ENTER(CLOUDAUTH_EV_FETCH, NULL, prof);
	TRACE_STATE("Microsoft Entra ID authority host", CLOUDAUTH_EV_FETCH, NULL, prof, &detail);
	req->meth = HTTP_METH_POST;
	if (cloudauth_azure_token_url(prof, req->url) < 0)
		goto full;

	if (cloudauth_form_add(req->body, "grant_type", ist("client_credentials")) < 0)
		goto full;
	if (cloudauth_form_add(req->body, "client_id", ist(ctx->client_id)) < 0)
		goto full;
	if (cloudauth_form_add(req->body, name1, value1) < 0)
		goto full;
	if (name2) {
		if (cloudauth_form_add(req->body, name2, value2) < 0)
			goto full;
	}
	if (cloudauth_form_add(req->body, "scope", ist(CLOUDAUTH_AZURE_SCOPE)) < 0)
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

/* Prepares in <req> the request of a token for profile <prof> to Microsoft
 * Entra ID, authenticated with the client secret of the application. Returns
 * 0 on success, otherwise -1 with <err> filled.
 */
static int cloudauth_azure_secret_request(const struct cloudauth_profile *prof, struct cloudauth_fetch_req *req,
                                          char **err)
{
	return cloudauth_azure_entra_request(prof, req, "client_secret", cloudauth_azure_ctx(prof)->client_secret,
	                                     NULL, IST_NULL, err);
}

/* Prepares in <req> the request of a token for profile <prof> to Microsoft
 * Entra ID, authenticated with a federated token of the workload, such as a
 * Kubernetes service account token (workload identity federation), passed as
 * the client assertion. Returns 0 on success, otherwise -1 with <err> filled.
 */
static int cloudauth_azure_wi_request(const struct cloudauth_profile *prof, struct cloudauth_fetch_req *req,
                                      char **err)
{
	return cloudauth_azure_entra_request(prof, req, "client_assertion_type", ist(CLOUDAUTH_AZURE_ASSERTION_TYPE),
	                                     "client_assertion", req->inputs[CLOUDAUTH_AZURE_INPUT_FEDERATED_TOKEN], err);
}

/* Builds into <out> the client assertion of profile <prof>: a JWT signed with
 * the private key of the certificate of the application (PS256), whose
 * header designates the certificate by its SHA-256 thumbprint, and whose
 * claims are those expected by Microsoft Entra ID, with a unique identifier
 * and a short lifetime. Returns 0 on success, otherwise -1 with <err> filled.
 */
static int cloudauth_azure_cert_assertion(const struct cloudauth_profile *prof, struct buffer *out, char **err)
{
	const struct cloudauth_azure_ctx *ctx = cloudauth_azure_ctx(prof);
	unsigned int now = date.tv_sec;
	struct buffer *header = NULL, *claims = NULL, *url = NULL, *jti = NULL;
	int ret = -1;

	header = alloc_trash_chunk();
	if (!header)
		goto oom;
	claims = alloc_trash_chunk();
	if (!claims)
		goto oom;
	url = alloc_trash_chunk();
	if (!url)
		goto oom;
	jti = alloc_trash_chunk();
	if (!jti)
		goto oom;

	ha_generate_uuid_v4(jti);
	if (cloudauth_azure_token_url(prof, url) < 0)
		goto full;
	if (chunk_printf(header, "{\"alg\":\"PS256\",\"typ\":\"JWT\",\"x5t#S256\":\"%s\"}", ctx->cert_x5t) < 0)
		goto full;
	if (chunk_printf(claims, "{\"aud\":\"%.*s\",\"exp\":%u,\"iss\":\"%s\",\"jti\":\"%.*s\",\"nbf\":%u,\"sub\":\"%s\",\"iat\":%u}",
	                 (int)url->data, url->area, now + CLOUDAUTH_AZURE_ASSERTION_LIFETIME, ctx->client_id,
	                 (int)jti->data, jti->area, now, ctx->client_id, now) < 0)
		goto full;

	ret = cloudauth_jwt_sign(out, ist2(header->area, header->data), ist2(claims->area, claims->data),
	                         ctx->cert_key, JWS_ALG_PS256, err);
	goto out;

  oom:
	memprintf(err, "out of memory");
	goto out;
  full:
	memprintf(err, "the client assertion does not fit in a buffer");
  out:
	free_trash_chunk(jti);
	free_trash_chunk(url);
	free_trash_chunk(claims);
	free_trash_chunk(header);
	return ret;
}

/* Prepares in <req> the request of a token for profile <prof> to Microsoft
 * Entra ID, authenticated with a client assertion signed with the certificate
 * of the application. A new assertion is signed for each request. Returns 0
 * on success, otherwise -1 with <err> filled.
 */
static int cloudauth_azure_cert_request(const struct cloudauth_profile *prof, struct cloudauth_fetch_req *req,
                                        char **err)
{
	struct buffer *jwt;
	int ret = -1;

	TRACE_ENTER(CLOUDAUTH_EV_FETCH, NULL, prof);

	jwt = alloc_trash_chunk();
	if (!jwt) {
		memprintf(err, "out of memory");
		goto out;
	}
	if (cloudauth_azure_cert_assertion(prof, jwt, err) == 0)
		ret = cloudauth_azure_entra_request(prof, req, "client_assertion_type", ist(CLOUDAUTH_AZURE_ASSERTION_TYPE),
		                                    "client_assertion", ist2(jwt->area, jwt->data), err);

	/* the assertion grants tokens until it expires */
	ha_memset_s(jwt->area, 0, jwt->size);
	free_trash_chunk(jwt);
  out:
	if (ret < 0)
		TRACE_DEVEL("leaving on error", CLOUDAUTH_EV_FETCH, NULL, prof);
	else
		TRACE_LEAVE(CLOUDAUTH_EV_FETCH, NULL, prof);
	return ret;
}

/* Extracts the token and its expiration date from the response of a token
 * endpoint, of status <status> and payload <body>, into <token> and <expire>.
 * Both the managed identity endpoints and Microsoft Entra ID answer with an
 * OAuth 2.0 token response. Returns 0 on success, otherwise -1 with <err>
 * filled.
 */
static int cloudauth_azure_token_response(const struct cloudauth_profile *prof, int status, const struct buffer *body,
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
static const char * const cloudauth_azure_wi_inputs[] = {
	[CLOUDAUTH_AZURE_INPUT_FEDERATED_TOKEN] = "federated-token",
	NULL
};

/* The token sources of the Azure provider, indexed by enum cloudauth_azure_src */
static const struct cloudauth_source cloudauth_azure_sources[CLOUDAUTH_AZURE_SRC_ENTRIES + 1] = {
	[CLOUDAUTH_AZURE_SRC_MI] = {
		.name     = "managed-identity",
		.signers  = 1U << CLOUDAUTH_SIGNER_BEARER,
		.flags    = CLOUDAUTH_SRC_F_ENDPOINT,
		.init     = cloudauth_azure_mi_init,
		.request  = cloudauth_azure_mi_request,
		.response = cloudauth_azure_token_response,
	},
	[CLOUDAUTH_AZURE_SRC_SECRET] = {
		.name     = "client-secret",
		.signers  = 1U << CLOUDAUTH_SIGNER_BEARER,
		.request  = cloudauth_azure_secret_request,
		.response = cloudauth_azure_token_response,
	},
	[CLOUDAUTH_AZURE_SRC_WI] = {
		.name     = "workload-identity",
		.signers  = 1U << CLOUDAUTH_SIGNER_BEARER,
		.inputs   = cloudauth_azure_wi_inputs,
		.request  = cloudauth_azure_wi_request,
		.response = cloudauth_azure_token_response,
	},
	[CLOUDAUTH_AZURE_SRC_CERT] = {
		.name     = "client-certificate",
		.signers  = 1U << CLOUDAUTH_SIGNER_BEARER,
		.request  = cloudauth_azure_cert_request,
		.response = cloudauth_azure_token_response,
	},
	[CLOUDAUTH_AZURE_SRC_ENTRIES] = { .name = NULL }
};

/* Returns non-zero if profile <prof> fetches its token from the Azure token
 * source <src>.
 */
static int cloudauth_azure_uses_src(const struct cloudauth_profile *prof, enum cloudauth_azure_src src)
{
	return prof->token_src == CLOUDAUTH_SRC_FETCH && prof->fetch.source == &cloudauth_azure_sources[src];
}

/* Allocates the Azure settings of profile <prof>. Returns 0 on success,
 * otherwise -1 with <err> filled.
 */
static int cloudauth_azure_init(struct cloudauth_profile *prof, char **err)
{
	prof->provider_ctx = calloc(1, sizeof(struct cloudauth_azure_ctx));
	if (!prof->provider_ctx) {
		memprintf(err, "out of memory");
		return -1;
	}
	return 0;
}

/* Loads into the Azure settings <ctx> the private key of the certificate of
 * the application, an RSA one, from the PEM data in ctx->cert_pem, decrypted
 * with ctx->cert_password if it is encrypted, then computes the thumbprint of
 * the certificate. Only the private key and the thumbprint are kept. Returns
 * 0 on success, otherwise -1 with <err> filled.
 */
static int cloudauth_azure_load_cert(struct cloudauth_azure_ctx *ctx, char **err)
{
	struct ist nopass = IST_NULL;
	unsigned char digest[EVP_MAX_MD_SIZE];
	unsigned int digest_len = 0;
	BIO *bio = NULL;
	X509 *cert = NULL;
	EVP_PKEY *key = NULL;
	int ret = -1;

	bio = BIO_new_mem_buf(istptr(ctx->cert_pem), istlen(ctx->cert_pem));
	if (!bio)
		goto oom;
	cert = PEM_read_bio_X509(bio, NULL, cloudauth_pem_password, &nopass);
	if (!cert) {
		memprintf(err, "no PEM certificate found");
		goto out;
	}

	/* the private key may be placed before the certificate */
	key = cloudauth_pem_private_key(ctx->cert_pem, ctx->cert_password);
	if (!key) {
		if (isttest(ctx->cert_password))
			memprintf(err, "no PEM private key found, or it cannot be decrypted with 'azure-client-certificate-password'");
		else if (ctx->cert_no_password)
			memprintf(err, "no PEM private key found, or it is encrypted while 'azure-client-certificate-password' is 'no-password'");
		else
			memprintf(err, "no PEM private key found, or it is encrypted and 'azure-client-certificate-password' is not set");
		goto out;
	}
	if (EVP_PKEY_base_id(key) != EVP_PKEY_RSA) {
		memprintf(err, "the private key must be an RSA one");
		goto out;
	}
	if (X509_check_private_key(cert, key) != 1) {
		memprintf(err, "the private key does not match the certificate");
		goto out;
	}

	if (X509_digest(cert, EVP_sha256(), digest, &digest_len) != 1) {
		memprintf(err, "cannot compute the thumbprint of the certificate");
		goto out;
	}
	if (a2base64url((char *)digest, digest_len, ctx->cert_x5t, sizeof(ctx->cert_x5t)) < 0) {
		memprintf(err, "cannot compute the thumbprint of the certificate");
		goto out;
	}
	ctx->cert_key = key;
	key = NULL;
	ret = 0;
	goto out;

  oom:
	memprintf(err, "out of memory");
  out:
	if (ret < 0)
		ERR_clear_error();
	EVP_PKEY_free(key);
	X509_free(cert);
	BIO_free(bio);
	return ret;
}

/* Checks the Azure settings of profile <prof> once its section is parsed.
 * Returns 0 on success, otherwise -1 with <err> filled.
 */
static int cloudauth_azure_check(struct cloudauth_profile *prof, char **err)
{
	struct cloudauth_azure_ctx *ctx = cloudauth_azure_ctx(prof);
	int mi, secret, wi, cert, ret;

	if (prof->signer == CLOUDAUTH_SIGNER_SHAREDKEY && !ctx->account) {
		memprintf(err, "the 'sharedkey' signer of provider 'azure' requires 'account'");
		return -1;
	}
	if (prof->signer != CLOUDAUTH_SIGNER_SHAREDKEY && ctx->account) {
		memprintf(err, "'account' is only used by the 'sharedkey' signer");
		return -1;
	}

	mi = cloudauth_azure_uses_src(prof, CLOUDAUTH_AZURE_SRC_MI);
	secret = cloudauth_azure_uses_src(prof, CLOUDAUTH_AZURE_SRC_SECRET);
	wi = cloudauth_azure_uses_src(prof, CLOUDAUTH_AZURE_SRC_WI);
	cert = cloudauth_azure_uses_src(prof, CLOUDAUTH_AZURE_SRC_CERT);
	if (ctx->client_id && !mi && !secret && !wi && !cert) {
		memprintf(err, "'azure-client-id' is only used by the 'managed-identity', 'client-secret', "
		          "'workload-identity' and 'client-certificate' token sources");
		return -1;
	}
	if ((ctx->tenant_id || ctx->authority_host) && !secret && !wi && !cert) {
		memprintf(err, "'azure-tenant-id' and 'azure-authority-host' are only used by the 'client-secret', "
		          "'workload-identity' and 'client-certificate' token sources");
		return -1;
	}
	if (isttest(ctx->client_secret) && !secret) {
		memprintf(err, "'azure-client-secret' is only used by the 'client-secret' token source");
		return -1;
	}
	if ((isttest(ctx->cert_pem) || isttest(ctx->cert_password) || ctx->cert_no_password) && !cert) {
		memprintf(err, "'azure-client-certificate' and 'azure-client-certificate-password' are only used by "
		          "the 'client-certificate' token source");
		return -1;
	}
	if (secret && (!ctx->tenant_id || !ctx->client_id || !isttest(ctx->client_secret))) {
		memprintf(err, "the 'client-secret' token source requires 'azure-tenant-id', 'azure-client-id' and 'azure-client-secret'");
		return -1;
	}
	if (wi && (!ctx->tenant_id || !ctx->client_id)) {
		memprintf(err, "the 'workload-identity' token source requires 'azure-tenant-id' and 'azure-client-id'");
		return -1;
	}
	if (cert && (!ctx->tenant_id || !ctx->client_id || !isttest(ctx->cert_pem))) {
		memprintf(err, "the 'client-certificate' token source requires 'azure-tenant-id', 'azure-client-id' and 'azure-client-certificate'");
		return -1;
	}

	/* the private key is loaded once its password is known, then the PEM
	 * data and the password are not needed anymore.
	 */
	if (cert) {
		ret = cloudauth_azure_load_cert(ctx, err);
		cloudauth_free_secret(&ctx->cert_pem);
		cloudauth_free_secret(&ctx->cert_password);
		if (ret < 0) {
			memprintf(err, "'azure-client-certificate' : invalid certificate in '%s' : %s", ctx->cert_arg, *err);
			return -1;
		}
	}
	return 0;
}

/* Releases the Azure settings of profile <prof> */
static void cloudauth_azure_release(struct cloudauth_profile *prof)
{
	struct cloudauth_azure_ctx *ctx = prof->provider_ctx;

	if (!ctx)
		return;
	ha_free(&ctx->account);
	ha_free(&ctx->version);
	ha_free(&ctx->client_id);
	ha_free(&ctx->identity_endpoint);
	cloudauth_free_secret(&ctx->identity_header);
	ha_free(&ctx->tenant_id);
	ha_free(&ctx->authority_host);
	cloudauth_free_secret(&ctx->client_secret);
	cloudauth_free_secret(&ctx->cert_pem);
	cloudauth_free_secret(&ctx->cert_password);
	ha_free(&ctx->cert_arg);
	EVP_PKEY_free(ctx->cert_key);
	ctx->cert_key = NULL;
	ha_free(&prof->provider_ctx);
}

struct cloudauth_provider cloudauth_azure_provider = {
	.name        = "azure",
	.signers     = (1U << CLOUDAUTH_SIGNER_BEARER) |
	               (1U << CLOUDAUTH_SIGNER_SAS) |
	               (1U << CLOUDAUTH_SIGNER_SHAREDKEY),
	.init        = cloudauth_azure_init,
	.check       = cloudauth_azure_check,
	.check_token = cloudauth_azure_check_token,
	.sign        = cloudauth_azure_sign,
	.release     = cloudauth_azure_release,
	.sources     = cloudauth_azure_sources,
};

INITCALL1(STG_REGISTER, cloudauth_register_provider, &cloudauth_azure_provider);

/* Returns the Azure settings of the profile being parsed, or NULL with <err>
 * filled if it does not use "provider azure", <kw> being the keyword parsed.
 */
static struct cloudauth_azure_ctx *cloudauth_azure_cfg_ctx(const char *kw, char **err)
{
	struct cloudauth_profile *prof = cloudauth_cfg_profile();

	if (!prof || prof->provider != &cloudauth_azure_provider) {
		memprintf(err, "'%s' requires 'provider azure' first.", kw);
		return NULL;
	}
	return prof->provider_ctx;
}

/* Returns non-zero if <name> is a storage account name: 3 to 24 lower case
 * letters and digits.
 */
static int cloudauth_azure_is_account(const char *name)
{
	size_t len = strlen(name);

	return len >= 3 && len <= 24 && strspn(name, "abcdefghijklmnopqrstuvwxyz0123456789") == len;
}

/* Returns non-zero if <v> is a version of the Azure Storage REST API, a date
 * formatted as "YYYY-MM-DD".
 */
static int cloudauth_azure_is_version(const char *v)
{
	const char *digits = "0123456789";

	return strlen(v) == 10 && v[4] == '-' && v[7] == '-' &&
	       strspn(v, digits) == 4 && strspn(v + 5, digits) == 2 && strspn(v + 8, digits) == 2;
}

/* Returns non-zero if <id> is a GUID, which is also safe in a query string */
static int cloudauth_azure_is_guid(const char *id)
{
	return strlen(id) == 36 && strspn(id, "0123456789abcdefABCDEF-") == 36;
}

/* Returns non-zero if <id> is a GUID or a domain name, which is also safe in a
 * path.
 */
static int cloudauth_azure_is_tenant(const char *id)
{
	size_t len = strlen(id);

	return len <= 253 && *id != '.' && *id != '-' &&
	       strspn(id, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-") == len;
}

/* Returns the length of the URL <url> without its trailing slashes */
static size_t cloudauth_azure_authority_len(const char *url)
{
	size_t len = strlen(url);

	while (len > 8 && url[len - 1] == '/')
		len--;
	return len;
}

/* Returns non-zero if <url> is an authority host: an HTTPS URL made of a host
 * and an optional port, possibly followed by slashes. Only the characters of
 * the host names, IP addresses and ports are accepted, since the URL is also
 * written in the claims of the client assertions.
 */
static int cloudauth_azure_is_authority(const char *url)
{
	size_t len = cloudauth_azure_authority_len(url);

	return strncmp(url, "https://", 8) == 0 && len > 8 &&
	       strspn(url + 8, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-:[]") == len - 8;
}

/* Parses the "account" keyword: the name of an Azure storage account */
static int cfg_parse_cloudauth_azure_account(char **args, int section_type, struct proxy *curpx,
                                             const struct proxy *defpx, const char *file, int linenum,
                                             char **err)
{
	struct cloudauth_azure_ctx *ctx = cloudauth_azure_cfg_ctx(args[0], err);

	if (!ctx)
		return ERR_ALERT | ERR_FATAL;
	return cloudauth_cfg_str(args, &ctx->account, 0, cloudauth_azure_is_account, "account name",
	                         "3 to 24 lower case letters and digits", err);
}

/* Parses the "azure-version" keyword: the version of the Azure Storage REST
 * API, a date formatted as "YYYY-MM-DD".
 */
static int cfg_parse_cloudauth_azure_version(char **args, int section_type, struct proxy *curpx,
                                             const struct proxy *defpx, const char *file, int linenum,
                                             char **err)
{
	struct cloudauth_azure_ctx *ctx = cloudauth_azure_cfg_ctx(args[0], err);

	if (!ctx)
		return ERR_ALERT | ERR_FATAL;
	return cloudauth_cfg_str(args, &ctx->version, 0, cloudauth_azure_is_version, "version",
	                         "a date like '" CLOUDAUTH_AZURE_VERSION "'", err);
}

/* Parses the "azure-client-id" keyword: the client ID of a user-assigned
 * managed identity or of an application, a GUID, either set directly or read
 * from an environment variable with "env:<variable>" like the one set by AKS
 * workload identity.
 */
static int cfg_parse_cloudauth_azure_client_id(char **args, int section_type, struct proxy *curpx,
                                               const struct proxy *defpx, const char *file, int linenum,
                                               char **err)
{
	struct cloudauth_azure_ctx *ctx = cloudauth_azure_cfg_ctx(args[0], err);

	if (!ctx)
		return ERR_ALERT | ERR_FATAL;
	return cloudauth_cfg_str(args, &ctx->client_id, 1, cloudauth_azure_is_guid, "client ID",
	                         "a GUID such as '00000000-0000-0000-0000-000000000000'", err);
}

/* Parses the "azure-tenant-id" keyword: the Microsoft Entra ID tenant of the
 * application, a GUID or a domain name, either set directly or read from an
 * environment variable with "env:<variable>".
 */
static int cfg_parse_cloudauth_azure_tenant_id(char **args, int section_type, struct proxy *curpx,
                                               const struct proxy *defpx, const char *file, int linenum,
                                               char **err)
{
	struct cloudauth_azure_ctx *ctx = cloudauth_azure_cfg_ctx(args[0], err);

	if (!ctx)
		return ERR_ALERT | ERR_FATAL;
	return cloudauth_cfg_str(args, &ctx->tenant_id, 1, cloudauth_azure_is_tenant, "tenant ID",
	                         "a GUID or a domain name", err);
}

/* Parses the "azure-client-secret" keyword: the client secret of the
 * application, read from an environment variable or a file when the
 * configuration is parsed, never from the configuration itself.
 */
static int cfg_parse_cloudauth_azure_client_secret(char **args, int section_type, struct proxy *curpx,
                                                   const struct proxy *defpx, const char *file, int linenum,
                                                   char **err)
{
	struct cloudauth_azure_ctx *ctx = cloudauth_azure_cfg_ctx(args[0], err);
	int err_code;

	if (!ctx)
		return ERR_ALERT | ERR_FATAL;

	if (!*args[1] || *args[2]) {
		memprintf(err, "'%s' expects exactly one argument.", args[0]);
		return ERR_ALERT | ERR_FATAL;
	}
	if (isttest(ctx->client_secret)) {
		memprintf(err, "'%s' may only be set once.", args[0]);
		return ERR_ALERT | ERR_FATAL;
	}

	err_code = cloudauth_cfg_read_secret(args[1], &ctx->client_secret, err);
	if (err_code)
		memprintf(err, "'%s' : %s.", args[0], *err);
	return err_code;
}

/* Parses the "azure-client-certificate" keyword: the certificate of the
 * application and its private key, in PEM format, read from an environment
 * variable or a file when the configuration is parsed, never from the
 * configuration itself. They are loaded once the section is parsed, since
 * the password of the private key may be set after.
 */
static int cfg_parse_cloudauth_azure_client_certificate(char **args, int section_type, struct proxy *curpx,
                                                        const struct proxy *defpx, const char *file, int linenum,
                                                        char **err)
{
	struct cloudauth_azure_ctx *ctx = cloudauth_azure_cfg_ctx(args[0], err);
	int err_code;

	if (!ctx)
		return ERR_ALERT | ERR_FATAL;

	if (!*args[1] || *args[2]) {
		memprintf(err, "'%s' expects exactly one argument.", args[0]);
		return ERR_ALERT | ERR_FATAL;
	}
	if (isttest(ctx->cert_pem)) {
		memprintf(err, "'%s' may only be set once.", args[0]);
		return ERR_ALERT | ERR_FATAL;
	}

	ctx->cert_arg = strdup(args[1]);
	if (!ctx->cert_arg) {
		memprintf(err, "out of memory");
		return ERR_ALERT | ERR_FATAL;
	}
	err_code = cloudauth_cfg_read_secret(args[1], &ctx->cert_pem, err);
	if (err_code)
		memprintf(err, "'%s' : %s.", args[0], *err);
	return err_code;
}

/* Parses the "azure-client-certificate-password" keyword: the password of
 * the private key of the certificate of the application, read from an
 * environment variable or a file when the configuration is parsed, never
 * from the configuration itself, or "no-password" to declare that the
 * private key is not encrypted.
 */
static int cfg_parse_cloudauth_azure_client_certificate_password(char **args, int section_type, struct proxy *curpx,
                                                                 const struct proxy *defpx, const char *file,
                                                                 int linenum, char **err)
{
	struct cloudauth_azure_ctx *ctx = cloudauth_azure_cfg_ctx(args[0], err);
	int err_code;

	if (!ctx)
		return ERR_ALERT | ERR_FATAL;

	if (!*args[1] || *args[2]) {
		memprintf(err, "'%s' expects exactly one argument.", args[0]);
		return ERR_ALERT | ERR_FATAL;
	}
	if (isttest(ctx->cert_password) || ctx->cert_no_password) {
		memprintf(err, "'%s' may only be set once.", args[0]);
		return ERR_ALERT | ERR_FATAL;
	}

	if (strcmp(args[1], "no-password") == 0) {
		ctx->cert_no_password = 1;
		return 0;
	}
	if (strncmp(args[1], "env:", 4) != 0 && strncmp(args[1], "file:", 5) != 0) {
		/* never echo the argument, it may be a secret */
		memprintf(err, "'%s' expects 'env:<variable>', 'file:<path>' or 'no-password', "
		          "secrets are not accepted in the configuration.", args[0]);
		return ERR_ALERT | ERR_FATAL;
	}
	err_code = cloudauth_cfg_read_secret(args[1], &ctx->cert_password, err);
	if (err_code)
		memprintf(err, "'%s' : %s.", args[0], *err);
	return err_code;
}

/* Parses the "azure-authority-host" keyword: the URL of the Microsoft Entra ID
 * authority host, such as the one of a national cloud. Only HTTPS is accepted
 * since the client secret is sent to it.
 */
static int cfg_parse_cloudauth_azure_authority_host(char **args, int section_type, struct proxy *curpx,
                                                    const struct proxy *defpx, const char *file, int linenum,
                                                    char **err)
{
	struct cloudauth_azure_ctx *ctx = cloudauth_azure_cfg_ctx(args[0], err);
	int err_code;

	if (!ctx)
		return ERR_ALERT | ERR_FATAL;
	err_code = cloudauth_cfg_str(args, &ctx->authority_host, 0, cloudauth_azure_is_authority, "URL",
	                             "'https://<host>[:<port>]'", err);
	if (err_code)
		return err_code;

	/* the path of the token endpoint is appended */
	ctx->authority_host[cloudauth_azure_authority_len(ctx->authority_host)] = 0;
	return 0;
}

static struct cfg_kw_list cfg_kws = { ILH, {
	{ CFG_CLOUDAUTH, "account",              cfg_parse_cloudauth_azure_account },
	{ CFG_CLOUDAUTH, "azure-authority-host", cfg_parse_cloudauth_azure_authority_host },
	{ CFG_CLOUDAUTH, "azure-client-certificate", cfg_parse_cloudauth_azure_client_certificate },
	{ CFG_CLOUDAUTH, "azure-client-certificate-password", cfg_parse_cloudauth_azure_client_certificate_password },
	{ CFG_CLOUDAUTH, "azure-client-id",      cfg_parse_cloudauth_azure_client_id },
	{ CFG_CLOUDAUTH, "azure-client-secret",  cfg_parse_cloudauth_azure_client_secret },
	{ CFG_CLOUDAUTH, "azure-tenant-id",      cfg_parse_cloudauth_azure_tenant_id },
	{ CFG_CLOUDAUTH, "azure-version",        cfg_parse_cloudauth_azure_version },
	{ 0, NULL, NULL },
}};

INITCALL1(STG_REGISTER, cfg_register_keywords, &cfg_kws);
