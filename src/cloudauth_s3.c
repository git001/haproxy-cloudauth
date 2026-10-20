/*
 * Cloud storage authentication: Amazon S3 and compatible storages provider.
 *
 * Copyright 2026 Aleksandar Lazic <al-haproxy@none.at>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 * The requests are signed with an access key (sigv4), made of an access key
 * identifier and a secret access key, and of a session token for the
 * temporary keys, with AWS Signature Version 4. It applies to Amazon S3 and
 * to the storages compatible with it (MinIO, Ceph, ...). The region is part
 * of the signature, so it must be set.
 *
 * The temporary access keys may be fetched by HAProxy from the credential
 * endpoint of the containers: the one of the Amazon ECS tasks ("token
 * container"), or the EKS Pod Identity Agent ("token pod-identity"), which
 * requires the token of the service account of the pod. They may also be
 * requested from the AWS Security Token Service for an IAM role trusting the
 * identity of the workload in another identity provider ("token
 * workload-identity"), such as the service account of an EKS pod with IAM
 * roles for service accounts (IRSA), in exchange for its token, or from the
 * EC2 Instance Metadata Service for the IAM role of the instance ("token
 * instance-metadata").
 */

#include <arpa/inet.h>
#include <netinet/in.h>

#include <import/mjson.h>

#include <haproxy/api.h>
#include <haproxy/cfgparse.h>
#include <haproxy/chunk.h>
#include <haproxy/errors.h>
#include <haproxy/global.h>
#include <haproxy/http.h>
#include <haproxy/init.h>
#include <haproxy/tools.h>
#include <haproxy/trace.h>

#include <cloudauth/cloudauth.h>
#include <cloudauth/cloudauth_common.h>
#include <cloudauth/cloudauth_s3.h>
#include <cloudauth/cloudauth_sigv4-t.h>
#include <cloudauth/cloudauth_trace.h>

/* The variant of Signature Version 4 of Amazon S3, without default region */
static const struct cloudauth_sigv4 cloudauth_s3_sigv4 = {
	.algorithm  = "AWS4-HMAC-SHA256",
	.key_prefix = "AWS4",
	.hdr_pfx    = IST("x-amz-"),
	.hash_hdr   = IST("x-amz-content-sha256"),
	.date_hdr   = IST("x-amz-date"),
	.token_hdr  = IST("x-amz-security-token"),
	.service    = "s3",
	.request    = "aws4_request",
	.region     = NULL,
	.unsigned_trailer = 1,
};

/* Returns the S3 settings of profile <prof> */
static inline struct cloudauth_s3_ctx *cloudauth_s3_ctx(const struct cloudauth_profile *prof)
{
	return prof->provider_ctx;
}

/* Returns the credential endpoint of a container token source of profile
 * <prof>: "token-endpoint", the one of the environment, otherwise <def>, the
 * default one of the token source, or NULL if it has none.
 */
static const char *cloudauth_s3_container_endpoint(const struct cloudauth_profile *prof, const char *def)
{
	const struct cloudauth_s3_ctx *ctx = cloudauth_s3_ctx(prof);

	if (prof->fetch.endpoint)
		return prof->fetch.endpoint;
	if (ctx->endpoint)
		return ctx->endpoint;
	return def;
}

/* Prepares in <req> the request of an access key for profile <prof> to the
 * credential endpoint <endpoint> of the containers, with the authorization
 * token <token> if set, coming from <origin>, which is traced instead of the
 * token. Returns 0 on success, otherwise -1 with <err> filled.
 */
static int cloudauth_s3_creds_request(const struct cloudauth_profile *prof, struct cloudauth_fetch_req *req,
                                      const char *endpoint, const struct ist token, const struct ist origin,
                                      char **err)
{
	struct ist detail = iststop(ist(endpoint), '?');

	TRACE_ENTER(CLOUDAUTH_EV_FETCH, NULL, prof);

	/* the endpoint carries no secret, but its query string is not traced */
	TRACE_STATE("container credential endpoint", CLOUDAUTH_EV_FETCH, NULL, prof, &detail);

	if (!chunk_strcat(req->url, endpoint))
		goto full;
	if (!isttest(token)) {
		TRACE_STATE("no authorization token sent", CLOUDAUTH_EV_FETCH, NULL, prof);
		TRACE_LEAVE(CLOUDAUTH_EV_FETCH, NULL, prof);
		return 0;
	}
	/* only where the token comes from */
	TRACE_STATE("authorization token sent from", CLOUDAUTH_EV_FETCH, NULL, prof, &origin);
	if (cloudauth_fetch_add_hdr(req, ist("authorization"), token) < 0)
		goto full;
	TRACE_LEAVE(CLOUDAUTH_EV_FETCH, NULL, prof);
	return 0;

  full:
	memprintf(err, "the request does not fit in a buffer");
	TRACE_DEVEL("leaving on error", CLOUDAUTH_EV_FETCH, NULL, prof);
	return -1;
}

/* Prepares in <req> the request of an access key for profile <prof> to the
 * credential endpoint of the Amazon ECS task, with the authorization token of
 * the environment if any. Returns 0 on success, otherwise -1 with <err>
 * filled.
 */
static int cloudauth_s3_container_request(const struct cloudauth_profile *prof, struct cloudauth_fetch_req *req,
                                          char **err)
{
	const char *endpoint = cloudauth_s3_container_endpoint(prof, NULL);

	/* checked once the section is parsed */
	BUG_ON(!endpoint);
	return cloudauth_s3_creds_request(prof, req, endpoint, cloudauth_s3_ctx(prof)->auth_token,
	                                  ist("AWS_CONTAINER_AUTHORIZATION_TOKEN"), err);
}

/* Prepares in <req> the request of an access key for profile <prof> to the
 * EKS Pod Identity Agent, with the token of the service account, the
 * "authorization-token" input. Returns 0 on success, otherwise -1 with <err>
 * filled.
 */
static int cloudauth_s3_pod_identity_request(const struct cloudauth_profile *prof, struct cloudauth_fetch_req *req,
                                             char **err)
{
	const char *endpoint = cloudauth_s3_container_endpoint(prof, CLOUDAUTH_S3_POD_IDENTITY_ENDPOINT);

	return cloudauth_s3_creds_request(prof, req, endpoint, req->inputs[CLOUDAUTH_S3_INPUT_AUTH_TOKEN],
	                                  ist("input 'authorization-token'"), err);
}

/* Traces the size of the payload <body> of the response of a credential
 * endpoint for profile <prof>, never its content, which carries the
 * credentials.
 */
static void cloudauth_s3_trace_payload(const struct cloudauth_profile *prof, const struct buffer *body)
{
	char str[32];
	struct ist detail;

	snprintf(str, sizeof(str), "%lu bytes", (ulong)b_data(body));
	detail = ist(str);
	TRACE_DATA("payload of the response", CLOUDAUTH_EV_FETCH, NULL, prof, &detail);
}

/* Appends to <token> the string <name> of the JSON credentials <body>, which
 * must be made of visible characters except the colon, since it is a part of
 * the token of the sigv4 signer. Returns 0 on success, -1 if it is missing or
 * invalid, or does not fit.
 */
static int cloudauth_s3_add_cred_part(struct buffer *token, const struct buffer *body, const char *name)
{
	char *part = b_tail(token);
	int len;

	len = mjson_get_string(b_orig(body), b_data(body), name, part, b_room(token));
	if (len <= 0)
		return -1;
	if (cloudauth_ist_check(ist2(part, len), isgraph) >= 0)
		return -1;
	if (memchr(part, ':', len))
		return -1;
	token->data += len;
	return 0;
}

/* Extracts the temporary access key and its expiration date from the response
 * of a credential endpoint of AWS, of status <status> and payload <body>, into
 * <token>, as "<access-key-id>:<secret>:<session-token>", and <expire>. The
 * payload is the JSON object of the containers and of the instances, whose
 * "AccessKeyId", "SecretAccessKey" and "Token" are mandatory, and whose
 * "Expiration" is an ISO 8601 date. Returns 0 on success, otherwise -1 with
 * <err> filled, which never contains the payload.
 */
static int cloudauth_s3_creds_response(const struct cloudauth_profile *prof, int status, const struct buffer *body,
                                       struct buffer *token, unsigned int *expire, char **err)
{
	char date[64];
	int len;

	TRACE_ENTER(CLOUDAUTH_EV_FETCH, NULL, prof);

	cloudauth_s3_trace_payload(prof, body);
	if (status < 200 || status >= 300) {
		memprintf(err, "the credential endpoint answered with status %d", status);
		goto error;
	}

	if (cloudauth_s3_add_cred_part(token, body, "$.AccessKeyId") < 0) {
		memprintf(err, "missing or invalid \"AccessKeyId\" in the credentials");
		goto error;
	}
	if (!chunk_memcat(token, ":", 1))
		goto full;
	if (cloudauth_s3_add_cred_part(token, body, "$.SecretAccessKey") < 0) {
		memprintf(err, "missing or invalid \"SecretAccessKey\" in the credentials");
		goto error;
	}
	if (!chunk_memcat(token, ":", 1))
		goto full;
	if (cloudauth_s3_add_cred_part(token, body, "$.Token") < 0) {
		memprintf(err, "missing or invalid \"Token\" in the credentials");
		goto error;
	}

	/* without expiration date, the credentials are refreshed periodically */
	*expire = 0;
	len = mjson_get_string(b_orig(body), b_data(body), "$.Expiration", date, sizeof(date));
	if (len < 0) {
		TRACE_STATE("no expiration date in the credentials", CLOUDAUTH_EV_FETCH, NULL, prof);
		TRACE_LEAVE(CLOUDAUTH_EV_FETCH, NULL, prof);
		return 0;
	}
	if (cloudauth_parse_iso_date(ist2(date, len), expire) < 0) {
		memprintf(err, "invalid \"Expiration\" in the credentials");
		goto error;
	}
	TRACE_LEAVE(CLOUDAUTH_EV_FETCH, NULL, prof);
	return 0;

  full:
	memprintf(err, "the credentials do not fit in a buffer");
  error:
	TRACE_DEVEL("leaving on error", CLOUDAUTH_EV_FETCH, NULL, prof);
	return -1;
}

/* Prepares in <req> the request of an access key for profile <prof> to the
 * AWS Security Token Service, exchanging the federated token of the workload
 * for a temporary access key of the role "s3-role-arn"
 * (AssumeRoleWithWebIdentity). The request is not signed, the federated token
 * being the proof of identity. The endpoint is "token-endpoint", otherwise the
 * regional endpoint of the region of the profile. Returns 0 on success,
 * otherwise -1 with <err> filled.
 */
static int cloudauth_s3_wi_request(const struct cloudauth_profile *prof, struct cloudauth_fetch_req *req,
                                   char **err)
{
	const struct cloudauth_s3_ctx *ctx = cloudauth_s3_ctx(prof);
	const char *session = ctx->role_session_name ? ctx->role_session_name : CLOUDAUTH_S3_ROLE_SESSION_NAME;
	struct ist detail, role = ist(ctx->role_arn), name = ist(session);

	TRACE_ENTER(CLOUDAUTH_EV_FETCH, NULL, prof);

	/* checked once the section is parsed */
	BUG_ON(!ctx->role_arn);
	BUG_ON(!prof->fetch.endpoint && !prof->region);

	req->meth = HTTP_METH_POST;
	if (prof->fetch.endpoint) {
		if (!chunk_strcat(req->url, prof->fetch.endpoint))
			goto full;
	}
	else {
		if (!chunk_strcat(req->url, CLOUDAUTH_S3_STS_HOST_PREFIX))
			goto full;
		if (!chunk_strcat(req->url, prof->region))
			goto full;
		if (!chunk_strcat(req->url, CLOUDAUTH_S3_STS_HOST_SUFFIX))
			goto full;
	}

	/* the endpoint carries no secret, but its query string is not traced */
	detail = iststop(ist2(req->url->area, req->url->data), '?');
	TRACE_STATE("security token service endpoint", CLOUDAUTH_EV_FETCH, NULL, prof, &detail);
	/* the role and the session name are not secrets */
	TRACE_STATE("role assumed", CLOUDAUTH_EV_FETCH, NULL, prof, &role);
	TRACE_STATE("role session name", CLOUDAUTH_EV_FETCH, NULL, prof, &name);

	if (cloudauth_form_add(req->body, "Action", ist("AssumeRoleWithWebIdentity")) < 0)
		goto full;
	if (cloudauth_form_add(req->body, "Version", ist(CLOUDAUTH_S3_STS_VERSION)) < 0)
		goto full;
	if (cloudauth_form_add(req->body, "RoleArn", ist(ctx->role_arn)) < 0)
		goto full;
	if (cloudauth_form_add(req->body, "RoleSessionName", ist(session)) < 0)
		goto full;
	if (cloudauth_form_add(req->body, "WebIdentityToken", req->inputs[CLOUDAUTH_S3_INPUT_FEDERATED_TOKEN]) < 0)
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

/* The AWS Security Token Service only answers in XML (its API uses the AWS
 * query protocol). No XML parser is used to read it, on purpose:
 *
 *   - neither HAProxy nor the libraries it embeds provide one, and an
 *     external library such as libxml2 or expat would be a new build
 *     dependency for a single document. Such libraries also support far more
 *     than needed here (entities, DTDs, external references, namespaces),
 *     which is the very attack surface of the XML parsers (entity expansion,
 *     XXE), and they allocate memory on their own while HAProxy uses its own
 *     allocators at runtime;
 *
 *   - the document is the fixed response of a single trusted endpoint (see
 *     cloudauth_s3_check_endpoint()), and only four elements without
 *     attribute are needed, whose values are made of visible ASCII characters
 *     which never need to be escaped in XML (identifiers, base64 strings and
 *     a date).
 *
 * So the elements are only located by their start and end tags. A start tag
 * cannot be found in the text of another element, where '<' is always
 * escaped. Their content is never decoded but strictly checked instead:
 * anything else than the expected characters, such as an entity, a CDATA
 * section, a comment or a nested element, is rejected. The worst case of an
 * unexpected document is a failed fetch, reported and retried, never a wrong
 * access key.
 */

/* Sets <out> to the content of the first element <name> of the XML document
 * <doc>, between its start tag "<name>", without attribute, and its end tag
 * "</name>". <name> is a constant shorter than 32 characters. Returns 0 on
 * success, -1 if the element is not found.
 */
static int cloudauth_s3_xml_elem(const struct ist doc, const char *name, struct ist *out)
{
	char stag[34], etag[35];
	struct ist start, end;
	int slen, elen;

	slen = snprintf(stag, sizeof(stag), "<%s>", name);
	elen = snprintf(etag, sizeof(etag), "</%s>", name);
	/* the names are constants of the callers */
	BUG_ON(slen < 0 || slen >= (int)sizeof(stag) || elen < 0 || elen >= (int)sizeof(etag));

	start = istist(doc, ist2(stag, slen));
	if (!isttest(start))
		return -1;
	/* the start tag is at the beginning of <start>, so it may be skipped */
	start = istadv(start, slen);
	end = istist(start, ist2(etag, elen));
	if (!isttest(end))
		return -1;
	*out = ist2(istptr(start), istptr(end) - istptr(start));
	return 0;
}

/* Returns non-zero if <c> may be part of a value read from the XML response of
 * the AWS Security Token Service as is: a visible ASCII character, except the
 * '<' and '&' of the markup, which are never decoded, and the colon separating
 * the parts of the token of the sigv4 signer.
 */
static int cloudauth_s3_is_xml_char(int c)
{
	return isgraph(c) && c != '<' && c != '&' && c != ':';
}

/* Appends to <token> the content of the element <name> of the credentials
 * <creds> of the XML response of the AWS Security Token Service. Returns 0 on
 * success, -1 if it is missing, empty or invalid, or does not fit.
 */
static int cloudauth_s3_add_xml_part(struct buffer *token, const struct ist creds, const char *name)
{
	struct ist value;

	if (cloudauth_s3_xml_elem(creds, name, &value) < 0)
		return -1;
	if (!istlen(value))
		return -1;
	if (cloudauth_ist_check(value, cloudauth_s3_is_xml_char) >= 0)
		return -1;
	if (!chunk_istcat(token, value))
		return -1;
	return 0;
}

/* Fills <err> with the status <status> of the error response <doc> of the AWS
 * Security Token Service for profile <prof>, and with its error code, such as
 * "InvalidIdentityToken", if made of letters and digits, which is also traced.
 * The message is never reported, since it may contain parts of the request.
 */
static void cloudauth_s3_sts_error(const struct cloudauth_profile *prof, int status, const struct ist doc,
                                   char **err)
{
	struct ist code;

	if (cloudauth_s3_xml_elem(doc, "Code", &code) < 0)
		goto no_code;
	if (!istlen(code) || istlen(code) > 64)
		goto no_code;
	if (cloudauth_ist_check(code, isalnum) >= 0)
		goto no_code;
	TRACE_STATE("security token service error code", CLOUDAUTH_EV_FETCH, NULL, prof, &code, &status);
	memprintf(err, "the security token service answered with status %d (%.*s)",
	          status, (int)istlen(code), istptr(code));
	return;

  no_code:
	TRACE_STATE("no error code in the response", CLOUDAUTH_EV_FETCH, NULL, prof, NULL, &status);
	memprintf(err, "the security token service answered with status %d", status);
}

/* Extracts the temporary access key and its expiration date from the XML
 * response of the AWS Security Token Service, of status <status> and payload
 * <body>, into <token>, as "<access-key-id>:<secret>:<session-token>", and
 * <expire>. The "AccessKeyId", "SecretAccessKey", "SessionToken" and
 * "Expiration" elements of the "Credentials" element are mandatory. Returns 0
 * on success, otherwise -1 with <err> filled, which never contains the
 * payload.
 */
static int cloudauth_s3_sts_response(const struct cloudauth_profile *prof, int status, const struct buffer *body,
                                     struct buffer *token, unsigned int *expire, char **err)
{
	const struct ist doc = ist2(b_orig(body), b_data(body));
	struct ist creds, date;

	TRACE_ENTER(CLOUDAUTH_EV_FETCH, NULL, prof);

	cloudauth_s3_trace_payload(prof, body);
	if (status < 200 || status >= 300) {
		cloudauth_s3_sts_error(prof, status, doc, err);
		goto error;
	}

	if (cloudauth_s3_xml_elem(doc, "Credentials", &creds) < 0) {
		memprintf(err, "missing \"Credentials\" in the response of the security token service");
		goto error;
	}
	TRACE_STATE("credentials element found", CLOUDAUTH_EV_FETCH, NULL, prof);
	if (cloudauth_s3_add_xml_part(token, creds, "AccessKeyId") < 0) {
		memprintf(err, "missing or invalid \"AccessKeyId\" in the credentials");
		goto error;
	}
	if (!chunk_memcat(token, ":", 1))
		goto full;
	if (cloudauth_s3_add_xml_part(token, creds, "SecretAccessKey") < 0) {
		memprintf(err, "missing or invalid \"SecretAccessKey\" in the credentials");
		goto error;
	}
	if (!chunk_memcat(token, ":", 1))
		goto full;
	if (cloudauth_s3_add_xml_part(token, creds, "SessionToken") < 0) {
		memprintf(err, "missing or invalid \"SessionToken\" in the credentials");
		goto error;
	}

	if (cloudauth_s3_xml_elem(creds, "Expiration", &date) < 0) {
		memprintf(err, "missing \"Expiration\" in the credentials");
		goto error;
	}
	if (cloudauth_parse_iso_date(date, expire) < 0) {
		memprintf(err, "invalid \"Expiration\" in the credentials");
		goto error;
	}
	TRACE_LEAVE(CLOUDAUTH_EV_FETCH, NULL, prof);
	return 0;

  full:
	memprintf(err, "the credentials do not fit in a buffer");
  error:
	TRACE_DEVEL("leaving on error", CLOUDAUTH_EV_FETCH, NULL, prof);
	return -1;
}

#ifdef DEBUG_UNIT
/* Unit test of cloudauth_s3_sts_response(), run with "-U cloudauth_s3_sts".
 * Returns 0 on success, 1 on failure.
 */
static int cloudauth_s3_sts_unittest(int argc, char **argv)
{
	static const struct {
		const char *body;
		int ret;
		const char *token;
	} tests[] = {
		{ "<R><Credentials><SessionToken>c+/=</SessionToken><SecretAccessKey>b/+</SecretAccessKey>"
		  "<Expiration>2100-01-01T00:00:00Z</Expiration><AccessKeyId>A</AccessKeyId></Credentials></R>",
		  0, "A:b/+:c+/=" },
		{ "<Credentials>\n  <AccessKeyId>A</AccessKeyId>\n  <SecretAccessKey>b</SecretAccessKey>\n"
		  "  <SessionToken>c</SessionToken>\n  <Expiration>2100-01-01T00:00:00.000Z</Expiration>\n</Credentials>",
		  0, "A:b:c" },
		/* the elements are only read inside "Credentials" */
		{ "<AccessKeyId>X</AccessKeyId><Credentials><SecretAccessKey>b</SecretAccessKey>"
		  "<SessionToken>c</SessionToken><Expiration>2100-01-01T00:00:00Z</Expiration></Credentials>",
		  -1, NULL },
		/* entities, CDATA sections, comments, nested elements and spaces */
		{ "<Credentials><AccessKeyId>A</AccessKeyId><SecretAccessKey>b&amp;c</SecretAccessKey>"
		  "<SessionToken>c</SessionToken><Expiration>2100-01-01T00:00:00Z</Expiration></Credentials>",
		  -1, NULL },
		{ "<Credentials><AccessKeyId>A</AccessKeyId><SecretAccessKey><![CDATA[b]]></SecretAccessKey>"
		  "<SessionToken>c</SessionToken><Expiration>2100-01-01T00:00:00Z</Expiration></Credentials>",
		  -1, NULL },
		{ "<Credentials><AccessKeyId>A<!-- x --></AccessKeyId><SecretAccessKey>b</SecretAccessKey>"
		  "<SessionToken>c</SessionToken><Expiration>2100-01-01T00:00:00Z</Expiration></Credentials>",
		  -1, NULL },
		{ "<Credentials><AccessKeyId><Id>A</Id></AccessKeyId><SecretAccessKey>b</SecretAccessKey>"
		  "<SessionToken>c</SessionToken><Expiration>2100-01-01T00:00:00Z</Expiration></Credentials>",
		  -1, NULL },
		{ "<Credentials><AccessKeyId> A </AccessKeyId><SecretAccessKey>b</SecretAccessKey>"
		  "<SessionToken>c</SessionToken><Expiration>2100-01-01T00:00:00Z</Expiration></Credentials>",
		  -1, NULL },
		/* a colon, an empty value, an attribute, a missing end tag or element */
		{ "<Credentials><AccessKeyId>A</AccessKeyId><SecretAccessKey>b:c</SecretAccessKey>"
		  "<SessionToken>c</SessionToken><Expiration>2100-01-01T00:00:00Z</Expiration></Credentials>",
		  -1, NULL },
		{ "<Credentials><AccessKeyId>A</AccessKeyId><SecretAccessKey>b</SecretAccessKey>"
		  "<SessionToken></SessionToken><Expiration>2100-01-01T00:00:00Z</Expiration></Credentials>",
		  -1, NULL },
		{ "<Credentials><AccessKeyId a=\"1\">A</AccessKeyId><SecretAccessKey>b</SecretAccessKey>"
		  "<SessionToken>c</SessionToken><Expiration>2100-01-01T00:00:00Z</Expiration></Credentials>",
		  -1, NULL },
		{ "<Credentials><AccessKeyId>A</AccessKeyId><SecretAccessKey>b</SecretAccessKey>"
		  "<SessionToken>c</SessionToken><Expiration>2100-01-01T00:00:00Z</Expiration>",
		  -1, NULL },
		{ "<Credentials><AccessKeyId>A</AccessKeyId><SecretAccessKey>b</SecretAccessKey>"
		  "<SessionToken>c</SessionToken></Credentials>",
		  -1, NULL },
		{ "<Credentials><AccessKeyId>A</AccessKeyId><SecretAccessKey>b</SecretAccessKey>"
		  "<SessionToken>c</SessionToken><Expiration>2100-01-01</Expiration></Credentials>",
		  -1, NULL },
		{ "", -1, NULL },
	};
	struct buffer body, *token;
	unsigned int expire;
	char *err = NULL;
	int i, ret, failed = 0;

	token = alloc_trash_chunk();
	if (!token)
		return 1;
	for (i = 0; i < sizeof(tests) / sizeof(*tests); i++) {
		body = b_make((char *)tests[i].body, strlen(tests[i].body), 0, strlen(tests[i].body));
		chunk_reset(token);
		expire = 0;
		ret = cloudauth_s3_sts_response(NULL, 200, &body, token, &expire, &err);
		ha_free(&err);
		if (ret != tests[i].ret ||
		    (ret == 0 && (!isteq(ist2(token->area, token->data), ist(tests[i].token)) || expire != 4102444800U))) {
			printf("test %d: cloudauth_s3_sts_response() = %d (%.*s, %u), expected %d (%s)\n",
			       i, ret, (int)token->data, token->area, expire, tests[i].ret,
			       tests[i].token ? tests[i].token : "-");
			failed = 1;
		}
	}
	free_trash_chunk(token);
	return failed;
}
REGISTER_UNITTEST("cloudauth_s3_sts", cloudauth_s3_sts_unittest);
#endif

/* Appends to <url> the URL of the EC2 Instance Metadata Service of profile
 * <prof>, "token-endpoint" or the default one, without its trailing slashes,
 * followed by <path>. Returns 0 on success, -1 if there is no more room.
 */
static int cloudauth_s3_imds_url(const struct cloudauth_profile *prof, struct buffer *url, const char *path)
{
	const char *base = prof->fetch.endpoint ? prof->fetch.endpoint : CLOUDAUTH_S3_IMDS_ENDPOINT;
	size_t len = strlen(base);

	/* the scheme ("http://", checked once the section is parsed) and the
	 * first character of the host are always kept
	 */
	while (len > 8 && base[len - 1] == '/')
		len--;
	if (!chunk_memcat(url, base, len))
		return -1;
	if (!chunk_strcat(url, path))
		return -1;
	return 0;
}

/* Sets <session> and <role> to what the previous requests of the fetch in
 * progress of profile <prof> from the EC2 Instance Metadata Service kept: the
 * session token, followed by the name of the IAM role after a line feed once
 * it is known, <role> being empty before.
 */
static void cloudauth_s3_imds_carry(const struct cloudauth_profile *prof, struct ist *session, struct ist *role)
{
	struct ist carry;

	/* the session token is always kept by the first request */
	BUG_ON(!prof->fetch.carry);
	carry = ist2(prof->fetch.carry->area, prof->fetch.carry->data);
	*session = iststop(carry, '\n');
	*role = istadv(carry, istlen(*session));
	if (istlen(*role))
		*role = istnext(*role);
}

/* Returns non-zero if <c> may be part of the name of an IAM role: a letter, a
 * digit, or one of "_+=,.@-".
 */
static int cloudauth_s3_is_role_char(int c)
{
	return isalnum(c) || (c && strchr("_+=,.@-", c));
}

/* Prepares in <req> the request <prof->fetch.step> of the fetch of an access
 * key for profile <prof> from the EC2 Instance Metadata Service (IMDSv2):
 * a session token, then the name of the IAM role of the instance with this
 * token, then the credentials of this role. Returns 0 on success, otherwise
 * -1 with <err> filled.
 */
static int cloudauth_s3_imds_request(const struct cloudauth_profile *prof, struct cloudauth_fetch_req *req,
                                     char **err)
{
	struct ist session, role, detail;

	TRACE_ENTER(CLOUDAUTH_EV_FETCH, NULL, prof);

	/* the response of the credentials ends the fetch */
	BUG_ON(prof->fetch.step > CLOUDAUTH_S3_IMDS_STEP_CREDS);

	switch (prof->fetch.step) {
	case CLOUDAUTH_S3_IMDS_STEP_TOKEN:
		req->meth = HTTP_METH_PUT;
		if (cloudauth_s3_imds_url(prof, req->url, "/latest/api/token") < 0)
			goto full;
		if (cloudauth_fetch_add_hdr(req, ist("x-aws-ec2-metadata-token-ttl-seconds"),
		                            ist(CLOUDAUTH_S3_IMDS_TOKEN_TTL)) < 0)
			goto full;
		break;
	case CLOUDAUTH_S3_IMDS_STEP_ROLE:
	case CLOUDAUTH_S3_IMDS_STEP_CREDS:
		cloudauth_s3_imds_carry(prof, &session, &role);
		if (cloudauth_s3_imds_url(prof, req->url, "/latest/meta-data/iam/security-credentials/") < 0)
			goto full;
		/* the role is only known for the credentials */
		if (!chunk_istcat(req->url, role))
			goto full;
		if (cloudauth_fetch_add_hdr(req, ist("x-aws-ec2-metadata-token"), session) < 0)
			goto full;
		break;
	}

	/* the URL carries no secret, only the name of the role */
	detail = ist2(req->url->area, req->url->data);
	TRACE_STATE("instance metadata service request", CLOUDAUTH_EV_FETCH, NULL, prof, &detail);
	TRACE_LEAVE(CLOUDAUTH_EV_FETCH, NULL, prof);
	return 0;

  full:
	memprintf(err, "the request does not fit in a buffer");
	TRACE_DEVEL("leaving on error", CLOUDAUTH_EV_FETCH, NULL, prof);
	return -1;
}

/* Extracts from the response of status <status> and payload <body> of the
 * request <prof->fetch.step> of the EC2 Instance Metadata Service for profile
 * <prof> what the next request needs into <token>: the session token, then
 * the session token and the name of the IAM role separated by a line feed,
 * returning 1. The last response is the JSON credentials of the role, read by
 * cloudauth_s3_creds_response() into <token> and <expire>, returning 0.
 * Returns -1 with <err> filled on failure, which never contains the payload.
 */
static int cloudauth_s3_imds_response(const struct cloudauth_profile *prof, int status, const struct buffer *body,
                                      struct buffer *token, unsigned int *expire, char **err)
{
	struct ist data = ist2(b_orig(body), b_data(body));
	struct ist session, role;

	TRACE_ENTER(CLOUDAUTH_EV_FETCH, NULL, prof);

	switch (prof->fetch.step) {
	case CLOUDAUTH_S3_IMDS_STEP_TOKEN:
		cloudauth_s3_trace_payload(prof, body);
		if (status < 200 || status >= 300) {
			memprintf(err, "the instance metadata service answered with status %d to the session token request",
			          status);
			goto error;
		}
		/* the token is sent as is in a header, and is followed by the
		 * name of the role after a line feed once it is known
		 */
		if (!istlen(data) || istlen(data) > CLOUDAUTH_S3_IMDS_MAX_TOKEN_LEN) {
			memprintf(err, "invalid session token from the instance metadata service");
			goto error;
		}
		if (cloudauth_ist_check(data, isgraph) >= 0) {
			memprintf(err, "invalid session token from the instance metadata service");
			goto error;
		}
		if (!chunk_istcat(token, data))
			goto full;
		TRACE_LEAVE(CLOUDAUTH_EV_FETCH, NULL, prof);
		return 1;

	case CLOUDAUTH_S3_IMDS_STEP_ROLE:
		cloudauth_s3_trace_payload(prof, body);
		if (status == 404) {
			memprintf(err, "no IAM role is attached to the instance");
			goto error;
		}
		if (status < 200 || status >= 300) {
			memprintf(err, "the instance metadata service answered with status %d to the role request", status);
			goto error;
		}
		/* one role per line, the instance profile having only one */
		role = iststop(iststop(data, '\n'), '\r');
		if (!istlen(role) || istlen(role) > CLOUDAUTH_S3_ROLE_NAME_MAX_LEN) {
			memprintf(err, "invalid IAM role from the instance metadata service");
			goto error;
		}
		if (cloudauth_ist_check(role, cloudauth_s3_is_role_char) >= 0) {
			memprintf(err, "invalid IAM role from the instance metadata service");
			goto error;
		}
		/* the name of the role is not a secret */
		TRACE_STATE("IAM role of the instance", CLOUDAUTH_EV_FETCH, NULL, prof, &role);
		cloudauth_s3_imds_carry(prof, &session, &data);
		if (!chunk_istcat(token, session))
			goto full;
		if (!chunk_memcat(token, "\n", 1))
			goto full;
		if (!chunk_istcat(token, role))
			goto full;
		TRACE_LEAVE(CLOUDAUTH_EV_FETCH, NULL, prof);
		return 1;
	}

	if (cloudauth_s3_creds_response(prof, status, body, token, expire, err) < 0)
		goto error;
	TRACE_LEAVE(CLOUDAUTH_EV_FETCH, NULL, prof);
	return 0;

  full:
	memprintf(err, "the response does not fit in a buffer");
  error:
	TRACE_DEVEL("leaving on error", CLOUDAUTH_EV_FETCH, NULL, prof);
	return -1;
}

/* Reads the credential endpoint of the Amazon ECS tasks for profile <prof>
 * from the environment when the "container" token source is selected: the
 * relative URI of AWS_CONTAINER_CREDENTIALS_RELATIVE_URI, or the full URI of
 * AWS_CONTAINER_CREDENTIALS_FULL_URI with the authorization token of
 * AWS_CONTAINER_AUTHORIZATION_TOKEN if set, which is removed from the
 * environment once the configuration is parsed. Returns 0 on success,
 * otherwise -1 with <err> filled.
 */
static int cloudauth_s3_container_init(struct cloudauth_profile *prof, char **err)
{
	struct cloudauth_s3_ctx *ctx = cloudauth_s3_ctx(prof);
	const char *relative = getenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI");
	const char *full = getenv("AWS_CONTAINER_CREDENTIALS_FULL_URI");
	const char *token = getenv("AWS_CONTAINER_AUTHORIZATION_TOKEN");

	if (relative && *relative) {
		memprintf(&ctx->endpoint, "%s%s", CLOUDAUTH_S3_ECS_HOST, relative);
		if (!ctx->endpoint)
			goto oom;
		return 0;
	}
	if (!full || !*full)
		return 0;

	ctx->endpoint = strdup(full);
	if (!ctx->endpoint)
		goto oom;
	if (!token || !*token)
		return 0;
	ctx->auth_token = istdup(ist(token));
	if (!isttest(ctx->auth_token))
		goto oom;
	if (cloudauth_register_secret_env("AWS_CONTAINER_AUTHORIZATION_TOKEN") < 0)
		goto oom;
	return 0;

  oom:
	memprintf(err, "out of memory");
	return -1;
}

/* Reads the credential endpoint of the EKS Pod Identity Agent for profile
 * <prof> from AWS_CONTAINER_CREDENTIALS_FULL_URI when the "pod-identity" token
 * source is selected, if set. Returns 0 on success, otherwise -1 with <err>
 * filled.
 */
static int cloudauth_s3_pod_identity_init(struct cloudauth_profile *prof, char **err)
{
	struct cloudauth_s3_ctx *ctx = cloudauth_s3_ctx(prof);
	const char *full = getenv("AWS_CONTAINER_CREDENTIALS_FULL_URI");

	if (!full || !*full)
		return 0;
	ctx->endpoint = strdup(full);
	if (!ctx->endpoint) {
		memprintf(err, "out of memory");
		return -1;
	}
	return 0;
}

/* The inputs of the "pod-identity" token source */
static const char * const cloudauth_s3_pod_identity_inputs[] = {
	[CLOUDAUTH_S3_INPUT_AUTH_TOKEN] = "authorization-token",
	NULL
};

/* The inputs of the "workload-identity" token source */
static const char * const cloudauth_s3_wi_inputs[] = {
	[CLOUDAUTH_S3_INPUT_FEDERATED_TOKEN] = "federated-token",
	NULL
};

/* The token sources of the S3 provider, indexed by enum cloudauth_s3_src */
static const struct cloudauth_source cloudauth_s3_sources[CLOUDAUTH_S3_SRC_ENTRIES + 1] = {
	[CLOUDAUTH_S3_SRC_CONTAINER] = {
		.name     = "container",
		.signers  = 1U << CLOUDAUTH_SIGNER_SIGV4,
		.flags    = CLOUDAUTH_SRC_F_ENDPOINT,
		.init     = cloudauth_s3_container_init,
		.request  = cloudauth_s3_container_request,
		.response = cloudauth_s3_creds_response,
	},
	[CLOUDAUTH_S3_SRC_POD_IDENTITY] = {
		.name     = "pod-identity",
		.signers  = 1U << CLOUDAUTH_SIGNER_SIGV4,
		.inputs   = cloudauth_s3_pod_identity_inputs,
		.flags    = CLOUDAUTH_SRC_F_ENDPOINT,
		.init     = cloudauth_s3_pod_identity_init,
		.request  = cloudauth_s3_pod_identity_request,
		.response = cloudauth_s3_creds_response,
	},
	[CLOUDAUTH_S3_SRC_WI] = {
		.name     = "workload-identity",
		.signers  = 1U << CLOUDAUTH_SIGNER_SIGV4,
		.inputs   = cloudauth_s3_wi_inputs,
		.flags    = CLOUDAUTH_SRC_F_ENDPOINT,
		.request  = cloudauth_s3_wi_request,
		.response = cloudauth_s3_sts_response,
	},
	[CLOUDAUTH_S3_SRC_IMDS] = {
		.name     = "instance-metadata",
		.signers  = 1U << CLOUDAUTH_SIGNER_SIGV4,
		.flags    = CLOUDAUTH_SRC_F_ENDPOINT,
		.request  = cloudauth_s3_imds_request,
		.response = cloudauth_s3_imds_response,
	},
	[CLOUDAUTH_S3_SRC_ENTRIES] = { .name = NULL }
};

/* Returns non-zero if profile <prof> fetches its access key from the S3 token
 * source <src>.
 */
static int cloudauth_s3_uses_src(const struct cloudauth_profile *prof, enum cloudauth_s3_src src)
{
	return prof->token_src == CLOUDAUTH_SRC_FETCH && prof->fetch.source == &cloudauth_s3_sources[src];
}

/* The credential agents of ECS and EKS, as the AWS SDKs accept them */
static const struct cloudauth_s3_agents cloudauth_s3_container_agents = {
	.ipv4 = { 0xa9feaa02, 0xa9feaa17 },  /* 169.254.170.2, 169.254.170.23 */
	.ipv6 = { 0xfd, 0x00, 0x0e, 0xc2, [15] = 0x23 },  /* fd00:ec2::23 */
	.desc = "container credential agents (169.254.170.2, 169.254.170.23, fd00:ec2::23)",
};

/* The EC2 Instance Metadata Service */
static const struct cloudauth_s3_agents cloudauth_s3_imds_agents = {
	.ipv4 = { 0xa9fea9fe },              /* 169.254.169.254 */
	.ipv6 = { 0xfd, 0x00, 0x0e, 0xc2, [14] = 0x02, [15] = 0x54 },  /* fd00:ec2::254 */
	.desc = "instance metadata service (169.254.169.254, fd00:ec2::254)",
};

/* Returns non-zero if the credential endpoint <url> may receive a secret, such
 * as the authorization token of the containers: an HTTPS URL, or an HTTP one
 * to the loopback or to one of the local <agents> of AWS, as the AWS SDKs
 * require, so that the secret never crosses the network in clear.
 */
static int cloudauth_s3_is_trusted_endpoint(const char *url, const struct cloudauth_s3_agents *agents)
{
	struct in6_addr addr6;
	struct in_addr addr;
	const char *host, *end;
	char name[INET6_ADDRSTRLEN];
	size_t len;
	int i;

	if (strncmp(url, "https://", 8) == 0)
		return 1;
	if (strncmp(url, "http://", 7) != 0)
		return 0;

	host = url + 7;
	if (*host == '[') {
		host++;
		end = strchr(host, ']');
		if (!end)
			return 0;
	}
	else
		end = host + strcspn(host, ":/?#");
	len = end - host;
	if (!len || len >= sizeof(name))
		return 0;
	memcpy(name, host, len);
	name[len] = 0;

	if (strcasecmp(name, "localhost") == 0)
		return 1;
	if (inet_pton(AF_INET, name, &addr) == 1) {
		if ((ntohl(addr.s_addr) >> 24) == 127)
			return 1;
		/* the list ends with a null address */
		for (i = 0; i < sizeof(agents->ipv4) / sizeof(*agents->ipv4) && agents->ipv4[i]; i++) {
			if (ntohl(addr.s_addr) == agents->ipv4[i])
				return 1;
		}
		return 0;
	}
	if (inet_pton(AF_INET6, name, &addr6) == 1)
		return IN6_IS_ADDR_LOOPBACK(&addr6) || memcmp(&addr6, agents->ipv6, sizeof(agents->ipv6)) == 0;
	return 0;
}

/* Allocates the S3 settings of profile <prof>. Returns 0 on success, otherwise
 * -1 with <err> filled.
 */
static int cloudauth_s3_init(struct cloudauth_profile *prof, char **err)
{
	prof->provider_ctx = calloc(1, sizeof(struct cloudauth_s3_ctx));
	if (!prof->provider_ctx) {
		memprintf(err, "out of memory");
		return -1;
	}
	return 0;
}

/* Checks that the credential endpoint <endpoint>, which receives a secret, is
 * an HTTP or HTTPS URL, and is trusted for the local <agents> of AWS (see
 * cloudauth_s3_is_trusted_endpoint()). Returns 0 on success, otherwise -1 with
 * <err> filled.
 */
static int cloudauth_s3_check_endpoint(const char *endpoint, const struct cloudauth_s3_agents *agents, char **err)
{
	if (!cloudauth_is_http_url(endpoint)) {
		memprintf(err, "invalid credential endpoint '%s', expects an HTTP or HTTPS URL", endpoint);
		return -1;
	}
	if (!cloudauth_s3_is_trusted_endpoint(endpoint, agents)) {
		memprintf(err, "the credential endpoint '%s' must use HTTPS, or HTTP to the loopback or to the %s",
		          endpoint, agents->desc);
		return -1;
	}
	return 0;
}

/* Checks the S3 settings of profile <prof> once its section is parsed: the
 * role of "workload-identity" must be set, and the credential endpoint of the
 * containers must be known and trusted, like the one of the Security Token
 * Service set with "token-endpoint". Returns 0 on success, otherwise -1 with
 * <err> filled.
 */
static int cloudauth_s3_check(struct cloudauth_profile *prof, char **err)
{
	const struct cloudauth_s3_ctx *ctx = cloudauth_s3_ctx(prof);
	const char *endpoint;
	int wi;

	wi = cloudauth_s3_uses_src(prof, CLOUDAUTH_S3_SRC_WI);
	if (!wi && (ctx->role_arn || ctx->role_session_name)) {
		memprintf(err, "'s3-role-arn' and 's3-role-session-name' are only used by the 'workload-identity' token source");
		return -1;
	}
	if (wi && !ctx->role_arn) {
		memprintf(err, "the 'workload-identity' token source requires 's3-role-arn'");
		return -1;
	}
	if (wi) {
		/* the default endpoint is HTTPS */
		if (!prof->fetch.endpoint)
			return 0;
		return cloudauth_s3_check_endpoint(prof->fetch.endpoint, &cloudauth_s3_container_agents, err);
	}
	if (cloudauth_s3_uses_src(prof, CLOUDAUTH_S3_SRC_IMDS)) {
		/* the session token grants access to the metadata */
		if (!prof->fetch.endpoint)
			return 0;
		return cloudauth_s3_check_endpoint(prof->fetch.endpoint, &cloudauth_s3_imds_agents, err);
	}

	if (cloudauth_s3_uses_src(prof, CLOUDAUTH_S3_SRC_POD_IDENTITY))
		endpoint = cloudauth_s3_container_endpoint(prof, CLOUDAUTH_S3_POD_IDENTITY_ENDPOINT);
	else if (cloudauth_s3_uses_src(prof, CLOUDAUTH_S3_SRC_CONTAINER))
		endpoint = cloudauth_s3_container_endpoint(prof, NULL);
	else
		return 0;
	if (!endpoint) {
		memprintf(err, "the 'container' token source requires AWS_CONTAINER_CREDENTIALS_RELATIVE_URI or "
		          "AWS_CONTAINER_CREDENTIALS_FULL_URI in the environment, or 'token-endpoint'");
		return -1;
	}
	if (cloudauth_s3_check_endpoint(endpoint, &cloudauth_s3_container_agents, err) < 0)
		return -1;
	if (!isttest(ctx->auth_token))
		return 0;
	/* the token is sent as is in a header */
	if (cloudauth_ist_check(ctx->auth_token, isprint) >= 0) {
		memprintf(err, "invalid AWS_CONTAINER_AUTHORIZATION_TOKEN, expects visible characters and spaces");
		return -1;
	}
	return 0;
}

/* Releases the S3 settings of profile <prof> */
static void cloudauth_s3_release(struct cloudauth_profile *prof)
{
	struct cloudauth_s3_ctx *ctx = prof->provider_ctx;

	if (!ctx)
		return;
	ha_free(&ctx->endpoint);
	cloudauth_free_secret(&ctx->auth_token);
	ha_free(&ctx->role_arn);
	ha_free(&ctx->role_session_name);
	ha_free(&prof->provider_ctx);
}

struct cloudauth_provider cloudauth_s3_provider = {
	.name        = "s3",
	.signers     = 1U << CLOUDAUTH_SIGNER_SIGV4,
	.init        = cloudauth_s3_init,
	.check       = cloudauth_s3_check,
	.release     = cloudauth_s3_release,
	.sources     = cloudauth_s3_sources,
	.sigv4       = &cloudauth_s3_sigv4,
};

INITCALL1(STG_REGISTER, cloudauth_register_provider, &cloudauth_s3_provider);
REGISTER_BUILD_OPTS("Built with the cloudauth provider: s3 (S3 compatible storages).");

/* Returns the S3 settings of the profile being parsed, or NULL with <err>
 * filled if it does not use "provider s3", <kw> being the keyword parsed.
 */
static struct cloudauth_s3_ctx *cloudauth_s3_cfg_ctx(const char *kw, char **err)
{
	struct cloudauth_profile *prof = cloudauth_cfg_profile();

	if (!prof || prof->provider != &cloudauth_s3_provider) {
		memprintf(err, "'%s' requires 'provider s3' first.", kw);
		return NULL;
	}
	return prof->provider_ctx;
}

/* Returns non-zero if <arn> is the ARN of a role accepted by the AWS Security
 * Token Service: "arn:" followed by visible ASCII characters, 20 to 2048
 * characters long.
 */
static int cloudauth_s3_is_role_arn(const char *arn)
{
	size_t len = strlen(arn);

	if (len < CLOUDAUTH_S3_ROLE_ARN_MIN_LEN || len > CLOUDAUTH_S3_ROLE_ARN_MAX_LEN)
		return 0;
	if (strncmp(arn, "arn:", 4) != 0)
		return 0;
	return cloudauth_ist_check(ist2(arn, len), isgraph) < 0;
}

/* Returns non-zero if <name> is a role session name accepted by the AWS
 * Security Token Service: 2 to 64 letters, digits and "_+=,.@-" characters.
 */
static int cloudauth_s3_is_role_session_name(const char *name)
{
	size_t len = strlen(name);

	if (len < CLOUDAUTH_S3_ROLE_SESSION_MIN_LEN || len > CLOUDAUTH_S3_ROLE_SESSION_MAX_LEN)
		return 0;
	return strspn(name, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_+=,.@-") == len;
}

/* Parses the "s3-role-arn" keyword: the ARN of the IAM role assumed by "token
 * workload-identity", either set directly or read from an environment variable
 * with "env:<variable>" like the one set by IRSA.
 */
static int cfg_parse_cloudauth_s3_role_arn(char **args, int section_type, struct proxy *curpx,
                                           const struct proxy *defpx, const char *file, int linenum,
                                           char **err)
{
	struct cloudauth_s3_ctx *ctx = cloudauth_s3_cfg_ctx(args[0], err);

	if (!ctx)
		return ERR_ALERT | ERR_FATAL;
	return cloudauth_cfg_str(args, &ctx->role_arn, 1, cloudauth_s3_is_role_arn, "role ARN",
	                         "'arn:' followed by visible characters, such as "
	                         "'arn:aws:iam::123456789012:role/name'", err);
}

/* Parses the "s3-role-session-name" keyword: the name of the role sessions of
 * "token workload-identity", either set directly or read from an environment
 * variable with "env:<variable>".
 */
static int cfg_parse_cloudauth_s3_role_session_name(char **args, int section_type, struct proxy *curpx,
                                                    const struct proxy *defpx, const char *file, int linenum,
                                                    char **err)
{
	struct cloudauth_s3_ctx *ctx = cloudauth_s3_cfg_ctx(args[0], err);

	if (!ctx)
		return ERR_ALERT | ERR_FATAL;
	return cloudauth_cfg_str(args, &ctx->role_session_name, 1, cloudauth_s3_is_role_session_name,
	                         "role session name", "2 to 64 letters, digits or '_+=,.@-'", err);
}

static struct cfg_kw_list cfg_kws = { ILH, {
	{ CLOUDAUTH_CFG_SECTION, "s3-role-arn",          cfg_parse_cloudauth_s3_role_arn },
	{ CLOUDAUTH_CFG_SECTION, "s3-role-session-name", cfg_parse_cloudauth_s3_role_session_name },
	{ 0, NULL, NULL },
}};

INITCALL1(STG_REGISTER, cloudauth_register_keywords, &cfg_kws);
