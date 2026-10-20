/*
 * Cloud storage authentication: Signature Version 4 (sigv4).
 *
 * Copyright 2026 Aleksandar Lazic <al-haproxy@none.at>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 * The requests are signed with an HMAC key, made of an access key identifier
 * and a secret, and of a session token for the temporary keys, as Amazon S3 and the storages compatible with it expect it
 * ("AWS Signature Version 4"), and as Google Cloud Storage does with its HMAC
 * keys ("V4 signing process"). Each provider brings its variant (struct
 * cloudauth_sigv4). The payload is not signed ("UNSIGNED-PAYLOAD"), since the
 * request is signed before its payload is forwarded.
 */

#include <haproxy/api.h>
#include <haproxy/chunk.h>
#include <haproxy/clock.h>
#include <haproxy/cloudauth_common.h>
#include <haproxy/cloudauth_sigv4.h>
#include <haproxy/cloudauth_trace.h>
#include <haproxy/http_htx.h>
#include <haproxy/htx.h>
#include <haproxy/openssl-compat.h>
#include <haproxy/tools.h>
#include <haproxy/trace.h>

/* The hash of the payload of the signed requests, which is not signed */
#define CLOUDAUTH_SIGV4_UNSIGNED_PAYLOAD "UNSIGNED-PAYLOAD"

/* Splits the token of the sigv4 signer, "<access-key-id>:<secret>" or
 * "<access-key-id>:<secret>:<session-token>" for a temporary key, into <id>,
 * <secret> and <session>, which is empty for a permanent key. Returns 0 on
 * success, -1 if it is not in one of these forms.
 */
static int cloudauth_sigv4_split_token(const struct ist token, struct ist *id, struct ist *secret,
                                       struct ist *session)
{
	struct ist rest = token;
	const char *colon;

	colon = istchr(rest, ':');
	if (!colon)
		return -1;
	*id = ist2(istptr(rest), colon - istptr(rest));
	rest = istadv(rest, istlen(*id) + 1);

	colon = istchr(rest, ':');
	if (colon) {
		*secret = ist2(istptr(rest), colon - istptr(rest));
		*session = istadv(rest, istlen(*secret) + 1);
		if (!istlen(*session))
			return -1;
		if (istchr(*session, ':'))
			return -1;
	}
	else {
		*secret = rest;
		*session = ist2(istend(rest), 0);
	}
	if (!istlen(*id))
		return -1;
	if (!istlen(*secret))
		return -1;
	return 0;
}

/* Checks that <token> may be used by the sigv4 signer with the variant <v4>:
 * a session token is only accepted if the variant has a header for it.
 * Returns 0 on success, otherwise -1 with <err> filled. The token is never
 * reported.
 */
int cloudauth_sigv4_check_token(const struct ist token, const struct cloudauth_sigv4 *v4, char **err)
{
	struct ist id, secret, session;

	if (cloudauth_sigv4_split_token(token, &id, &secret, &session) < 0) {
		if (isttest(v4->token_hdr))
			memprintf(err, "the token of the 'sigv4' signer must be '<access-key-id>:<secret>' "
			          "or '<access-key-id>:<secret>:<session-token>'");
		else
			memprintf(err, "the token of the 'sigv4' signer must be '<access-key-id>:<secret>'");
		return -1;
	}
	if (istlen(session) && !isttest(v4->token_hdr)) {
		memprintf(err, "the session tokens are not supported, the token of the 'sigv4' signer must be "
		          "'<access-key-id>:<secret>'");
		return -1;
	}
	return 0;
}

/* Writes into <out> the <len> bytes of <in> encoded in lower case hexadecimal,
 * followed by a trailing zero, so <out> must have room for 2 * <len> + 1
 * bytes.
 */
static void cloudauth_sigv4_hex(const unsigned char *in, unsigned int len, char *out)
{
	static const char digits[] = "0123456789abcdef";
	unsigned int i;

	for (i = 0; i < len; i++) {
		out[2 * i]     = digits[in[i] >> 4];
		out[2 * i + 1] = digits[in[i] & 0xf];
	}
	out[2 * len] = 0;
}

/* Computes into <mac> the HMAC-SHA256 of <data> with the key <key> of
 * <key_len> bytes. <mac> must have room for SHA256_DIGEST_LENGTH bytes.
 * Returns 0 on success, -1 on failure.
 */
static int cloudauth_sigv4_hmac(const void *key, int key_len, const struct ist data, unsigned char *mac)
{
	unsigned int mac_len = 0;

	if (!HMAC(EVP_sha256(), key, key_len, (const unsigned char *)istptr(data), istlen(data), mac, &mac_len))
		return -1;
	if (mac_len != SHA256_DIGEST_LENGTH)
		return -1;
	return 0;
}

/* Appends to <out> the canonical URI of the path <path>: its URL-decoded
 * copy, made in the work chunk <work>, URL-encoded again so that only the
 * unreserved characters of RFC 3986 and the slashes are kept, or "/" if the
 * path is empty. The '+' is not a space in a path. Returns 0 on success, -1
 * on failure.
 */
static int cloudauth_sigv4_add_uri(struct buffer *out, struct ist path, struct buffer *work)
{
	struct ist seg;
	int len;

	if (!istlen(path)) {
		if (!chunk_memcat(out, "/", 1))
			return -1;
		return 0;
	}

	chunk_reset(work);
	if (!chunk_istcat(work, path))
		return -1;
	if (!chunk_memcat(work, "", 1))
		return -1;
	len = url_decode(work->area, 0);
	if (len < 0)
		return -1;
	path = ist2(work->area, len);

	while (1) {
		seg = iststop(path, '/');
		if (cloudauth_url_encode_cat(out, seg) < 0)
			return -1;
		if (istlen(seg) == istlen(path))
			break;
		if (!chunk_memcat(out, "/", 1))
			return -1;
		path = istadv(path, istlen(seg) + 1);
	}
	return 0;
}

/* Appends to <out> the canonical query string of the query string <query>,
 * without its leading question mark: its parameters URL-decoded then
 * URL-encoded again so that only the unreserved characters of RFC 3986 are
 * kept, sorted by name then by value once encoded, as "<name>=<value>"
 * separated by '&'. The work chunks <dec> and <enc> receive the decoded and
 * the encoded copies. Returns 0 on success, -1 on failure.
 */
static int cloudauth_sigv4_add_query(struct buffer *out, struct ist query, struct buffer *dec, struct buffer *enc)
{
	struct cloudauth_qparam params[CLOUDAUTH_SIGV4_MAX_PARAMS];
	struct cloudauth_qparam param;
	struct ist p;
	char *start;
	int nb = 0, i;

	chunk_reset(dec);
	chunk_reset(enc);
	while (istlen(query)) {
		p = istsplit(&query, '&');
		if (!istlen(p))
			continue;
		if (nb == CLOUDAUTH_SIGV4_MAX_PARAMS)
			return -1;
		if (cloudauth_qparam_decode(dec, p, &param) < 0)
			return -1;

		start = b_tail(enc);
		if (cloudauth_url_encode_cat(enc, param.name) < 0)
			return -1;
		params[nb].name = ist2(start, b_tail(enc) - start);
		start = b_tail(enc);
		if (cloudauth_url_encode_cat(enc, param.value) < 0)
			return -1;
		params[nb].value = ist2(start, b_tail(enc) - start);
		nb++;
	}

	qsort(params, nb, sizeof(*params), cloudauth_qparam_cmp);
	for (i = 0; i < nb; i++) {
		/* the parameters are separated by '&' */
		if (i) {
			if (!chunk_memcat(out, "&", 1))
				return -1;
		}
		if (!chunk_istcat(out, params[i].name))
			return -1;
		if (!chunk_memcat(out, "=", 1))
			return -1;
		if (!chunk_istcat(out, params[i].value))
			return -1;
	}
	return 0;
}

/* Appends to <out> the scope of the signatures of the day <day> in the region
 * <region> with the variant <v4>: "<day>/<region>/<service>/<request>".
 * Returns 0 on success, -1 on failure.
 */
static int cloudauth_sigv4_add_scope(struct buffer *out, const struct ist day, const char *region,
                                     const struct cloudauth_sigv4 *v4)
{
	if (!chunk_istcat(out, day))
		return -1;
	if (!chunk_memcat(out, "/", 1))
		return -1;
	if (!chunk_strcat(out, region))
		return -1;
	if (!chunk_memcat(out, "/", 1))
		return -1;
	if (!chunk_strcat(out, v4->service))
		return -1;
	if (!chunk_memcat(out, "/", 1))
		return -1;
	if (!chunk_strcat(out, v4->request))
		return -1;
	return 0;
}

/* Appends to <out> the names of the headers signed with the variant <v4>,
 * separated by semicolons, the session token one only if <session> is set.
 * Returns 0 on success, -1 on failure.
 */
static int cloudauth_sigv4_add_signed_hdrs(struct buffer *out, const struct cloudauth_sigv4 *v4, int session)
{
	if (!chunk_strcat(out, "host;"))
		return -1;
	if (!chunk_istcat(out, v4->hash_hdr))
		return -1;
	if (!chunk_memcat(out, ";", 1))
		return -1;
	if (!chunk_istcat(out, v4->date_hdr))
		return -1;
	if (!session)
		return 0;
	if (!chunk_memcat(out, ";", 1))
		return -1;
	if (!chunk_istcat(out, v4->token_hdr))
		return -1;
	return 0;
}

/* Appends to <out> the line "<name>:<value>" of a signed header, followed by a
 * line feed. chunk_appendf() is not used since it does not report a value
 * which does not fit. Returns 0 on success, -1 on failure.
 */
static int cloudauth_sigv4_add_hdr_line(struct buffer *out, const struct ist name, const struct ist value)
{
	if (!chunk_istcat(out, name))
		return -1;
	if (!chunk_memcat(out, ":", 1))
		return -1;
	if (!chunk_istcat(out, value))
		return -1;
	if (!chunk_memcat(out, "\n", 1))
		return -1;
	return 0;
}

/* Appends to <out> the canonical request of the request in <htx>, signed at
 * the date <stamp> with the variant <v4> and the session token <session> if
 * not empty: the method, the canonical URI, the canonical query string, the
 * signed headers with their values, the list of the signed headers, and the
 * hash of the payload, one per line. The signed headers are the Host header
 * and the headers added by the signer, since the client headers carrying the
 * prefix of the variant were removed. Returns 0 on success, -1 on failure.
 */
static int cloudauth_sigv4_add_creq(struct buffer *out, struct htx *htx, const struct cloudauth_sigv4 *v4,
                                    const char *stamp, const struct ist session)
{
	struct buffer *work1 = NULL, *work2 = NULL;
	struct http_hdr_ctx ctx;
	struct htx_sl *sl;
	struct ist path, query;
	int ret = -1;

	sl = http_get_stline(htx);
	if (!sl)
		return -1;
	ctx.blk = NULL;
	if (!http_find_header(htx, ist("host"), &ctx, 1))
		return -1;

	work1 = alloc_trash_chunk();
	if (!work1)
		goto out;
	work2 = alloc_trash_chunk();
	if (!work2)
		goto out;

	path = cloudauth_req_path(htx);
	query = istfind(path, '?');
	path = ist2(istptr(path), istlen(path) - istlen(query));
	if (istlen(query))
		query = istnext(query);

	if (!chunk_istcat(out, htx_sl_req_meth(sl)))
		goto out;
	if (!chunk_memcat(out, "\n", 1))
		goto out;
	if (cloudauth_sigv4_add_uri(out, path, work1) < 0)
		goto out;
	if (!chunk_memcat(out, "\n", 1))
		goto out;
	if (cloudauth_sigv4_add_query(out, query, work1, work2) < 0)
		goto out;
	if (!chunk_memcat(out, "\n", 1))
		goto out;
	if (cloudauth_sigv4_add_hdr_line(out, ist("host"), ctx.value) < 0)
		goto out;
	if (cloudauth_sigv4_add_hdr_line(out, v4->hash_hdr, ist(CLOUDAUTH_SIGV4_UNSIGNED_PAYLOAD)) < 0)
		goto out;
	if (cloudauth_sigv4_add_hdr_line(out, v4->date_hdr, ist(stamp)) < 0)
		goto out;
	if (istlen(session)) {
		if (cloudauth_sigv4_add_hdr_line(out, v4->token_hdr, session) < 0)
			goto out;
	}
	if (!chunk_memcat(out, "\n", 1))
		goto out;
	if (cloudauth_sigv4_add_signed_hdrs(out, v4, istlen(session)) < 0)
		goto out;
	if (!chunk_memcat(out, "\n", 1))
		goto out;
	if (!chunk_strcat(out, CLOUDAUTH_SIGV4_UNSIGNED_PAYLOAD))
		goto out;
	ret = 0;

  out:
	free_trash_chunk(work2);
	free_trash_chunk(work1);
	return ret;
}

/* Derives into <key> the signing key of the secret <secret> for the day <day>
 * ("YYYYMMDD"), the region <region> and the variant <v4>: the HMAC-SHA256
 * chain of the day, the region, the service and the request type, starting
 * from the secret prefixed by the key prefix of the variant. <key> must have
 * room for SHA256_DIGEST_LENGTH bytes, and is a secret. Returns 0 on success,
 * -1 on failure.
 */
static int cloudauth_sigv4_signing_key(const struct ist secret, const struct ist day, const char *region,
                                       const struct cloudauth_sigv4 *v4, unsigned char *key)
{
	unsigned char k1[SHA256_DIGEST_LENGTH], k2[SHA256_DIGEST_LENGTH];
	struct buffer *ksecret;
	int ret = -1;

	ksecret = alloc_trash_chunk();
	if (!ksecret)
		return -1;
	if (!chunk_strcat(ksecret, v4->key_prefix))
		goto out;
	if (!chunk_istcat(ksecret, secret))
		goto out;

	if (cloudauth_sigv4_hmac(ksecret->area, ksecret->data, day, k1) < 0)
		goto out;
	if (cloudauth_sigv4_hmac(k1, sizeof(k1), ist(region), k2) < 0)
		goto out;
	if (cloudauth_sigv4_hmac(k2, sizeof(k2), ist(v4->service), k1) < 0)
		goto out;
	if (cloudauth_sigv4_hmac(k1, sizeof(k1), ist(v4->request), key) < 0)
		goto out;
	ret = 0;

  out:
	ha_memset_s(k1, 0, sizeof(k1));
	ha_memset_s(k2, 0, sizeof(k2));
	ha_memset_s(ksecret->area, 0, ksecret->size);
	free_trash_chunk(ksecret);
	return ret;
}

/* Signs the request in <htx> with the HMAC key of profile <prof>, with the
 * variant <v4> of Signature Version 4: the headers carrying the hash of the
 * payload ("UNSIGNED-PAYLOAD") and the date are added, then the
 * "Authorization: <algorithm> Credential=<access-key-id>/<scope>,
 * SignedHeaders=<headers>, Signature=<signature>" header, the signature being
 * the hexadecimal HMAC-SHA256 of the string to sign with the signing key of
 * the day. The session token of a temporary key is sent and signed in its own
 * header. The client headers carrying the prefix of the variant and the
 * Authorization header were removed, and the Host header was set. The lock of
 * the profile must be held. The scope, the signed headers and the hash of the
 * canonical request are traced for the stream <strm>, so that they may be
 * compared with the ones of the storage when it rejects the signature: none
 * of them reveals the key, nor the session token. Returns 0 on success,
 * otherwise -1 with <reason> set to a static string describing the failure.
 */
int cloudauth_sigv4_sign(const struct cloudauth_profile *prof, const struct stream *strm, struct htx *htx,
                         const struct cloudauth_sigv4 *v4, const char **reason)
{
	const char *region = prof->region ? prof->region : v4->region;
	unsigned char key[SHA256_DIGEST_LENGTH];
	unsigned char mac[SHA256_DIGEST_LENGTH];
	char hex[2 * SHA256_DIGEST_LENGTH + 1];
	char stamp[CLOUDAUTH_SIGV4_DATE_SIZE];
	struct buffer *creq = NULL, *sts = NULL, *auth = NULL;
	struct ist id, secret, session, day, detail;
	struct tm tm;
	size_t len;
	int ret = -1;

	TRACE_ENTER(CLOUDAUTH_EV_REQ, strm, prof);

	/* the region is mandatory for the variants without default one */
	BUG_ON(!region);

	if (cloudauth_sigv4_split_token(prof->cred.token, &id, &secret, &session) < 0) {
		*reason = "invalid sigv4 token";
		goto out;
	}
	/* checked when the token was set */
	BUG_ON(istlen(session) && !isttest(v4->token_hdr));

	get_gmtime(date.tv_sec, &tm);
	if (!strftime(stamp, sizeof(stamp), "%Y%m%dT%H%M%SZ", &tm)) {
		*reason = "cannot format the date of the signature";
		goto out;
	}
	day = ist2(stamp, 8);

	*reason = "cannot add the sigv4 headers";
	if (!http_add_header(htx, v4->hash_hdr, ist(CLOUDAUTH_SIGV4_UNSIGNED_PAYLOAD), 0))
		goto out;
	if (!http_add_header(htx, v4->date_hdr, ist(stamp), 0))
		goto out;
	if (istlen(session)) {
		if (!http_add_header(htx, v4->token_hdr, session, 0))
			goto out;
	}

	*reason = "out of memory";
	creq = alloc_trash_chunk();
	if (!creq)
		goto out;
	sts = alloc_trash_chunk();
	if (!sts)
		goto out;
	auth = alloc_trash_chunk();
	if (!auth)
		goto out;

	*reason = "the canonical request does not fit in a buffer";
	if (cloudauth_sigv4_add_creq(creq, htx, v4, stamp, session) < 0)
		goto out;
	*reason = "cannot compute the signature";
	if (!EVP_Digest(creq->area, creq->data, mac, NULL, EVP_sha256(), NULL))
		goto out;
	cloudauth_sigv4_hex(mac, sizeof(mac), hex);
	/* a hash does not reveal the session token of the canonical request */
	detail = ist(hex);
	TRACE_DATA("sigv4 canonical request hash", CLOUDAUTH_EV_REQ, strm, prof, &detail);

	if (chunk_printf(sts, "%s\n%s\n", v4->algorithm, stamp) < 0)
		goto out;
	/* the scope follows the algorithm and the date */
	len = sts->data;
	if (cloudauth_sigv4_add_scope(sts, day, region, v4) < 0)
		goto out;
	detail = ist2(sts->area + len, sts->data - len);
	TRACE_STATE("sigv4 credential scope", CLOUDAUTH_EV_REQ, strm, prof, &detail);
	if (!chunk_memcat(sts, "\n", 1))
		goto out;
	if (!chunk_strcat(sts, hex))
		goto out;

	if (cloudauth_sigv4_signing_key(secret, day, region, v4, key) < 0)
		goto out;
	if (cloudauth_sigv4_hmac(key, sizeof(key), ist2(sts->area, sts->data), mac) < 0)
		goto out;
	cloudauth_sigv4_hex(mac, sizeof(mac), hex);

	*reason = "cannot add the Authorization header";
	if (chunk_printf(auth, "%s Credential=%.*s/", v4->algorithm, (int)istlen(id), istptr(id)) < 0)
		goto out;
	if (cloudauth_sigv4_add_scope(auth, day, region, v4) < 0)
		goto out;
	if (!chunk_strcat(auth, ", SignedHeaders="))
		goto out;
	/* only the names of the headers, the signature is appended after */
	len = auth->data;
	if (cloudauth_sigv4_add_signed_hdrs(auth, v4, istlen(session)) < 0)
		goto out;
	detail = ist2(auth->area + len, auth->data - len);
	TRACE_STATE("sigv4 signed headers", CLOUDAUTH_EV_REQ, strm, prof, &detail);
	if (!chunk_strcat(auth, ", Signature="))
		goto out;
	if (!chunk_strcat(auth, hex))
		goto out;
	if (!http_add_header(htx, ist("authorization"), ist2(auth->area, auth->data), 0))
		goto out;
	ret = 0;

  out:
	/* the signing key grants access for the whole day */
	ha_memset_s(key, 0, sizeof(key));
	ha_memset_s(mac, 0, sizeof(mac));
	ha_memset_s(hex, 0, sizeof(hex));
	/* the canonical request may carry the session token */
	if (creq)
		ha_memset_s(creq->area, 0, creq->size);
	if (auth)
		ha_memset_s(auth->area, 0, auth->size);
	free_trash_chunk(auth);
	free_trash_chunk(sts);
	free_trash_chunk(creq);
	if (ret < 0)
		TRACE_DEVEL("leaving on error", CLOUDAUTH_EV_REQ, strm, prof);
	else
		TRACE_LEAVE(CLOUDAUTH_EV_REQ, strm, prof);
	return ret;
}
