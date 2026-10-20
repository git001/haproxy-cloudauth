/*
 * Cloud storage authentication: helpers shared by the providers.
 *
 * Copyright 2026 Aleksandar Lazic <al-haproxy@none.at>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <import/mjson.h>

#include <haproxy/api.h>
#include <haproxy/base64.h>
#include <haproxy/chunk.h>
#include <haproxy/clock.h>
#include <haproxy/cloudauth_common.h>
#include <haproxy/errors.h>
#include <haproxy/http.h>
#include <haproxy/http_htx.h>
#include <haproxy/htx.h>
#include <haproxy/init.h>
#include <haproxy/intops.h>
#include <haproxy/istbuf.h>
#include <haproxy/openssl-compat.h>
#include <haproxy/tools.h>

/* Checks that all the characters of <s> satisfy <valid>, which is one of the
 * character classification functions such as isgraph(). Returns the position
 * of the first invalid character, or -1 if all of them are valid.
 */
ssize_t cloudauth_ist_check(const struct ist s, int (*valid)(int))
{
	size_t i;

	for (i = 0; i < istlen(s); i++) {
		if (!valid((unsigned char)istptr(s)[i]))
			return i;
	}
	return -1;
}

/* Formats the wall clock date <t> (in seconds) as an HTTP date into <buf> of
 * <size> bytes, which should be CLOUDAUTH_HTTP_DATE_SIZE. Returns the length
 * of the date, or 0 if it does not fit.
 */
int cloudauth_http_date(time_t t, char *buf, size_t size)
{
	struct tm tm;

	get_gmtime(t, &tm);
	return strftime(buf, size, "%a, %d %b %Y %T GMT", &tm);
}

/* Formats the wall clock date <t> (in seconds) as an ISO 8601 UTC date into
 * <buf> of <size> bytes, which should be CLOUDAUTH_ISO_DATE_SIZE. Returns the
 * length of the date, or 0 if it does not fit.
 */
int cloudauth_iso_date(time_t t, char *buf, size_t size)
{
	struct tm tm;

	get_gmtime(t, &tm);
	return strftime(buf, size, "%Y-%m-%dT%H:%M:%SZ", &tm);
}

/* Parses the ISO 8601 date <in>, as profiled by RFC 3339 and used for the
 * expiration dates of the temporary credentials: "YYYY-MM-DDTHH:MM:SS", an
 * optional fraction of second, which is ignored, then "Z" or the offset from
 * UTC, "+HH:MM" or "-HH:MM". The "T" and the "Z" may be in lower case. The
 * date is stored into <date> as a wall clock date in seconds. Returns 0 on
 * success, -1 if <in> is not such a date, or if the date is before the Epoch
 * or beyond the range of <date>, or of time_t when it is 32-bit.
 */
int cloudauth_parse_iso_date(struct ist in, unsigned int *date)
{
	/* the position and the length of the numbers of "YYYY-MM-DDTHH:MM:SS" */
	static const struct { unsigned char ofs, len; } fields[6] = {
		{ 0, 4 }, { 5, 2 }, { 8, 2 }, { 11, 2 }, { 14, 2 }, { 17, 2 },
	};
	static const unsigned char mdays[12] = { 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
	const char *p = istptr(in);
	const char *end = istend(in);
	const char *s;
	unsigned int val[6], off_hour, off_min;
	unsigned int year, mon, mday;
	long long offset = 0, t;
	struct tm tm;
	int i;

	/* The shortest date, "YYYY-MM-DDTHH:MM:SSZ", is 20 characters long, so
	 * once this length is checked, all the characters from p[0] to p[19]
	 * may be read: the fixed part and the first character after it.
	 */
	if (istlen(in) < 20)
		return -1;

	/* the separators of the fixed part "YYYY-MM-DDTHH:MM:SS" are at fixed
	 * positions, between the numbers read below: '-' after the year and
	 * the month, 'T' after the day, ':' after the hour and the minute.
	 */
	if (p[4] != '-' || p[7] != '-' || toupper((unsigned char)p[10]) != 'T' || p[13] != ':' || p[16] != ':')
		return -1;

	/* read_uint() stops at <s> + len at most, and at the first non-digit,
	 * so the number has exactly the expected digits if it stopped there.
	 */
	for (i = 0; i < 6; i++) {
		s = p + fields[i].ofs;
		val[i] = read_uint(&s, s + fields[i].len);
		if (s != p + fields[i].ofs + fields[i].len)
			return -1;
	}
	year = val[0];
	mon = val[1];
	mday = val[2];

	/* the fraction of second has at least one digit. p[19] exists, see
	 * above, and the digits are only read while <s> is before <end>.
	 */
	s = p + 19;
	if (*s == '.') {
		s++;
		if (s == end || !isdigit((unsigned char)*s))
			return -1;
		while (s < end && isdigit((unsigned char)*s))
			s++;
	}

	/* <s> may have reached <end> after a fraction, which is then not
	 * followed by "Z" nor by an offset.
	 */
	if (s < end && toupper((unsigned char)*s) == 'Z')
		s++;
	else if (s < end && (*s == '+' || *s == '-')) {
		/* "+HH:MM" or "-HH:MM", the last part of the date, so exactly 6
		 * characters must remain before s[1] to s[5] are read.
		 */
		if (end - s != 6 || s[3] != ':')
			return -1;
		p = s + 1;
		off_hour = read_uint(&p, s + 3);
		if (p != s + 3)
			return -1;
		p = s + 4;
		off_min = read_uint(&p, s + 6);
		if (p != s + 6)
			return -1;
		if (off_hour > 23 || off_min > 59)
			return -1;
		offset = off_hour * 3600 + off_min * 60;
		if (*s == '-')
			offset = -offset;
		s += 6;
	}
	else
		return -1;
	if (s != end)
		return -1;

	/* my_timegm() does not check the fields, a leap second is accepted */
	if (year < 1970 || mon < 1 || mon > 12 || mday < 1 || mday > mdays[mon - 1])
		return -1;
	if (mon == 2 && mday == 29 && ((year & 3) || (!(year % 100) && (year % 400))))
		return -1;
	if (val[3] > 23 || val[4] > 59 || val[5] > 60)
		return -1;
	/* my_timegm() would overflow beyond 2037 with a 32-bit time_t */
	if (sizeof(time_t) < 8 && year > 2037)
		return -1;

	memset(&tm, 0, sizeof(tm));
	tm.tm_year = year - 1900;
	tm.tm_mon = mon - 1;
	tm.tm_mday = mday;
	tm.tm_hour = val[3];
	tm.tm_min = val[4];
	tm.tm_sec = val[5];
	t = (long long)my_timegm(&tm) - offset;
	if (t < 0 || t > UINT_MAX)
		return -1;
	*date = t;
	return 0;
}

#ifdef DEBUG_UNIT
/* Unit test of cloudauth_parse_iso_date(), run with "-U cloudauth_iso_date".
 * Returns 0 on success, 1 on failure.
 */
static int cloudauth_iso_date_unittest(int argc, char **argv)
{
	static const struct {
		const char *in;
		int ret;
		unsigned int date;
	} tests[] = {
		{ "1970-01-01T00:00:00Z",                0, 0 },
		{ "2026-10-18T12:34:56Z",                0, 1792326896 },
		{ "2026-10-18t12:34:56z",                0, 1792326896 },
		{ "2026-10-18T12:34:56.123456789Z",      0, 1792326896 },
		{ "2026-10-18T14:34:56+02:00",           0, 1792326896 },
		{ "2026-10-18T09:04:56-03:30",           0, 1792326896 },
		{ "2024-02-29T00:00:00Z",                0, 1709164800 },
		{ "2105-12-31T23:59:59Z",                0, 4291747199U },
		{ "2023-02-29T00:00:00Z",               -1, 0 },
		{ "2100-02-29T00:00:00Z",               -1, 0 },
		{ "2026-13-01T00:00:00Z",               -1, 0 },
		{ "2026-04-31T00:00:00Z",               -1, 0 },
		{ "2026-10-18T24:00:00Z",               -1, 0 },
		{ "2026-10-18T12:60:00Z",               -1, 0 },
		{ "2026-10-18T12:34:56",                -1, 0 },
		{ "2026-10-18T12:34:56.Z",              -1, 0 },
		{ "2026-10-18T12:34:56Zx",              -1, 0 },
		{ "2026-10-18T12:34:56+0200",           -1, 0 },
		{ "2026-10-18 12:34:56Z",               -1, 0 },
		{ "2026-1-18T12:34:56Z",                -1, 0 },
		{ "1969-12-31T23:59:59Z",               -1, 0 },
		{ "1970-01-01T00:00:00+00:01",          -1, 0 },
		{ "2106-12-31T23:59:59Z",               -1, 0 },
		{ "2026-10-18T12:34:5+Z",               -1, 0 },
		{ "2026-10-18T12:34:56+02:00x",         -1, 0 },
		{ "2026-10-18T12:34:56+2:000",          -1, 0 },
		{ "",                                   -1, 0 },
	};
	unsigned int date;
	int i, ret, failed = 0;

	for (i = 0; i < sizeof(tests) / sizeof(*tests); i++) {
		date = 0;
		ret = cloudauth_parse_iso_date(ist(tests[i].in), &date);
		if (ret != tests[i].ret || (ret == 0 && date != tests[i].date)) {
			printf("cloudauth_parse_iso_date(\"%s\") = %d (%u), expected %d (%u)\n",
			       tests[i].in, ret, date, tests[i].ret, tests[i].date);
			failed = 1;
		}
	}
	return failed;
}
REGISTER_UNITTEST("cloudauth_iso_date", cloudauth_iso_date_unittest);
#endif

/* Returns the path of the request in <htx> with its query string, without the
 * scheme and the authority of an absolute URI, or IST_NULL if it has no start
 * line.
 */
struct ist cloudauth_req_path(const struct htx *htx)
{
	struct htx_sl *sl = http_get_stline(htx);
	struct http_uri_parser parser;
	struct ist path;

	if (!sl)
		return IST_NULL;
	parser = http_uri_parser_init(htx_sl_req_uri(sl));
	path = http_parse_path(&parser);
	if (!isttest(path))
		path = htx_sl_req_uri(sl);
	return path;
}

/* Appends the query string parameters <params> (without leading '?' or '&')
 * to the query string of the request in <htx>, adding the question mark if the
 * request has no query string. Returns 1 on success, 0 on failure.
 *
 * <params> is a credential, such as a shared access signature, which is why
 * http_replace_req_query() is not used: it builds the new start line in a
 * buffer returned by get_trash_chunk(), which is neither private nor wiped,
 * so the credential would remain in memory until the trash is reused. Here,
 * the start line is built in a chunk allocated for this purpose and wiped
 * once the start line was replaced. This also handles the separator, which
 * depends on the current query string: none after "path?", '&' after
 * "path?a=b", and a question mark after "path".
 */
int cloudauth_append_query(struct htx *htx, const struct ist params)
{
	struct htx_sl *sl = http_get_stline(htx);
	struct buffer *tmp;
	struct ist meth, uri, vsn, query;
	int ret = 0;

	if (!sl)
		return 0;

	tmp = alloc_trash_chunk();
	if (!tmp)
		return 0;

	uri = htx_sl_req_uri(sl);
	query = istfind(uri, '?');
	if (!chunk_memcat(tmp, HTX_SL_REQ_MPTR(sl), HTX_SL_REQ_MLEN(sl)))
		goto out;
	if (!chunk_memcat(tmp, HTX_SL_REQ_VPTR(sl), HTX_SL_REQ_VLEN(sl)))
		goto out;
	if (!chunk_istcat(tmp, uri))
		goto out;

	if (!istlen(query)) {
		if (!chunk_memcat(tmp, "?", 1))
			goto out;
	}
	else if (istlen(query) > 1) {
		if (!chunk_memcat(tmp, "&", 1))
			goto out;
	}
	if (!chunk_istcat(tmp, params))
		goto out;

	meth = ist2(tmp->area, HTX_SL_REQ_MLEN(sl));
	vsn = ist2(tmp->area + istlen(meth), HTX_SL_REQ_VLEN(sl));
	uri = ist2(tmp->area + istlen(meth) + istlen(vsn), tmp->data - istlen(meth) - istlen(vsn));
	ret = http_replace_stline(htx, meth, uri, vsn);

  out:
	ha_memset_s(tmp->area, 0, tmp->data);
	free_trash_chunk(tmp);
	return ret;
}

/* Appends to <work> the URL-decoded copy of <in>, the '+' being decoded as a
 * space, and makes <out> point to it. The copy is followed by a zero which is
 * not part of <out>. Returns 0 on success, -1 if there is no more room or <in>
 * cannot be decoded.
 */
int cloudauth_url_decode(struct buffer *work, const struct ist in, struct ist *out)
{
	char *p = b_tail(work);
	int len;

	if (b_room(work) < istlen(in) + 1)
		return -1;
	memcpy(p, istptr(in), istlen(in));
	p[istlen(in)] = 0;

	len = url_decode(p, 1);
	if (len < 0)
		return -1;

	work->data += len + 1;
	*out = ist2(p, len);
	return 0;
}

/* Splits the query string parameter <param> ("name=value", "name=" or "name")
 * into <out>, its name and its value being URL-decoded into <work>. Returns 0
 * on success, -1 on failure.
 */
int cloudauth_qparam_decode(struct buffer *work, const struct ist param, struct cloudauth_qparam *out)
{
	struct ist name = iststop(param, '=');
	struct ist value = istadv(param, istlen(name) + 1);

	if (cloudauth_url_decode(work, name, &out->name) < 0)
		return -1;
	if (cloudauth_url_decode(work, value, &out->value) < 0)
		return -1;
	return 0;
}

/* Compares two struct cloudauth_qparam, by name then by value, for qsort() */
int cloudauth_qparam_cmp(const void *a, const void *b)
{
	const struct cloudauth_qparam *pa = a;
	const struct cloudauth_qparam *pb = b;
	int ret;

	ret = istdiff(pa->name, pb->name);
	if (ret != 0)
		return ret;
	return istdiff(pa->value, pb->value);
}

/* Appends to <out> the URL-encoded copy of <in>, as a query string parameter
 * or a form field: only the unreserved characters of RFC 3986 are kept.
 * Returns 0 on success, -1 if there is no more room.
 */
int cloudauth_url_encode_cat(struct buffer *out, const struct ist in)
{
	struct buffer buf = ist2buf(in);
	char *end;

	/* encode_chunk() stops silently when the output is full, so the room
	 * for the value fully encoded is checked first.
	 */
	if (b_room(out) < istlen(in) * 3 + 1)
		return -1;
	end = encode_chunk(b_tail(out), b_tail(out) + b_room(out), '%', query_encode_map, &buf, 0);
	if (!end)
		return -1;
	out->data = end - out->area;
	return 0;
}

/* Appends to the form-encoded payload <body> (application/x-www-form-urlencoded)
 * the field <name>, which must not need to be encoded, with the value <value>,
 * which is URL-encoded. Returns 0 on success, -1 if there is no more room. The
 * value may be a secret, so <body> must be wiped by the caller.
 */
int cloudauth_form_add(struct buffer *body, const char *name, const struct ist value)
{
	/* the fields are separated by '&' */
	if (b_data(body)) {
		if (!chunk_memcat(body, "&", 1))
			return -1;
	}
	if (!chunk_strcat(body, name))
		return -1;
	if (!chunk_memcat(body, "=", 1))
		return -1;
	return cloudauth_url_encode_cat(body, value);
}

/* Reads into <out> the unsigned integer at <path> in the JSON document <json>
 * of <len> bytes. It may be a number, whose fractional part is ignored (such
 * as a JWT NumericDate), or a string made of digits, since some token
 * endpoints return the durations as strings. The value is saturated to
 * ULLONG_MAX. Floating point numbers are not used, so the exponents are not
 * accepted. Returns 0 on success, -1 if the value is missing or is not an
 * unsigned integer.
 */
int cloudauth_json_uint(const char *json, int len, const char *path, ullong *out)
{
	const char *tok, *end;
	int toklen, number = 0;

	switch (mjson_find(json, len, path, &tok, &toklen)) {
	case MJSON_TOK_NUMBER:
		number = 1;
		break;
	case MJSON_TOK_STRING:
		/* skip the quotes */
		if (toklen < 2)
			return -1;
		tok++;
		toklen -= 2;
		break;
	default:
		return -1;
	}

	end = tok + toklen;
	if (tok == end)
		return -1;
	*out = read_uint64(&tok, end);
	if (number && tok < end && *tok == '.') {
		tok++;
		while (tok < end && isdigit((unsigned char)*tok))
			tok++;
	}
	if (tok != end)
		return -1;
	return 0;
}

/* Extracts from the OAuth 2.0 token response <body> (RFC 6749 section 5.1)
 * the access token into <token>, and its expiration date (wall clock, in
 * seconds) into <expire>: "expires_in" seconds from now, otherwise the
 * "expires_on" date used by some Azure endpoints, otherwise 0 if unknown.
 * Returns 0 on success, otherwise -1 with <err> filled, which never contains
 * the token.
 */
int cloudauth_oauth_token(const struct buffer *body, struct buffer *token, unsigned int *expire, char **err)
{
	unsigned int now = date.tv_sec;
	ullong val;
	int len;

	len = mjson_get_string(b_orig(body), b_data(body), "$.access_token", b_orig(token), b_size(token));
	if (len <= 0) {
		memprintf(err, "no access token in the response");
		return -1;
	}
	token->data = len;

	*expire = 0;
	if (cloudauth_json_uint(b_orig(body), b_data(body), "$.expires_in", &val) == 0)
		*expire = (val < UINT_MAX - now) ? now + val : UINT_MAX;
	else if (cloudauth_json_uint(b_orig(body), b_data(body), "$.expires_on", &val) == 0)
		*expire = MIN(val, UINT_MAX);
	return 0;
}

/* Fills <err> with the reason why a token endpoint answered with status
 * <status> and payload <body>: the "error" code of an OAuth 2.0 error response
 * (RFC 6749 section 5.2) if it is made of visible characters. The description
 * is not reported, since it may be long and quote the request.
 */
void cloudauth_oauth_error(int status, const struct buffer *body, char **err)
{
	char code[64];
	int len;

	len = mjson_get_string(b_orig(body), b_data(body), "$.error", code, sizeof(code));
	if (len > 0 && cloudauth_ist_check(ist2(code, len), isgraph) < 0)
		memprintf(err, "the token endpoint answered with status %d (%s)", status, code);
	else
		memprintf(err, "the token endpoint answered with status %d", status);
}

/* Returns non-zero if <url> is an HTTP or an HTTPS URL */
int cloudauth_is_http_url(const char *url)
{
	return strncmp(url, "http://", 7) == 0 || strncmp(url, "https://", 8) == 0;
}

/* Parses the argument of the keyword <args[0]> setting the string <field> of
 * the settings of a provider. If <env> is non-zero, it may also be read from
 * an environment variable with "env:<variable>" when the configuration is
 * parsed, so it must not be a secret. It must satisfy <valid>, otherwise it is
 * reported as an invalid <what>, <expects> describing the expected format.
 * Returns 0 on success, otherwise ERR_* flags with <err> filled.
 */
int cloudauth_cfg_str(char **args, char **field, int env, int (*valid)(const char *str),
                      const char *what, const char *expects, char **err)
{
	const char *str = args[1];

	if (!*args[1] || *args[2]) {
		memprintf(err, "'%s' expects exactly one argument.", args[0]);
		return ERR_ALERT | ERR_FATAL;
	}
	if (*field) {
		memprintf(err, "'%s' may only be set once.", args[0]);
		return ERR_ALERT | ERR_FATAL;
	}

	if (env && strncmp(str, "env:", 4) == 0) {
		str = getenv(args[1] + 4);
		if (!str || !*str) {
			memprintf(err, "'%s' : environment variable '%s' is not set or empty.", args[0], args[1] + 4);
			return ERR_ALERT | ERR_FATAL;
		}
	}

	if (!valid(str)) {
		memprintf(err, "'%s' : invalid %s '%s', expects %s.", args[0], what, str, expects);
		return ERR_ALERT | ERR_FATAL;
	}

	*field = strdup(str);
	if (!*field) {
		memprintf(err, "out of memory");
		return ERR_ALERT | ERR_FATAL;
	}
	return 0;
}

/* Copies into <buf> of <size> bytes the password of a private key, which is
 * the struct ist <u>. Returns its length, or 0 if there is none or it does not
 * fit, so that an encrypted private key cannot be decrypted. It is the
 * password callback of the PEM_read_bio_*() functions of OpenSSL, which must
 * never prompt for a password.
 */
int cloudauth_pem_password(char *buf, int size, int rwflag, void *u)
{
	const struct ist *password = u;

	if (!isttest(*password) || istlen(*password) > size)
		return 0;
	memcpy(buf, istptr(*password), istlen(*password));
	return istlen(*password);
}

/* Loads the private key found in the PEM data <pem>, decrypted with
 * <password> if it is encrypted, IST_NULL meaning that it must not be. The
 * key may be placed before or after the other PEM blocks. Returns the key,
 * which must be released with EVP_PKEY_free(), or NULL if none is found or it
 * cannot be decrypted.
 */
EVP_PKEY *cloudauth_pem_private_key(const struct ist pem, struct ist password)
{
	EVP_PKEY *key;
	BIO *bio;

	bio = BIO_new_mem_buf(istptr(pem), istlen(pem));
	if (!bio)
		return NULL;
	key = PEM_read_bio_PrivateKey(bio, NULL, cloudauth_pem_password, &password);
	BIO_free(bio);
	if (!key)
		ERR_clear_error();
	return key;
}

/* Appends to <out> the <len> bytes of <in> encoded in base64url. Returns 0 on
 * success, -1 if there is no more room.
 */
static int cloudauth_b64url_cat(struct buffer *out, const char *in, size_t len)
{
	int ret = a2base64url(in, len, b_tail(out), b_room(out));

	if (ret < 0)
		return -1;
	out->data += ret;
	return 0;
}

/* Appends to <out> a JWT made of the protected header <header> and the claims
 * <claims>, which are JSON objects, signed with the RSA private key <key> with
 * the algorithm <alg>: JWS_ALG_RS256 (RSASSA-PKCS1-v1_5 with SHA-256) or
 * JWS_ALG_PS256 (RSASSA-PSS with SHA-256, the salt being as long as the
 * digest). The JWT usually grants tokens until it expires, so <out> must be
 * wiped by the caller. Returns 0 on success, otherwise -1 with <err> filled.
 */
int cloudauth_jwt_sign(struct buffer *out, const struct ist header, const struct ist claims,
                       EVP_PKEY *key, enum jwt_alg alg, char **err)
{
	unsigned char sig[1024];
	EVP_MD_CTX *md = NULL;
	EVP_PKEY_CTX *pctx = NULL;
	size_t sig_len = sizeof(sig);
	int ret = -1;

	BUG_ON(alg != JWS_ALG_RS256 && alg != JWS_ALG_PS256);

	/* the protected header and the claims, in base64url, separated by a dot */
	if (cloudauth_b64url_cat(out, istptr(header), istlen(header)) < 0)
		goto full;
	if (!chunk_memcat(out, ".", 1))
		goto full;
	if (cloudauth_b64url_cat(out, istptr(claims), istlen(claims)) < 0)
		goto full;

	if (EVP_PKEY_size(key) > sizeof(sig))
		goto sign;
	md = EVP_MD_CTX_new();
	if (!md) {
		memprintf(err, "out of memory");
		goto out;
	}
	if (EVP_DigestSignInit(md, &pctx, EVP_sha256(), NULL, key) != 1)
		goto sign;
	if (alg == JWS_ALG_PS256) {
		if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) <= 0)
			goto sign;
		if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST) <= 0)
			goto sign;
	}
	if (EVP_DigestSignUpdate(md, out->area, out->data) != 1)
		goto sign;
	if (EVP_DigestSignFinal(md, sig, &sig_len) != 1)
		goto sign;

	if (!chunk_memcat(out, ".", 1))
		goto full;
	if (cloudauth_b64url_cat(out, (char *)sig, sig_len) < 0)
		goto full;
	ret = 0;
	goto out;

  full:
	memprintf(err, "the assertion does not fit in a buffer");
	goto out;
  sign:
	memprintf(err, "cannot sign the assertion");
	ERR_clear_error();
  out:
	EVP_MD_CTX_free(md);
	ha_memset_s(sig, 0, sizeof(sig));
	return ret;
}
