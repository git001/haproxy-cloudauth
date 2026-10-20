# HAProxy cloud storage authentication filter: internal API

Last update: 2026-10-20.

## 1. Background

The cloudauth filter authenticates the requests that HAProxy sends to cloud
object storages (Azure Blob Storage, Google Cloud Storage, S3 compatible
storages...). It is an addon of HAProxy, built with the HAProxy sources by
listing its directory in `EXTRA_MAKE`, and only relies on the public APIs of
HAProxy. It is made of:

- the core (`src/cloudauth.c`, `src/flt_cloudauth.c`): the `cloudauth` sections
    declaring the credential profiles, the credential store, the CLI, the stats
    module and the filter. The filter class is registered with
    `filter_register_class()`, and its http_headers callback authenticates each
    request with the profile and the host of the filter instance of the
    backend;

- the helpers shared by the providers (`src/cloudauth_common.c`);

- the Signature Version 4 shared by the providers of the `sigv4` signer
    (`src/cloudauth_sigv4.c`, see section 7);

- the fetching of the credentials (`src/cloudauth_fetch.c`), which requests
    them with the HTTP client and refreshes them before they expire;

- the `cloudauth` trace source (`src/cloudauth_trace.c`, see section 5);

- the storage providers, each one in its own file, which may be left out at
    build time, such as `src/cloudauth_azure.c` with `CLOUDAUTH_AZURE=0`. A
    provider implements what is specific to a storage: its signatures, its
    headers, its keywords and its token sources.

The request is authenticated by `cloudauth_authenticate()` in this order: the
headers and the query string parameters which may carry credentials are
removed, as well as the headers set by the signers, the Host header is set to
the host of the filter, then the request is signed by the provider, or with the
bearer token without provider. The signature is computed last since it may
cover the other headers, including the ones of the storage sent by the client.

A profile selects a provider with `provider <name>`, a signer with
`signer <type>` among the generic types `bearer`, `sas`, `sharedkey` and
`sigv4`, and where the token comes from with `token <source>`. Without
provider, only the bearer signer is accepted.

## 2. Secrets

The credentials are secrets. The rules below apply to the core and to the
providers:

- a secret is never accepted in the configuration text, only from the
    environment (`env:`), from a file read at parse time (`file:`), from the
    CLI, or fetched by HAProxy. The file system is never accessed at runtime;

- a secret is never logged, never traced, never reported in an error message,
    and never dumped by the CLI. The error messages must not quote the
    arguments that may be secrets, nor the payloads of the token endpoints;

- any buffer which held a secret is wiped with `ha_memset_s()` before being
    released: the token itself, the decoded keys, the chunks used to build a
    header, a query string or a request, and the buffers of the HTTP client.
    For this reason, a function writing a secret must use its own chunk
    obtained with `alloc_trash_chunk()` rather than `get_trash_chunk()`, or
    wipe the trash chunk it used;

- the environment variables carrying secrets are registered with
    `cloudauth_register_secret_env()`, and are wiped and removed from the
    environment once the configuration is parsed;

- a keyword receiving a secret reads it with `cloudauth_cfg_read_secret()`,
    which accepts `env:<variable>`, registering the variable, and
    `file:<path>`, and rejects anything else without quoting it. The secret is
    released with `cloudauth_free_secret()`, which wipes it first.

## 3. Providers

A provider declares a `struct cloudauth_provider` (cloudauth-t.h) and registers
it at the `STG_REGISTER` stage:

```
INITCALL1(STG_REGISTER, cloudauth_register_provider, &my_provider);
```

A provider without `sign()` callback, or with a token source without
`request()` or `response()` callback, triggers a `BUG_ON()` when it is
registered. The list of the providers is only modified by these INITCALLs and
only browsed while the configuration is parsed, before the threads are started,
so it needs no lock. The profiles keep a pointer to their provider.

The fields of `struct cloudauth_provider` are:

- name: the name used by the `provider` keyword;

- signers: the supported signers, as `(1 << CLOUDAUTH_SIGNER_*)`. The other
    ones are rejected once the section is parsed;

- `init(prof, err)`: optional, called when the provider is set for the profile,
    to allocate `prof->provider_ctx`, which holds the settings of the provider.
    Returns 0 on success, -1 with `<err>` filled on error;

- `check(prof, err)`: optional, called once the section is parsed, to check the
    settings of the provider, for instance a keyword mandatory with a signer.
    Returns 0 on success, -1 with `<err>` filled on error;

- `check_token(prof, token, err)`: optional, checks that a token may be used by
    the signer of the profile, for instance that a shared access signature has
    a `sig` parameter. It is called for each new token, and once the section is
    parsed for a token loaded before the provider or the signer was known.
    `<err>` must never contain the token;

- `sign(prof, strm, htx)`: mandatory unless `sigv4` is the only signer of the
    provider, authenticates the request of the stream `<strm>`, passed for the
    traces, with the credential of the profile, whose lock is held for reading.
    The credentials of the client were removed and the Host header was set.
    Returns 0 on success, -1 on failure. A provider supporting bearer tokens
    may call `cloudauth_sign_bearer()`. It is not called for the `sigv4`
    signer, which the core performs (see section 7);

- `release(prof)`: optional, releases `prof->provider_ctx`, which may be NULL
    if `init()` failed;

- sources: the token sources of the provider (see section 4), terminated by an
    element with a NULL name, or NULL if none;

- sigv4: the variant of the `sigv4` signer (see section 7), which must be set
    if and only if the provider supports this signer.

The keywords of a provider are declared with the `CLOUDAUTH_CFG_SECTION`
section type and registered with `cloudauth_register_keywords()`, from an
`STG_REGISTER` initcall. They are kept in a list of their own, not in the
keywords of HAProxy. Their parsers reach the profile being parsed with
`cloudauth_cfg_profile()`, and must reject the keyword if the profile does not
use their provider, so that the provider must be set first.

## 4. Token sources

A token source is a place from which HAProxy fetches the credential of a
profile, then refreshes it. It is declared by a provider in a table of
`struct cloudauth_source`, and selected with `token <source>`, once the
provider is set. The profile then has the `CLOUDAUTH_SRC_FETCH` source, and
`prof->fetch` holds the state of the fetching.

The fields of `struct cloudauth_source` are:

- name: the name used by the `token` keyword;

- signers: the signers using the tokens of the source, as
    `(1 << CLOUDAUTH_SIGNER_*)`;

- inputs: the names of the inputs of the source, terminated by NULL, at most
    `CLOUDAUTH_MAX_INPUTS`, or NULL if it has none. An input is a secret
    exchanged for a token and renewed outside of HAProxy, such as a Kubernetes
    service account token. It is loaded with the `input` keyword when the
    configuration is parsed, and replaced with `set cloudauth input` on the
    CLI, since the file system is never accessed at runtime. The inputs are
    kept in `prof->inputs`, in the same order, and their state is reported by
    `show cloudauth`;

- flags: the settings supported by the source, as `CLOUDAUTH_SRC_F_*`:
    `CLOUDAUTH_SRC_F_ENDPOINT` if `token-endpoint` may replace its endpoint,
    which is then in `prof->fetch.endpoint`, and `CLOUDAUTH_SRC_F_SCOPES` if
    `token-scopes` may set the scopes of its tokens, which are then in
    `prof->fetch.scopes`, separated by spaces. These keywords are rejected for
    the other sources once the section is parsed;

- `init(prof, err)`: optional, called when the source is selected, for instance
    to read environment variables at parse time;

- `request(prof, req, err)`: mandatory, prepares the request fetching a
    credential in `<req>`: the method (GET by default), the URL in `req->url`,
    the payload in `req->body`, and up to `CLOUDAUTH_FETCH_MAX_HDRS` headers
    added with `cloudauth_fetch_add_hdr()`. These chunks are allocated, wiped
    and released by the caller. The inputs of the source, which are all valid
    since the request is not sent otherwise, are copied in `req->inputs`, in
    their order. Returns 0 on success, -1 with `<err>` filled on error;

- `response(prof, status, body, token, expire, err)`: mandatory, extracts the
    credential from a complete response of status `<status>` and payload
    `<body>` into the chunk `<token>`, which is wiped by the caller, and its
    expiration date (wall clock, in seconds, 0 if unknown) into `<expire>`.
    Returns 0 on success, -1 with `<err>` filled on error, which must never
    contain the payload. The OAuth 2.0 token responses may be parsed with
    `cloudauth_oauth_token()` and `cloudauth_oauth_error()`.

A token source may need several requests to fetch a credential, such as a
metadata service requiring a session token first. Its `response()` callback
then returns 1 after a request which is not the last one, `<token>` containing
what it keeps for the next request, such as the session token. The core then
sends the next request at once: `prof->fetch.step` is the index of the request
of the fetch, from 0, and `prof->fetch.carry` is the chunk kept by the previous
one, or NULL for the first one. Both callbacks may read them, the core only
updating them. The chunk is wiped and released once the fetch succeeds or
fails, and a failure of any request is a failure of the whole fetch, the next
attempt starting with the first request again. A fetch is limited to
`CLOUDAUTH_FETCH_MAX_STEPS` requests.

The fetching is performed by `src/cloudauth_fetch.c`, with one task per profile
created once the configuration is checked, and an HTTP client proxy created
before the configuration checks if at least one profile fetches its credential.
The task sends one request at a time, whose response must arrive within
`prof->fetch.timeout` (`fetch-timeout`, 5 seconds by default) for each attempt
of the HTTP client. Once the response is complete, the token is stored with
`cloudauth_set_token()`, which also takes the expiration date from a JWT if
none was given, and the next fetch is scheduled once half of the lifetime of
the token has elapsed, or after `prof->fetch.refresh` (`fetch-refresh`, 1 hour
by default) if it is unknown. On failure, a new attempt is scheduled after 1
second, the delay being doubled each time up to `prof->fetch.max_backoff`
(`fetch-max-backoff`, 5 minutes by default). The defaults are applied once the
section is parsed. When an input is replaced from the CLI,
`cloudauth_fetch_now()` requests a new fetch at once if the credential is not
valid or the last fetch failed. The reason of the last failure is kept in
`prof->fetch.error` for `show cloudauth`. Only the state changes are logged:
the first credential fetched, the first failure of a series, and the first
success after failures.

## 5. Traces

The `cloudauth` trace source (`src/cloudauth_trace.c`) is declared in
cloudauth_trace.h, which also defines `TRACE_SOURCE`, so that the core and the
providers emit their traces with the `TRACE_*`() macros after including it. The
events are:

- `CLOUDAUTH_EV_REQ`: the authentication of a request;
- `CLOUDAUTH_EV_STRIP`: a client credential removed from a request;
- `CLOUDAUTH_EV_CRED`: a credential updated from the CLI, or expired;
- `CLOUDAUTH_EV_FETCH`: the fetching of a credential from a token source.

The arguments of the traces are, in this order: the stream, or NULL outside of
a request, which allows to lock the traces on a stream, a session, a backend or
a server; the profile, or NULL; a detail as a pointer to a `struct ist`, such
as the name of a removed header or the reason of a failure; and a pointer to
the HTTP status of a token endpoint. A trace must never receive a credential,
nor a header value, a query string, a payload or a buffer which may carry one:
only names, states, statuses and error reasons. The URL of a token endpoint may
be traced only without its query string. A hash covering a secret may be traced
when it helps to compare with the peer, such as the hash of the canonical
request of the sigv4 signer, which covers the session token: the secret is a
random token, which cannot be recovered from it.

Like in the rest of HAProxy, the functions called at runtime, such as the
`request()`, `response()` and `sign()` callbacks of the providers, are traced
at the developer level with `TRACE_ENTER()` on entry and `TRACE_LEAVE()` on
success, the failures being traced with `TRACE_DEVEL`(`leaving on error`, ...),
so that the step where a fetch or an authentication fails may be found. The
small helpers they call are not traced.

The traces emitted while the configuration is parsed are lost, so the
credentials loaded on startup are not traced, nor the functions only called
while it is parsed.

## 6. Helpers

The helpers shared by the providers are declared in cloudauth_common.h:

- `cloudauth_ist_check(s, valid)`: returns the position of the first character
    of `<s>` which does not satisfy the classification function `<valid>` (such
    as isgraph), or -1 if they all do;

- `cloudauth_http_date(t, buf, size)`, `cloudauth_iso_date(t, buf, size)`:
    format a wall clock date as an HTTP date or as an ISO 8601 UTC date with
    `get_gmtime()`, into buffers of `CLOUDAUTH_HTTP_DATE_SIZE` and
    `CLOUDAUTH_ISO_DATE_SIZE` bytes;

- `cloudauth_parse_iso_date(in, date)`: parses an ISO 8601 date as profiled by
    RFC 3339, `YYYY-MM-DDTHH:MM:SS` with an optional fraction of second, then
    `Z` or an offset from UTC, such as the expiration dates of the temporary
    credentials, into a wall clock date, with `my_timegm()`. The core has no
    such parser, only the HTTP dates of `parse_http_date()`. It is covered by
    the `cloudauth_iso_date` unit test, run with `haproxy -U` when HAProxy is
    built with -`DDEBUG_UNIT` (`test/unit/`, run by `test/run.sh`);

- `CLOUDAUTH_B64_SIZE`(n): the size of the buffer receiving `<n>` bytes encoded
    in base64 by `a2base64()`, with the trailing zero;

- `cloudauth_req_path(htx)`: returns the path of the request with its query
    string, without the scheme and the authority of an absolute URI;

- `cloudauth_append_query(htx, params)`: appends query string parameters
    carrying a credential to the request. Unlike `http_replace_req_query()`, it
    builds the new start line in its own chunk, which is wiped afterwards;

- `cloudauth_url_decode(work, in, out)`: URL-decodes a copy of `<in>` into the
    work chunk `<work>`;

- `struct cloudauth_qparam`, `cloudauth_qparam_decode()` and
    `cloudauth_qparam_cmp()`: split, decode and sort the query string
    parameters, for the signatures covering the query string;

- `struct cloudauth_hdr`, `cloudauth_collect_hdrs(htx, name, pfx, hdrs, max)`
    and `cloudauth_canon_hdrs_cat(out, hdrs, nb)`: collect the headers of a
    request named `<name>` or starting with `<pfx>`, sorted by name, at most
    `CLOUDAUTH_MAX_SIGNED_HDRS`, then append their canonical form, one line
    per name with the values of a same name separated by commas, their spaces
    trimmed and squeezed, for the signatures covering headers;

- `cloudauth_url_encode_cat(out, in)`: appends the URL-encoded copy of `<in>`,
    for a query string parameter or a form field;

- `cloudauth_form_add(body, name, value)`: appends a field to a form-encoded
    payload (application/x-www-form-urlencoded), the value being URL-encoded,
    for the token requests sent with a POST;

- `cloudauth_json_uint(json, len, path, out)`: reads an unsigned integer given
    as a JSON number, whose fractional part is ignored, or as a string, without
    floating point. It is also used for the `exp` claim of the JWT;

- `cloudauth_oauth_token(body, token, expire, err)` and
    `cloudauth_oauth_error(status, body, err)`: parse an OAuth 2.0 token
    response (`access_token`, `expires_in` or `expires_on`) and the `error`
    code of an error response;

- `cloudauth_is_http_url(url)`: returns non-zero if `<url>` is an HTTP or an
    HTTPS URL, for the keywords designating an endpoint;

- `cloudauth_cfg_str(args, field, env, valid, what, expects, err)`: parses the
    single argument of a keyword setting the string `<field>` of the settings
    of a provider, possibly read from an environment variable with
    `env:<variable>`, and checks it with `<valid>`, such as
    `cloudauth_is_http_url()`. The secrets are read with
    `cloudauth_cfg_read_secret()` instead (see section 2);

- `cloudauth_pem_private_key(pem, password)`: loads the private key of PEM
    data, such as a certificate or a credential file read at parse time,
    decrypted with `<password>` unless it is `IST_NULL`. The PEM functions of
    OpenSSL called by the providers must use `cloudauth_pem_password()` as
    password callback, so that they never prompt for a password;

- `cloudauth_jwt_sign(out, header, claims, key, alg, err)`: appends a JWT
    signed with an RSA private key, with RS256 or PS256, such as the client
    assertions exchanged for a token. The JWT is a credential, so `<out>` must
    be wiped.

## 7. Signature Version 4

The `sigv4` signer signs the requests with an HMAC key, as Amazon S3 and the
storages compatible with it, and Google Cloud Storage with its HMAC keys,
expect it. Its token is `<access-key-id>:<secret>`, or
`<access-key-id>:<secret>:<session-token>` for a temporary key, which the core
checks with `cloudauth_sigv4_check_token()` before the provider. The region is
set by the generic `region` keyword, in `prof->region`, which the core only
accepts with this signer.

The variants differ by their names, so a provider describes its own one in a
`struct cloudauth_sigv4` (cloudauth_sigv4-t.h), referenced by the sigv4 field
of the provider. The core then signs the requests with `cloudauth_sigv4_sign()`
instead of calling the `sign()` callback, checks the tokens against the
variant, and requires `region` if the variant has no default one. The signer
reports the reason of its failures, and traces the scope, the signed headers
and the hash of the canonical request of each request. The fields of
`struct cloudauth_sigv4` are:

- algorithm: the name of the algorithm, such as `AWS4-HMAC-SHA256` or
    `GOOG4-HMAC-SHA256`;

- key_prefix: the prefix of the secret deriving the signing key, such as `AWS4`
    or `GOOG4`;

- hdr_pfx: the prefix of the headers of the storage, such as `x-amz-` or
    `x-goog-`, which are all signed;

- hash_hdr, date_hdr, token_hdr: the names, in lower case, of the headers
    carrying the hash of the payload, the date and the session token, such as
    `x-amz-content-sha256`, `x-amz-date` and `x-amz-security-token`. They must
    start with hdr_pfx so that they are signed. The token_hdr is `IST_NULL` if
    the variant has no session tokens, which are then rejected;

- service, request: the service and the request type of the credential scope,
    such as `s3` and `aws4_request`;

- region: the region used without `region`, or NULL if it is mandatory.

The signed headers are the Host header and all the headers starting with
hdr_pfx, the ones of the client as well as the ones added by the signer.
The path and the query string are URL-decoded then encoded again with only the
unreserved characters of RFC 3986, the parameters being sorted once encoded, at
most `CLOUDAUTH_SIGV4_MAX_PARAMS`. The payload is not signed
(`UNSIGNED-PAYLOAD`), since it is not known yet when the request is signed. The
secret, the signing key, the canonical request, which may carry the session
token, and the Authorization header are wiped once the request is signed.
