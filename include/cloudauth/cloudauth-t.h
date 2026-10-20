/*
 * include/cloudauth/cloudauth-t.h
 * Cloud storage authentication: type definitions.
 *
 * Copyright 2026 Aleksandar Lazic <al-haproxy@none.at>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#ifndef _CLOUDAUTH_T_H
#define _CLOUDAUTH_T_H

#include <import/ist.h>

#include <haproxy/api-t.h>
#include <haproxy/buf-t.h>
#include <haproxy/http-hdr-t.h>
#include <haproxy/http-t.h>
#include <haproxy/list-t.h>
#include <haproxy/thread-t.h>

struct cloudauth_provider;
struct cloudauth_sigv4;
struct cloudauth_source;
struct httpclient;
struct htx;
struct stream;
struct task;

/* How the requests are authenticated */
enum cloudauth_signer {
	CLOUDAUTH_SIGNER_NONE = 0,  /* not set yet */
	CLOUDAUTH_SIGNER_BEARER,    /* "Authorization: Bearer <token>" */
	CLOUDAUTH_SIGNER_SAS,       /* shared access signature appended to the query string */
	CLOUDAUTH_SIGNER_SHAREDKEY, /* request signed with a shared key */
	CLOUDAUTH_SIGNER_SIGV4,     /* request signed with an HMAC key (Signature Version 4) */
	/* the number of signers must always be placed last */
	CLOUDAUTH_SIGNER_ENTRIES
};

/* Where the credential of a profile comes from */
enum cloudauth_src {
	CLOUDAUTH_SRC_NONE = 0,     /* not set */
	CLOUDAUTH_SRC_ENV,          /* environment variable, read on startup */
	CLOUDAUTH_SRC_FILE,         /* file, read on startup */
	CLOUDAUTH_SRC_CLI,          /* only injected from the CLI */
	CLOUDAUTH_SRC_FETCH,        /* fetched by HAProxy from a token source of the provider */
};

/* State of the request fetching the credential of a profile */
enum cloudauth_fetch_state {
	CLOUDAUTH_FETCH_IDLE = 0,   /* no request in progress */
	CLOUDAUTH_FETCH_SENT,       /* a request was sent, waiting for its end */
	CLOUDAUTH_FETCH_ENDED,      /* the response was received, or the request failed */
};

/* State of the credential of a profile */
enum cloudauth_cred_state {
	CLOUDAUTH_CRED_MISSING = 0, /* no credential was loaded yet */
	CLOUDAUTH_CRED_VALID,       /* the credential may be used */
	CLOUDAUTH_CRED_EXPIRED,     /* the credential expired */
};

/* The credential of a profile. It is a secret: it must never be logged nor
 * dumped, and it is wiped when it is released.
 */
struct cloudauth_cred {
	struct ist token;               /* the token, IST_NULL if not loaded */
	unsigned int expire;            /* expiration date (wall clock, in seconds), 0 = never */
	unsigned int updated;           /* date of the last update (wall clock, in seconds) */
	int expired_reported;           /* the expiration was already logged */
};

/* Size of the reason of the last failure to fetch a credential */
#define CLOUDAUTH_FETCH_ERROR_SIZE 128

/* Default timeout of the response to a request fetching a credential, in
 * milliseconds ("fetch-timeout")
 */
#define CLOUDAUTH_FETCH_TIMEOUT 5000

/* Default delay before refreshing a credential whose expiration date is
 * unknown, in seconds ("fetch-refresh")
 */
#define CLOUDAUTH_FETCH_REFRESH 3600

/* Default maximum delay between two attempts after failures, in seconds
 * ("fetch-max-backoff")
 */
#define CLOUDAUTH_FETCH_MAX_BACKOFF 300

/* Maximum number of inputs of a token source */
#define CLOUDAUTH_MAX_INPUTS 4

/* An input of a token source, such as a Kubernetes service account token
 * exchanged for a credential. It is a secret, loaded when the configuration
 * is parsed ("input") or injected from the CLI, since the file system is never
 * accessed at runtime.
 */
struct cloudauth_input {
	struct ist value;               /* the input, IST_NULL if missing */
	unsigned int expire;            /* expiration date (wall clock, in seconds), 0 if unknown */
	unsigned int updated;           /* date of the last update (wall clock, in seconds), 0 if never */
};

/* Maximum number of requests of a single fetch of a credential, such as the
 * session token, the role and the credentials of a metadata service. It only
 * protects against a token source which would never end a fetch.
 */
#define CLOUDAUTH_FETCH_MAX_STEPS 4

/* The fetching of the credential of a profile from a token source */
struct cloudauth_fetch {
	const struct cloudauth_source *source; /* where the credential is fetched from */
	struct task *task;              /* fetches the credential, then refreshes it */
	struct httpclient *hc;          /* the request in progress, only valid while not idle */
	enum cloudauth_fetch_state state; /* state of the request, atomically updated */
	unsigned int failures;          /* number of consecutive failures */
	int fetched;                    /* a credential was already fetched */
	unsigned int next;              /* date of the next fetch (wall clock, in seconds), 0 = none */
	char error[CLOUDAUTH_FETCH_ERROR_SIZE]; /* reason of the last failure, empty after a success */
	unsigned int timeout;           /* timeout of the response, in milliseconds, 0 = default */
	unsigned int refresh;           /* refresh delay if the expiration is unknown, in seconds, 0 = default */
	unsigned int max_backoff;       /* maximum delay between attempts, in seconds, 0 = default */
	char *endpoint;                 /* URL of the token endpoint set by "token-endpoint", or NULL */
	char *scopes;                   /* scopes set by "token-scopes", separated by spaces, or NULL */
	int step;                       /* index of the request of the fetch in progress, from 0 */
	struct buffer *carry;           /* what the previous request of the fetch kept for the next one, or NULL */
};

/* A credential profile, declared by a "cloudauth" section */
struct cloudauth_profile {
	char *name;                     /* section name */
	char *file;                     /* config file where the section was declared */
	int line;                       /* config line where the section was declared */
	enum cloudauth_signer signer;   /* how the requests are authenticated */
	enum cloudauth_src token_src;   /* where the token comes from */
	char *token_src_arg;            /* variable name, file path or token source name, NULL for the CLI */
	const struct cloudauth_provider *provider; /* the storage provider, NULL if none */
	void *provider_ctx;             /* settings of the provider, owned by it */
	char *region;                   /* region of the "sigv4" signer ("region"), or NULL */
	__decl_thread(HA_RWLOCK_T lock); /* protects <cred>, <inputs>, <fetch.failures>, <fetch.next> and <fetch.error> */
	struct cloudauth_cred cred;     /* the current credential */
	struct cloudauth_input inputs[CLOUDAUTH_MAX_INPUTS]; /* inputs of the token source, in its order */
	struct task *expire_task;       /* reports the expiration of the credential */
	struct cloudauth_fetch fetch;   /* fetching of the credential (CLOUDAUTH_SRC_FETCH) */
	struct list list;               /* next profile */
};

/* Maximum number of headers of a request fetching a credential, set by its
 * token source. The headers are kept in a fixed array to avoid an allocation
 * per request. The token endpoints only need one or two of them, since the
 * HTTP client already sends the Host, Accept and User-Agent headers, and the
 * request fails if a token source adds more.
 */
#define CLOUDAUTH_FETCH_MAX_HDRS 8

/* A request fetching a credential, prepared by a token source. The buffers
 * are allocated and wiped by the caller, since they may carry secrets.
 */
struct cloudauth_fetch_req {
	enum http_meth_t meth;          /* method, HTTP_METH_GET by default */
	struct buffer *url;             /* URL of the request */
	struct buffer *body;            /* payload, empty if none */
	struct buffer *values;          /* storage of the header values and of the inputs */
	int nb_hdrs;                    /* number of headers in <hdrs> */
	struct http_hdr hdrs[CLOUDAUTH_FETCH_MAX_HDRS + 1]; /* headers, followed by an empty one */
	struct ist inputs[CLOUDAUTH_MAX_INPUTS]; /* copies of the inputs of the profile, in the order of the source */
};

/* Maximum length of the scopes set by "token-scopes", separators included. The
 * scopes are short URLs, so a longer list is certainly a mistake, which is
 * better reported on startup than by each fetch once the request does not fit
 * in a buffer.
 */
#define CLOUDAUTH_MAX_SCOPES_LEN 1024

/* Maximum length of the region set by "region". The regions are short names,
 * such as "us-east-1", and are part of every signature.
 */
#define CLOUDAUTH_MAX_REGION_LEN 64

/* The settings of the fetching supported by a token source */
#define CLOUDAUTH_SRC_F_ENDPOINT 0x00000001 /* its token endpoint may be set with "token-endpoint" */
#define CLOUDAUTH_SRC_F_SCOPES   0x00000002 /* its scopes may be set with "token-scopes" */

/* A source of tokens, from which HAProxy fetches the credentials of a profile
 * and refreshes them before they expire. It is provided by a storage provider
 * and selected with the "token" keyword. The callbacks are mandatory unless
 * stated otherwise.
 */
struct cloudauth_source {
	const char *name;               /* name used by the "token" keyword, NULL ends a list */
	unsigned int signers;           /* signers using these tokens, as (1 << CLOUDAUTH_SIGNER_*) */
	const char * const *inputs;     /* names of the inputs, NULL-terminated, at most CLOUDAUTH_MAX_INPUTS, or NULL */
	unsigned int flags;             /* supported settings, as CLOUDAUTH_SRC_F_* */

	/* Optional. Called when the source is selected for profile <prof>,
	 * whose provider is set. Returns 0 on success, otherwise -1 with <err>
	 * filled.
	 */
	int (*init)(struct cloudauth_profile *prof, char **err);

	/* Prepares in <req> the request fetching a credential for profile
	 * <prof>, the request <prof->fetch.step> of the fetch for the token
	 * sources needing several ones. Returns 0 on success, otherwise -1
	 * with <err> filled.
	 */
	int (*request)(const struct cloudauth_profile *prof, struct cloudauth_fetch_req *req, char **err);

	/* Extracts from the response of status <status> and payload <body>
	 * the credential into <token>, and its expiration date (wall clock, in
	 * seconds, 0 if unknown) into <expire>. Returns 0 on success, otherwise
	 * -1 with <err> filled, which must never contain the payload. A token
	 * source needing another request returns 1 instead, <token> then
	 * containing what it keeps for the next request, which finds it in
	 * <prof->fetch.carry>.
	 */
	int (*response)(const struct cloudauth_profile *prof, int status, const struct buffer *body,
	                struct buffer *token, unsigned int *expire, char **err);
};

/* A storage provider (Azure, ...). Each provider is implemented in its own
 * module, which registers it with cloudauth_register_provider() and may also
 * register its own keywords in the "cloudauth" sections. A profile without
 * provider only supports the bearer signer. The callbacks are optional unless
 * stated otherwise.
 */
struct cloudauth_provider {
	const char *name;               /* name used by the "provider" keyword */
	unsigned int signers;           /* supported signers, as (1 << CLOUDAUTH_SIGNER_*) */

	/* Called when the provider is set for profile <prof>, to allocate
	 * <prof->provider_ctx>. Returns 0 on success, otherwise -1 with <err>
	 * filled.
	 */
	int (*init)(struct cloudauth_profile *prof, char **err);

	/* Called once the section of profile <prof> is parsed. Returns 0 on
	 * success, otherwise -1 with <err> filled.
	 */
	int (*check)(struct cloudauth_profile *prof, char **err);

	/* Checks that <token> may be used by the signer of profile <prof>,
	 * which is known. Returns 0 on success, otherwise -1 with <err>
	 * filled, which must never contain the token.
	 */
	int (*check_token)(const struct cloudauth_profile *prof, const struct ist token, char **err);

	/* Mandatory unless "sigv4" is the only supported signer, which is
	 * performed by the core. Authenticates the request in <htx> of the
	 * stream <strm>, used for the traces, with the credential of profile
	 * <prof>, whose lock is held. The headers and the query string
	 * parameters which may carry credentials were removed and the Host
	 * header was set. Returns 0 on success, -1 on failure.
	 */
	int (*sign)(const struct cloudauth_profile *prof, const struct stream *strm, struct htx *htx);

	/* Releases <prof->provider_ctx>, which may be NULL */
	void (*release)(struct cloudauth_profile *prof);

	const struct cloudauth_source *sources; /* token sources, NULL if none */
	const struct cloudauth_sigv4 *sigv4; /* variant of the "sigv4" signer, set if and only if it is supported */

	struct list list;               /* next registered provider, only used on startup */
};

/* The cloudauth settings of a server */
struct cloudauth_srv {
	char *profile_name;                 /* name of the profile, until it is resolved */
	struct cloudauth_profile *profile;  /* the profile, once resolved */
};

#endif /* _CLOUDAUTH_T_H */
