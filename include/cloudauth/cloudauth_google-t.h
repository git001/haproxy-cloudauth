/*
 * include/cloudauth/cloudauth_google-t.h
 * Cloud storage authentication: Google Cloud Storage provider, type
 * definitions.
 *
 * Copyright 2026 Aleksandar Lazic <al-haproxy@none.at>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#ifndef _CLOUDAUTH_GOOGLE_T_H
#define _CLOUDAUTH_GOOGLE_T_H

#include <import/ist.h>

#include <haproxy/openssl-compat.h>

/* The default token endpoint of the metadata server of Google Cloud (Compute
 * Engine, GKE, Cloud Run...), for the service account attached to the
 * workload. The IP address is used rather than "metadata.google.internal" so
 * that no resolver is needed.
 */
#define CLOUDAUTH_GOOGLE_METADATA_ENDPOINT "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token"

/* The default OAuth 2.0 token endpoint of Google, to which the service
 * accounts send their assertions.
 */
#define CLOUDAUTH_GOOGLE_TOKEN_ENDPOINT "https://oauth2.googleapis.com/token"

/* The default Security Token Service endpoint of Google, which exchanges the
 * tokens of the workload identities for access tokens.
 */
#define CLOUDAUTH_GOOGLE_STS_ENDPOINT "https://sts.googleapis.com/v1/token"

/* The scope of the tokens requested from the token endpoints of Google without
 * "token-scopes": only the read accesses to the storage.
 */
#define CLOUDAUTH_GOOGLE_SCOPE "https://www.googleapis.com/auth/devstorage.read_only"

/* The region of the signatures of the HMAC keys without "region": Cloud
 * Storage accepts any region, "auto" being the usual one.
 */
#define CLOUDAUTH_GOOGLE_REGION "auto"

/* The grant type of the assertions exchanged for a token (RFC 7523) */
#define CLOUDAUTH_GOOGLE_JWT_BEARER "urn:ietf:params:oauth:grant-type:jwt-bearer"

/* The grant type of the token exchanges, and the type of the tokens requested
 * from the Security Token Service (RFC 8693).
 */
#define CLOUDAUTH_GOOGLE_TOKEN_EXCHANGE "urn:ietf:params:oauth:grant-type:token-exchange"
#define CLOUDAUTH_GOOGLE_ACCESS_TOKEN   "urn:ietf:params:oauth:token-type:access_token"

/* Lifetime of the assertions signed with a service account key, in seconds:
 * the maximum accepted by Google.
 */
#define CLOUDAUTH_GOOGLE_ASSERTION_LIFETIME 3600

/* The token sources of the Google provider */
enum cloudauth_google_src {
	CLOUDAUTH_GOOGLE_SRC_METADATA = 0, /* "metadata-server" */
	CLOUDAUTH_GOOGLE_SRC_SA,           /* "service-account" */
	CLOUDAUTH_GOOGLE_SRC_WI,           /* "workload-identity" */
	/* must always be last */
	CLOUDAUTH_GOOGLE_SRC_ENTRIES
};

/* The inputs of the "workload-identity" token source */
enum cloudauth_google_input {
	CLOUDAUTH_GOOGLE_INPUT_FEDERATED_TOKEN = 0, /* "federated-token" */
};

/* The Google settings of a profile ("provider google") */
struct cloudauth_google_ctx {
	struct ist credentials;         /* credential file ("google-credentials"), until loaded */
	char *credentials_arg;          /* where the credential file was read from, for the error messages */
	EVP_PKEY *sa_key;               /* private key of the service account, once loaded */
	char *sa_email;                 /* e-mail address of the service account ("client_email") */
	char *sa_key_id;                /* identifier of the key ("private_key_id"), or NULL */
	char *sa_token_uri;             /* token endpoint of the credential file ("token_uri"), or NULL */
	char *wi_audience;              /* workload identity pool provider ("audience") */
	char *wi_token_type;            /* type of the federated token ("subject_token_type") */
	char *wi_token_url;             /* Security Token Service endpoint ("token_url"), or NULL */
};

#endif /* _CLOUDAUTH_GOOGLE_T_H */
