/*
 * include/cloudauth/cloudauth_azure-t.h
 * Cloud storage authentication: Azure Blob Storage provider, type definitions.
 *
 * Copyright 2026 Aleksandar Lazic <al-haproxy@none.at>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#ifndef _CLOUDAUTH_AZURE_T_H
#define _CLOUDAUTH_AZURE_T_H

#include <import/ist.h>

#include <haproxy/openssl-compat.h>

/* The Azure Storage REST API version sent by default in "x-ms-version": the
 * latest one deployed in all the Azure regions.
 */
#define CLOUDAUTH_AZURE_VERSION "2026-04-06"

/* Maximum size of a decoded storage account key (the keys are 64 bytes) */
#define CLOUDAUTH_AZURE_MAX_KEY 256

/* Maximum number of query string parameters covered by a Shared Key signature */
#define CLOUDAUTH_AZURE_MAX_PARAMS 64

/* The resource whose tokens are requested from the managed identity endpoints
 * ("https://storage.azure.com/"), URL-encoded for the query string.
 */
#define CLOUDAUTH_AZURE_RESOURCE "https%3A%2F%2Fstorage.azure.com%2F"

/* The default endpoint of the Azure Instance Metadata Service (IMDS) */
#define CLOUDAUTH_AZURE_IMDS_ENDPOINT "http://169.254.169.254/metadata/identity/oauth2/token"

/* The scope of the tokens requested from Microsoft Entra ID */
#define CLOUDAUTH_AZURE_SCOPE "https://storage.azure.com/.default"

/* The type of the client assertions sent to Microsoft Entra ID */
#define CLOUDAUTH_AZURE_ASSERTION_TYPE "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

/* The inputs of the "workload-identity" token source */
enum cloudauth_azure_wi_input {
	CLOUDAUTH_AZURE_INPUT_FEDERATED_TOKEN = 0, /* "federated-token" */
};

/* Lifetime of the client assertions signed with the certificate of an
 * application, in seconds. Microsoft recommends at most 10 minutes.
 */
#define CLOUDAUTH_AZURE_ASSERTION_LIFETIME 600

/* Size of the SHA-256 thumbprint of a certificate encoded in base64url
 * ("x5t#S256"): 43 characters for 32 bytes, but a2base64url() requires the
 * room of the padded encoding (44 characters) plus the trailing zero.
 */
#define CLOUDAUTH_AZURE_X5T_SIZE 45

/* The default Microsoft Entra ID authority host, of the Azure public cloud */
#define CLOUDAUTH_AZURE_AUTHORITY_HOST "https://login.microsoftonline.com"

/* The token sources of the Azure provider */
enum cloudauth_azure_src {
	CLOUDAUTH_AZURE_SRC_MI = 0,     /* "managed-identity" */
	CLOUDAUTH_AZURE_SRC_SECRET,     /* "client-secret" */
	CLOUDAUTH_AZURE_SRC_WI,         /* "workload-identity" */
	CLOUDAUTH_AZURE_SRC_CERT,       /* "client-certificate" */
	/* must always be last */
	CLOUDAUTH_AZURE_SRC_ENTRIES
};

/* The Azure settings of a profile ("provider azure") */
struct cloudauth_azure_ctx {
	char *account;                  /* storage account name, for the Shared Key signer */
	char *version;                  /* "x-ms-version" sent, NULL for the default */
	char *client_id;                /* client ID of a managed identity or an application, or NULL */
	char *identity_endpoint;        /* App Service endpoint ($IDENTITY_ENDPOINT), or NULL */
	struct ist identity_header;     /* secret of the App Service endpoint ($IDENTITY_HEADER) */
	char *tenant_id;                /* Microsoft Entra ID tenant of the application, or NULL */
	char *authority_host;           /* authority host forced by "azure-authority-host", or NULL */
	struct ist client_secret;       /* client secret of the application */
	struct ist cert_pem;            /* certificate and private key of the application, until loaded */
	struct ist cert_password;       /* password of the private key, until loaded */
	int cert_no_password;           /* the private key is declared as not encrypted ("no-password") */
	char *cert_arg;                 /* where the certificate was read from, for the error messages */
	EVP_PKEY *cert_key;             /* private key of the certificate of the application, once loaded */
	char cert_x5t[CLOUDAUTH_AZURE_X5T_SIZE]; /* SHA-256 thumbprint of the certificate, in base64url */
};

#endif /* _CLOUDAUTH_AZURE_T_H */
