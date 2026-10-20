/*
 * include/haproxy/cloudauth_s3-t.h
 * Cloud storage authentication: Amazon S3 and compatible storages provider,
 * type definitions.
 *
 * Copyright 2026 Aleksandar Lazic <al-haproxy@none.at>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#ifndef _HAPROXY_CLOUDAUTH_S3_T_H
#define _HAPROXY_CLOUDAUTH_S3_T_H

#include <import/ist.h>

/* The address of the credential endpoint of the Amazon ECS tasks, to which
 * the relative URI of AWS_CONTAINER_CREDENTIALS_RELATIVE_URI is appended.
 */
#define CLOUDAUTH_S3_ECS_HOST "http://169.254.170.2"

/* The default credential endpoint of the EKS Pod Identity Agent */
#define CLOUDAUTH_S3_POD_IDENTITY_ENDPOINT "http://169.254.170.23/v1/credentials"

/* The default endpoint of the EC2 Instance Metadata Service, to which the
 * paths of its requests are appended, and the lifetime of its session tokens,
 * in seconds: a new session is opened for each fetch, so it only needs to last
 * for its three requests.
 */
#define CLOUDAUTH_S3_IMDS_ENDPOINT   "http://169.254.169.254"
#define CLOUDAUTH_S3_IMDS_TOKEN_TTL  "300"

/* Maximum length of a session token of the EC2 Instance Metadata Service, and
 * of the name of an IAM role.
 */
#define CLOUDAUTH_S3_IMDS_MAX_TOKEN_LEN 1024
#define CLOUDAUTH_S3_ROLE_NAME_MAX_LEN  64

/* The regional endpoint of the AWS Security Token Service, around the region
 * of the profile, and the version of its API.
 */
#define CLOUDAUTH_S3_STS_HOST_PREFIX "https://sts."
#define CLOUDAUTH_S3_STS_HOST_SUFFIX ".amazonaws.com/"
#define CLOUDAUTH_S3_STS_VERSION     "2011-06-15"

/* The name of the role sessions without "s3-role-session-name" */
#define CLOUDAUTH_S3_ROLE_SESSION_NAME "haproxy"

/* Lengths of the role ARNs and of the role session names accepted by the AWS
 * Security Token Service.
 */
#define CLOUDAUTH_S3_ROLE_ARN_MIN_LEN      20
#define CLOUDAUTH_S3_ROLE_ARN_MAX_LEN      2048
#define CLOUDAUTH_S3_ROLE_SESSION_MIN_LEN  2
#define CLOUDAUTH_S3_ROLE_SESSION_MAX_LEN  64

/* The token sources of the S3 provider */
enum cloudauth_s3_src {
	CLOUDAUTH_S3_SRC_CONTAINER = 0,    /* "container" */
	CLOUDAUTH_S3_SRC_POD_IDENTITY,     /* "pod-identity" */
	CLOUDAUTH_S3_SRC_WI,               /* "workload-identity" */
	CLOUDAUTH_S3_SRC_IMDS,             /* "instance-metadata" */
	/* must always be last */
	CLOUDAUTH_S3_SRC_ENTRIES
};

/* The requests of a fetch from the EC2 Instance Metadata Service, in their
 * order (prof->fetch.step).
 */
enum cloudauth_s3_imds_step {
	CLOUDAUTH_S3_IMDS_STEP_TOKEN = 0,  /* PUT of a session token */
	CLOUDAUTH_S3_IMDS_STEP_ROLE,       /* GET of the name of the IAM role */
	CLOUDAUTH_S3_IMDS_STEP_CREDS,      /* GET of the credentials of the role */
};

/* The agents of AWS local to the host which a token source may reach through
 * HTTP: their IPv4 addresses, in host order, a null one ending the list, their
 * IPv6 address, and their description for the error messages.
 */
struct cloudauth_s3_agents {
	unsigned int ipv4[3];
	unsigned char ipv6[16];
	const char *desc;
};

/* The inputs of the token sources, each source numbering its own ones */
enum cloudauth_s3_input {
	CLOUDAUTH_S3_INPUT_AUTH_TOKEN = 0,      /* "authorization-token" ("pod-identity") */
	CLOUDAUTH_S3_INPUT_FEDERATED_TOKEN = 0, /* "federated-token" ("workload-identity") */
};

/* The S3 settings of a profile ("provider s3") */
struct cloudauth_s3_ctx {
	char *endpoint;                 /* credential endpoint of the environment, or NULL */
	struct ist auth_token;          /* AWS_CONTAINER_AUTHORIZATION_TOKEN ("container"), or IST_NULL */
	char *role_arn;                 /* role assumed by "workload-identity" ("s3-role-arn"), or NULL */
	char *role_session_name;        /* name of its sessions ("s3-role-session-name"), or NULL */
};

#endif /* _HAPROXY_CLOUDAUTH_S3_T_H */
