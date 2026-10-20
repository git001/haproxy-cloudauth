# HAProxy cloud storage authentication filter: configuration manual

This document describes the configuration of the cloudauth filter, an addon of
HAProxy. It completes the configuration manual of HAProxy, to which it refers
for the general concepts (filters, time units, loggers, traces...).

## 1. Introduction

The cloud object storages (Azure Blob Storage, Google Cloud Storage, S3
compatible storages...) require the requests to be authenticated, generally
with a token or a signature. The cloudauth filter authenticates the requests
that HAProxy sends to them, with the credentials of a profile declared by a
`cloudauth` section (see section 3), so that the clients do not need any
credential and cannot use their own ones.

The filter and the `cloudauth` sections are experimental, meaning that
`expose-experimental-directives` must be in the global section so they can be
used.

The bearer tokens are supported by most of the storages. The signatures and the
headers specific to a storage are provided by a storage provider (see
`provider` in section 3). All of them are built by default, and each one may be
left out at build time (see README.md):

- `azure`: Azure Blob Storage, left out with `CLOUDAUTH_AZURE=0`.
- `google`: Google Cloud Storage, left out with `CLOUDAUTH_GOOGLE=0`.
- `s3`: Amazon S3 and compatible storages, left out with `CLOUDAUTH_S3=0`.

The filter and the providers which were built are reported by `haproxy -vv`:

```
Built with the cloudauth filter.
Built with the cloudauth provider: azure (Azure Blob Storage).
...
```

The events affecting the credentials are reported once, when they happen, to
the global loggers: a credential updated from the CLI (notice) and a credential
which expired (warning). The profiles without valid credential are also
reported on startup. The state of the profiles may be inspected with the
`show cloudauth` CLI command (see `doc/management.md`).

The processing may also be followed with the `cloudauth` trace source (see
`trace` in the management guide of HAProxy, and the `traces` section): the
authentication of each request, the client credentials removed from it (by
name), and the updates and fetches of the credentials, with the status of the
token endpoints and the size of their responses. With the `sigv4` signer, the
scope, the signed headers and the hash of the canonical request are also
traced, so that they may be compared with the ones that the storage reports
when it rejects a signature. The traces never contain the credentials, nor the
headers, query strings or payloads carrying them.

## 2. The cloudauth filter

### filter-config cloudauth

```
filter-config cloudauth [enabled] profile <name> host <host>
```

Declares the cloud storage authentication filter in a backend. It may only be
declared with the `filter-config` directive, and only once per backend, so the
instance id is not needed. It is experimental and must be allowed via a global
`expose-experimental-directives`.

- `<name>` is the name of the credential profile used to authenticate the
    requests of the backend, declared by a `cloudauth` section (see section 3).
    The profile may be declared after the backend.

- `<host>` is the host the requests are destined to, which is set in the Host
    header of the requests, such as `myaccount.blob.core.windows.net`,
    `storage.googleapis.com` or `s3.eu-west-1.amazonaws.com`. It may be
    followed by a port, and may be an IPv6 address between brackets.

Like any filter instance declared with `filter-config`, the filter is only used
when it is enabled, with `enabled` or `filter-enable`. Otherwise the requests
of the backend are sent as received, without authentication, and a warning is
emitted on startup.

The request is processed once its headers were analyzed, after all the HTTP
rules of the frontend and of the backend and after the other filters, in this
order:

- the headers which may carry credentials, and the ones set by the signers,
    are removed: `Authorization`, `X-Auth-Token`, `X-Amz-Date`,
    `X-Amz-Security-Token`, `X-Goog-Date`, `X-Ms-Copy-Source-Authorization`,
    `X-Ms-Date` and `X-Ms-Version`. The hashes of the payload,
    `X-Amz-Content-Sha256` and `X-Goog-Content-Sha256`, are replaced by the
    `sigv4` signer. This way, a client cannot use its own credentials, nor
    interfere with the ones added by HAProxy. The other headers of the
    storages, starting with `X-Amz-`, `X-Ms-` or `X-Goog-`, are kept, and
    signed when the signer covers them (see `signer` in section 3);

- for the same reasons, the query string parameters which may carry credentials
    are removed: the parameters of the Azure shared access signatures (`sv`,
    `ss`, `srt`, `sp`, `se`, `st`, `spr`, `sip`, `si`, `sr`, `sig`, `sdd`,
    `ses`, `skoid`, `sktid`, `skt`, `ske`, `sks`, `skv`, `saoid`, `suoid`,
    `scid`, `sduoid`, `rscc`, `rscd`, `rsce`, `rscl`, `rsct`, `tn`, `spk`,
    `srk`, `epk` and `erk`), the ones of the pre-signed URLs of S3 and Google
    Cloud Storage (`AWSAccessKeyId`, `Signature`, `Expires`, `GoogleAccessId`
    and all the parameters starting with `X-Amz-` or `X-Goog-`), and
    `access_token`. The names are compared without case once URL-decoded, and
    the parameters whose name cannot be decoded are removed too;

- the Host header is set to `<host>`;

- the request is authenticated with the credential of the profile, as described
    by its signer (see `signer` in section 3).

The Host header sent by the client is never used: with most storages, it
designates the account or the bucket, so a client could otherwise access any
data the credentials give access to. By default, the servers without `sni`
present the Host header of the request as TLS SNI (see `sni-auto`), which is
then `<host>` without its port. A server reached with another name must set its
`sni`.

The filter processes the requests independently of the HTTP versions. The
clients may use HTTP/1.1, HTTP/2 or HTTP/3, and the servers HTTP/1.1 or HTTP/2.
The requests of HTTP/2 and HTTP/3 clients carry the authority in their URI,
which is replaced by `<host>` too, so that it is the one sent to an HTTP/2
server. HTTP/3 has not been tested on any side, nor the QUIC servers, which are
experimental in HAProxy.

The headers of the storages sent by the clients are needed by some requests,
mostly the writes, such as `x-ms-blob-type` with Azure, or the metadata of the
objects (`x-amz-meta-*`, `x-ms-meta-*`, `x-goog-meta-*`). However, some of them
let a client act with the permissions of the credentials beyond the requested
object, and must be removed by the HTTP rules unless the clients are trusted,
for instance the ones making an object public (`x-amz-acl`, `x-amz-grant-*`,
`x-goog-acl`), copying an object from another one (`x-amz-copy-source`,
`x-ms-copy-source`, `x-goog-copy-source`), or choosing the project billed for
the requests (`x-goog-user-project`). The simplest is to only keep the needed
ones, here the metadata and the storage class with S3, the regular expression
requiring PCRE2 (`USE_PCRE2=1`):

```
http-request del-header ^x-amz-(?!meta-|storage-class$) -m reg
```

Or to remove the unwanted ones:

```
http-request del-header x-amz-acl
http-request del-header x-amz-grant- -m beg
http-request del-header x-amz-copy-source -m beg
```

The signature does not depend on the server, so all the servers of the backend
must give access to the same storage, behind the same host. The request is
authenticated once, before a server is chosen, and remains so when it is sent
again to another server after a connection failure followed by a redispatch, or
after a L7 retry (see `retry-on`). A storage reached with other credentials, in
another region or from another provider is declared in its own backend, which
may be used as a fallback, for instance:

```
backend storage
    mode http
    filter-config cloudauth enabled profile primary-token host storage-1.example.com
    server primary storage-1.example.com:443 ssl verify required ca-file @system-ca check

backend storage-fallback
    mode http
    filter-config cloudauth enabled profile fallback-token host storage-2.example.com
    server fallback storage-2.example.com:443 ssl verify required ca-file @system-ca check

frontend www
    bind :8080
    use_backend storage-fallback if { nbsrv(storage) eq 0 }
    default_backend storage
```

If the request cannot be authenticated, for instance because the profile has no
valid credential, it is not sent to any server, and the client receives the 503
error of the backend, which may be customized with `errorfile` or
`http-errors`. The request is logged with the termination state `IR` (an
internal error during the request processing). The reason is stored in the
`txn.cloudauth.error` variable, which may be logged as well. Note that the
health checks are not authenticated, so they do not detect such an issue, but
the state changes of the credentials are logged (see section 1). A request
which cannot be authenticated as sent by the client, such as a chunked payload
signed by the client (see `signer sigv4`), is rejected with the 400 error
instead, and logged with the termination state `PR`.

```
backend storage
    mode http
    log-format "${HAPROXY_HTTP_LOG_FMT} cloudauth_error=%{+Q}[var(txn.cloudauth.error)]"
    errorfile 503 /etc/haproxy/errors/storage-503.http
    filter-config cloudauth enabled profile storage-token host storage.example.com
    ...
```

The backends count the authenticated requests (`cloudauth_req_signed`) and the
requests which could not be authenticated (`cloudauth_req_failed`). These
counters are reported by the `show stat` CLI command and by the Prometheus
exporter.

The request is authenticated before it is queued, when the servers are full.
The signatures of the storages are valid for a few minutes (15 minutes for
Amazon S3 and Azure Blob Storage), which is generally longer than the queue
timeout, but the request is rejected by the storage if it waited longer.

The path of the request is not changed. When the container or the bucket name
is part of the path, it may be added with `http-request set-path`, for instance
`http-request set-path /media%[path]`, after the path was normalized (see
`http-request normalize-uri`).

The health checks are not authenticated: they only verify that the storage
answers, and do not detect a missing or expired credential. Since the storages
reject the `OPTIONS / HTTP/1.0` request sent by default, as well as the
unauthenticated requests to private data, the check must either read a public
object, or accept such a rejection, for instance any response which is not a
server error. The Host header of the check is also its TLS SNI (see
`check-sni-auto`):

```
backend storage
    mode http
    option httpchk
    http-check send meth HEAD uri /my-bucket/healthcheck.txt ver HTTP/1.1 hdr host storage.googleapis.com
    http-check expect ! rstatus ^5
    filter-config cloudauth enabled profile gcs-token host storage.googleapis.com
    server gcs storage.googleapis.com:443 ssl verify required ca-file @system-ca check
```

Example:

```
global
    expose-experimental-directives

cloudauth storage-token
    signer bearer
    token env:STORAGE_TOKEN

backend storage
    mode http
    http-request deny unless METH_GET or METH_HEAD
    http-request normalize-uri path-strip-dotdot full
    http-request set-path /media%[path]
    balance first
    retries 1
    retry-on conn-failure 503
    option redispatch
    filter-config cloudauth enabled profile storage-token host storage.example.com
    server primary   storage-1.example.com:443 ssl verify required ca-file @system-ca sni str(storage.example.com)
    server secondary storage-2.example.com:443 ssl verify required ca-file @system-ca sni str(storage.example.com)
```

See also: `filter-config`, `filter-enable`, `retry-on`, `option redispatch`
and `expose-experimental-directives` in the configuration manual of HAProxy.

### Writes and uploads

The writes (`PUT`, `POST`, `DELETE`...) are authenticated like the reads, with
the same credential, so the methods the clients may use are only limited by the
HTTP rules and by the permissions of the credential. A read-only access is best
enforced on both sides, with a credential which only grants the reads, and a
rule rejecting the other methods:

```
http-request deny unless METH_GET or METH_HEAD
```

The payload of the writes is forwarded as received, and is not part of the
signatures (see `signer` in section 3). The following points should be
considered with the writes:

- Amazon S3 and Azure Blob Storage require a `Content-Length` header with the
    uploads, and do not accept the chunked transfer coding, which HAProxy uses
    towards the HTTP/1.1 servers when an HTTP/2 or HTTP/3 client sends a
    payload without `Content-Length`. Such requests may be rejected early, for
    instance:

    ```
    http-request return status 411 if METH_PUT !{ req.hdr(content-length) -m found }
    ```

- the L7 retries (`retry-on` with other conditions than `conn-failure`) only
    apply to the requests fitting in a buffer (see `tune.bufsize`), so the
    large uploads are not retried;

- the multipart uploads of Amazon S3 and the uploads by blocks of Azure Blob
    Storage are made of several requests, each one authenticated on its own,
    and their query string parameters (`uploads`, `uploadId`, `partNumber`,
    `comp`, `blockid`...) are kept and signed;

- the resumable uploads of Google Cloud Storage return the URI of the upload
    session in the `Location` header of the response. This URI designates the
    storage itself, and grants the access to the upload session without any
    other credential, so a client following it sends the next requests
    directly to the storage. When they must go through HAProxy, the header may
    be rewritten with `http-response replace-header Location`.

## 3. Credential profiles

A `cloudauth` section declares a credential profile, describing how the
requests are authenticated by the cloudauth filter instances referencing it
(see section 2). Several backends may use the same profile.

### cloudauth

```
cloudauth <name>
```

Declares a credential profile named `<name>`. The name must be unique among the
`cloudauth` sections.

The following keywords are usable in a `cloudauth` section:

### account

```
account <name>
```

Sets the name of the Azure storage account, which is part of the Shared Key
signature. It requires `provider azure` first. It is mandatory with the
`sharedkey` signer and not accepted with the other ones. It is made of 3 to 24
lower case letters and digits. It cannot be deduced from the host of the
filter, since the storage may be reached with a custom domain name. Note that
with the storage emulator (Azurite), the account name is also the first part of
the path, which must then be added with `http-request set-path`.

### azure-authority-host

```
azure-authority-host <url>
```

Sets the URL of the Microsoft Entra ID authority host to which the client
secret, the federated token or the client assertion is sent with
`token client-secret`, `token workload-identity` or `token client-certificate`,
such as `AZURE_AUTHORITY_HOST`, instead of the default one
`https://login.microsoftonline.com` of the Azure public cloud, for instance
`https://login.microsoftonline.us` for Azure Government. Only HTTPS is
accepted, and `<url>` is made of the scheme, the host and an optional port. It
requires `provider azure` first.

### azure-client-id

```
azure-client-id <id> | env:<variable>
```

Sets the client ID, as a GUID, of the user-assigned managed identity whose
tokens are fetched with `token managed-identity`, or of the application whose
tokens are fetched with `token client-secret`, `token workload-identity` or
`token client-certificate`. It may be read from the environment variable
`<variable>` when the configuration is parsed, such as `AZURE_CLIENT_ID`.
Without it, `token managed-identity` uses the system-assigned identity. It is
mandatory with the other token sources. It requires `provider azure` first.

### azure-client-certificate

```
azure-client-certificate env:<variable> | file:<path>
```

Sets the certificate of the application whose tokens are fetched with
`token client-certificate`, and its private key, in PEM format, such as the
file designated by `AZURE_CLIENT_CERTIFICATE_PATH`. It is mandatory with this
token source. The private key must be an RSA key matching the certificate. If
it is encrypted, its password must be set with
`azure-client-certificate-password`. Like the token (see `token`), it is never
accepted in the configuration: it is read when the configuration is parsed,
either from the environment variable `<variable>`, which is then removed from
the environment, or from the file `<path>`. Only the private key and the
SHA-256 thumbprint of the certificate are kept once the section is parsed, and
the private key is never logged nor reported. A certificate renewed in the file
requires a reload. It requires `provider azure` first.

### azure-client-certificate-password

```
azure-client-certificate-password env:<variable> | file:<path> | no-password
```

Sets the password of the encrypted private key set with
`azure-client-certificate`, such as `AZURE_CLIENT_CERTIFICATE_PASSWORD`. Like
the other secrets, it is never accepted in the configuration: it is read when
the configuration is parsed, either from the environment variable `<variable>`,
which is then removed from the environment, or from the file `<path>`, whose
trailing spaces and line feeds are ignored. It is wiped once the private key is
decrypted. `no-password` explicitly declares that the private key is not
encrypted, which is also the case without this keyword. It requires
`provider azure` first.

### azure-client-secret

```
azure-client-secret env:<variable> | file:<path>
```

Sets the client secret of the application whose tokens are fetched with
`token client-secret`. It is mandatory with this token source. Like the token
(see `token`), it is never accepted in the configuration: it is read when the
configuration is parsed, either from the environment variable `<variable>`,
such as `AZURE_CLIENT_SECRET`, which is then removed from the environment, or
from the file `<path>`, whose trailing spaces and line feeds are ignored. It is
never logged nor reported. It requires `provider azure` first.

### azure-tenant-id

```
azure-tenant-id <id> | env:<variable>
```

Sets the Microsoft Entra ID tenant of the application whose tokens are fetched
with `token client-secret`, `token workload-identity` or
`token client-certificate`, as a GUID or a domain name such as
`contoso.onmicrosoft.com`. It may be read from the environment variable
`<variable>` when the configuration is parsed, such as `AZURE_TENANT_ID`. It is
mandatory with these token sources. It requires `provider azure` first.

### azure-version

```
azure-version <version>
```

Sets the version of the Azure Storage REST API sent in the `x-ms-version`
header, as a date like `2026-04-06`, which is the default. It requires
`provider azure` first.

### fetch-max-backoff

```
fetch-max-backoff <time>
```

Sets the maximum delay between two attempts to fetch the token from a token
source (see `token <source>`) after failures. After the first failure, a new
attempt is made after 1 second, then the delay is doubled after each new
failure: 1, 2, 4, 8, 16, 32, 64, 128 and 256 seconds, then this maximum, until
a token is fetched. The default value is 5 minutes, the maximum one is one day.
A lower value lets a profile recover sooner after an outage of the token
endpoint, while a higher one lowers the load on an endpoint which limits the
request rate, such as the Azure Instance Metadata Service. The current token is
used until it expires. `<time>` is expressed in seconds by default, and may use
any other unit as documented in section 2.5 of the configuration manual of
HAProxy. It requires `token <source>`.

### fetch-refresh

```
fetch-refresh <time>
```

Sets the delay after which a token fetched from a token source is refreshed
when its expiration date is unknown. Otherwise, the token is refreshed once
half of its lifetime has elapsed. The default value is 1 hour, the maximum one
is one day. `<time>` is expressed in seconds by default, and may use any other
unit as documented in section 2.5 of the configuration manual of HAProxy. It
requires `token <source>`.

### fetch-timeout

```
fetch-timeout <time>
```

Sets the maximum time to wait for the response of the token endpoint once the
request was sent, for each attempt of the internal HTTP client. The default
value is 5 seconds. The HTTP client makes up to `httpclient.retries` new
attempts after a timeout, and the time to establish the connection is limited
by `httpclient.timeout.connect`. `<time>` is expressed in milliseconds by
default, and may use any other unit as documented in section 2.5 of the
configuration manual of HAProxy. It requires `token <source>`.

### google-credentials

```
google-credentials env:<variable> | file:<path>
```

Loads the Google Cloud credential file, in JSON, of a service account, as
downloaded from Google Cloud, used by `token service-account`, or of a workload
identity federation (`external_account`), as generated by
`gcloud iam workload-identity-pools create-cred-config`, used by
`token workload-identity`. Like the token (see `token`), it is never accepted
in the configuration: it is read from the environment variable `<variable>`,
which is then removed from the environment, or from the file `<path>`, usually
the one named by `GOOGLE_APPLICATION_CREDENTIALS`, when the configuration is
parsed. Only the e-mail address of the service account, the identifier and the
private key of its key, and its token endpoint are kept, the private key never
being logged nor reported, or the workload identity pool provider, the type of
the federated token and the Security Token Service endpoint. Since the file is
never read again, a new key requires a reload. It requires `provider google`
first.

### input

```
input <name> env:<variable> | file:<path>
```

Loads the input `<name>` of the token source of the profile (see
`token <source>`), which must be set first, when the configuration is parsed.
The inputs are secrets that HAProxy exchanges for a token, such as the token of
a Kubernetes service account with `token workload-identity`, so they are never
accepted in the configuration: they are read from the environment variable
`<variable>`, which is then removed from the environment, or from the file
`<path>`, whose trailing spaces and line feeds are ignored. Since the file is
never read again, an input which changes must be replaced from the CLI with
`set cloudauth input` (see `doc/management.md`), for instance by a sidecar,
before it expires, or the configuration must be reloaded. Without this keyword,
the input must be injected from the CLI. An input which is a JWT is not used
after the date of its `exp` claim. The inputs are never logged nor reported,
`show cloudauth` only reports their state.

### provider

```
provider <name>
```

Sets the storage provider, which brings the signers and the headers specific to
a storage, and its own keywords, which may only be used after it. Without
provider, only the `bearer` signer is supported. The supported providers depend
on the build options (see above):

- `azure`: Azure Blob Storage. The `x-ms-version` header, required by Azure, is
    sent with all the signers (see `azure-version`). The supported signers are
    `bearer` with a Microsoft Entra ID access token, `sas` and `sharedkey`. The
    tokens of the managed identities, of the applications and of the workload
    identities may be fetched by HAProxy (see `token managed-identity`,
    `token client-secret`, `token client-certificate` and
    `token workload-identity`).

- `google`: Google Cloud Storage. The supported signers are `bearer` with an
    OAuth 2.0 access token, which may be fetched by HAProxy from the metadata
    server, with the key of a service account, or in exchange for the token of
    a workload identity (see `token metadata-server`, `token service-account`
    and `token workload-identity`), and `sigv4` with an HMAC key, only accepted
    by the XML API. The default region of `sigv4` is `auto`.

- `s3`: Amazon S3 and the storages compatible with it (MinIO, Ceph, OVHcloud
    Object Storage, STACKIT Object Storage...). The supported signer is
    `sigv4` with an access key, permanent or temporary with its session token.
    The region is mandatory (see `region`). The temporary access keys of the
    containers, of the workload identities and of the EC2 instances may be
    fetched by HAProxy (see `token container`, `token pod-identity`,
    `token workload-identity` and `token instance-metadata`).

### region

```
region <name>
```

Sets the region of the storage, which is part of the signatures of the `sigv4`
signer, instead of the default one of the provider (see `provider`). It is made
of up to 64 letters, digits, dashes and underscores, such as `us-east-1`, `gra`
with OVHcloud Object Storage or `eu01` with STACKIT Object Storage. It is only
accepted with the `sigv4` signer, and mandatory with the providers without
default region, such as `s3`. Note that a wrong region is only reported by the
storage, which rejects the signature.

### s3-role-arn

```
s3-role-arn <arn> | env:<variable>
```

Sets the ARN of the IAM role whose temporary access keys are fetched with
`token workload-identity`, such as `arn:aws:iam::123456789012:role/name`. It
may be read from the environment variable `<variable>` when the configuration
is parsed, such as `AWS_ROLE_ARN`, which IRSA sets. It is mandatory with this
token source, and not accepted with the other ones. It requires `provider s3`
first.

### s3-role-session-name

```
s3-role-session-name <name> | env:<variable>
```

Sets the name of the role sessions opened with `token workload-identity`, which
appears in the AWS CloudTrail logs, instead of the default one `haproxy`. It is
made of 2 to 64 letters, digits and `_+=,.@-` characters. It may be read from
the environment variable `<variable>` when the configuration is parsed, such as
`AWS_ROLE_SESSION_NAME`. It is not accepted with the other token sources. It
requires `provider s3` first.

### signer

```
signer <type>
```

Sets how the requests are authenticated. This keyword is mandatory. The
supported types are:

- `bearer`: the request is sent with an `Authorization: Bearer <token>` header.
    It is supported by Google Cloud Storage with an OAuth 2.0 access token, by
    Azure Blob Storage with a Microsoft Entra ID access token, or by any
    storage accepting bearer tokens. It is the only signer usable without
    `provider`.

- `sas`: the token is a shared access signature (SAS), appended to the query
    string of the request. With `provider azure`, it is the signature provided
    by Azure, for instance `sv=2022-11-02&ss=b&sp=r&se=...&sig=...`, optionally
    starting with a question mark, which must have a `sig` parameter.

- `sharedkey`: the token is a key shared with the storage, which signs the
    request. With `provider azure`, it is the key of the storage account,
    encoded in base64 as provided by Azure. The `x-ms-date` and `x-ms-version`
    headers are added, the `Date` header of the client is removed, then the
    `Authorization: SharedKey <account>:<signature>` header is added, the
    signature covering the method, the standard headers, all the headers
    starting with `x-ms-`, the ones of the client included, the path and the
    query string of the request (see `Authorize with Shared Key` in the Azure
    Storage REST API documentation). The `account` keyword is mandatory. Note
    that the account key gives access to the whole account, so a shared access
    signature or a Microsoft Entra ID token limited to the needed data should
    be preferred when possible.

- `sigv4`: the request is signed with an HMAC key, the token being
    `<access-key-id>:<secret>`, or `<access-key-id>:<secret>:<session-token>`
    for a temporary key if the provider supports it, with Signature Version 4,
    as expected by Amazon S3 and the compatible storages, and by Google Cloud
    Storage with its `GOOG4` variant (see `V4 signing process` in the Cloud
    Storage documentation). The provider sets the variant. The headers carrying
    the date and the hash of the payload are added (`x-amz-date` and
    `x-amz-content-sha256` with `provider s3`, `x-goog-date` and
    `x-goog-content-sha256` with `provider google`), the session token in its
    own header (`x-amz-security-token`), then the Authorization header,
    `<algorithm> Credential=<access-key-id>/<scope>, SignedHeaders=<headers>, Signature=<signature>`,
    the signature covering the method, the path and the query string of the
    request, which are encoded again as expected by the signature, the Host
    header and all the headers starting with `x-amz-` with `provider s3` or
    `x-goog-` with `provider google`, the added ones as well as the ones of the
    client, within the credential scope made of the day, the region (see
    `region`) and the service. The payload is not signed
    (`UNSIGNED-PAYLOAD`), since the request is signed before its payload is
    forwarded, so it should be protected by TLS. With `provider s3`, the
    chunked payloads with an unsigned trailer of the AWS SDKs
    (`Content-Encoding: aws-chunked` and
    `x-amz-content-sha256: STREAMING-UNSIGNED-PAYLOAD-TRAILER`), which carry
    a checksum of the payload in their trailer, are signed as such, with their
    `x-amz-decoded-content-length` and `x-amz-trailer` headers. The other
    chunked payloads (`x-amz-content-sha256: STREAMING-...`) are rejected with
    a 400 error, since their chunks are signed with the signature of the
    request, which HAProxy replaces. A client may then be configured to send
    the checksums in headers instead, with the
    `request_checksum_calculation = when_required` setting of the AWS SDKs.
    The access key identifier is not a secret, but the token is, like any
    other one.

### token

```
token <source>
token <access-key-id> <secret> [<session-token>]
```

Sets where the token used by the signer comes from. This keyword is mandatory.
For security reasons, the token itself is never accepted in the configuration.
`<source>` is one of:

- `env:<variable>`: the token is read from the environment variable
    `<variable>` when the configuration is parsed. The variable must be set and
    not empty. It is the usual way to receive a secret provided by an external
    secret manager (Vault, External Secrets Operator...). Note that the
    environment of a process does not change on reload, so a new token requires
    a restart, or to be injected from the CLI.

- `file:<path>`: the token is read from the file `<path>` when the
    configuration is parsed, thus before any chroot. The trailing spaces and
    line feeds are ignored. A warning is emitted if the file may be accessed by
    other users than its owner. The file is never read again, as HAProxy does
    not access the file system at runtime.

- `cli`: no token is loaded on startup. It must be injected from the CLI. Until
    then, the requests cannot be authenticated.

- `<source>`: the token is fetched by HAProxy from the token source `<source>`
    of the provider, which must be set first, then refreshed once half of its
    lifetime has elapsed, or after `fetch-refresh` if its expiration date is
    unknown. On failure, new attempts are made with an increasing delay up to
    `fetch-max-backoff`, while the current token is used until it expires. The
    first token fetched, the first failure and the first success after failures
    are logged. The requests are sent with the internal HTTP client, whose TLS
    settings, retries and connection timeout are those of the `httpclient.*`
    global keywords (see also `fetch-timeout`). The token cannot be injected
    from the CLI, but it may be fetched at once with
    `update cloudauth credential` (see `doc/management.md`). The supported
    sources are:

    - `managed-identity`: with `provider azure`, the Microsoft Entra ID token
        of the managed identity of the host, for the storage. It is fetched
        from the App Service endpoint if the `IDENTITY_ENDPOINT` and
        `IDENTITY_HEADER` environment variables are set (App Service, Azure
        Functions, Container Apps), otherwise from the Azure Instance Metadata
        Service (virtual machines, AKS nodes). See also `azure-client-id`.
        `token-endpoint` replaces the IMDS endpoint, and also takes precedence
        over the App Service one. It is only usable with the `bearer` signer.

    - `client-secret`: with `provider azure`, the Microsoft Entra ID token of
        an application (service principal), for the storage. It is requested
        from the Microsoft Entra ID token endpoint of the tenant with the
        client secret of the application (OAuth 2.0 client credentials grant).
        The `azure-tenant-id`, `azure-client-id` and `azure-client-secret`
        keywords are mandatory, see also `azure-authority-host`. It is only
        usable with the `bearer` signer.

    - `workload-identity`: the token of an identity trusting the identity of
        the workload in another identity provider (workload identity
        federation), such as a Kubernetes cluster, in exchange for the
        federated token of the workload, the `federated-token` input (see
        `input`). It is only usable with the `bearer` signer, except with
        `provider s3` which uses the `sigv4` signer.

        With `provider azure`, the Microsoft Entra ID token of an application,
        such as with AKS workload identity. It is requested from the Microsoft
        Entra ID token endpoint of the tenant with the federated token as
        client assertion. With AKS workload identity, it is the token of the
        service account in the file named by `AZURE_FEDERATED_TOKEN_FILE`,
        which kubelet renews before it expires. The `azure-tenant-id` and
        `azure-client-id` keywords are mandatory, see also
        `azure-authority-host`.

        With `provider google`, the OAuth 2.0 access token of a workload
        identity trusted by a workload identity pool of Google Cloud, such as
        the service account of a Kubernetes cluster outside of GKE. It is
        requested from the Security Token Service of Google in exchange for the
        federated token, for instance the projected service account token whose
        audience is the workload identity pool provider. The
        `google-credentials` keyword is mandatory, with an `external_account`
        credential file, whose `credential_source` is ignored since the
        federated token is the input. The service account impersonation is not
        supported, so the access to the storage must be granted to the workload
        identity itself. The endpoint is the `token_url` of the credential
        file, or `https://sts.googleapis.com/v1/token`, and `token-endpoint`
        replaces it. `token-scopes` sets the scopes of the token,
        `devstorage.read_only` under `https://www.googleapis.com/auth/` by
        default.

        With `provider s3`, the temporary access key of an IAM role trusting an
        OpenID Connect identity provider, such as with IAM roles for service
        accounts (IRSA) on EKS. It is requested from the AWS Security Token
        Service with the federated token (AssumeRoleWithWebIdentity), which is
        the only proof of identity, so the request is not signed. With IRSA, it
        is the token of the service account in the file named by
        `AWS_WEB_IDENTITY_TOKEN_FILE`, which kubelet renews before it expires.
        The `s3-role-arn` keyword is mandatory, see also
        `s3-role-session-name`. The access key is valid for one hour. The
        endpoint is the regional one of the region of the profile,
        `https://sts.<region>.amazonaws.com/`, and `token-endpoint` replaces
        it, for instance for the regions outside of the `amazonaws.com` domain,
        or for the Security Token Service of a compatible storage, with the
        same restrictions as for `container`. Its XML response is read without
        XML parser, which would be a new dependency for a single fixed
        document: the values of the access key are never decoded, so a value
        using an XML construct, such as an entity, is rejected.

    - `client-certificate`: with `provider azure`, the Microsoft Entra ID token
        of an application (service principal), for the storage. It is requested
        from the Microsoft Entra ID token endpoint of the tenant with a client
        assertion: a JWT signed with the private key of the certificate of the
        application (PS256), which designates the certificate by its SHA-256
        thumbprint (`x5t#S256`). A new assertion, valid for 10 minutes, is
        signed for each request. The `azure-tenant-id`, `azure-client-id` and
        `azure-client-certificate` keywords are mandatory, see also
        `azure-client-certificate-password` and `azure-authority-host`. It is
        only usable with the `bearer` signer.

    - `metadata-server`: with `provider google`, the OAuth 2.0 access token of
        the service account attached to the workload, fetched from the metadata
        server of Google Cloud (Compute Engine, GKE with or without Workload
        Identity, Cloud Run...) with the `Metadata-Flavor: Google` header. The
        metadata server caches the token until it is about to expire.
        `token-endpoint` replaces the default endpoint, the `default/token`
        path under `/computeMetadata/v1/instance/service-accounts/` of
        `http://169.254.169.254` (rather than `metadata.google.internal`, so
        that no resolver is needed). It may for instance designate the service
        account by its e-mail address instead of `default`. `token-scopes` sets
        the scopes of the token, which are otherwise those of the workload, but
        the metadata server of Compute Engine ignores them, unlike the ones of
        Cloud Run and App Engine. It is only usable with the `bearer` signer.

    - `service-account`: with `provider google`, the OAuth 2.0 access token of
        a service account, requested from the token endpoint of Google with an
        assertion signed with the key of the service account (RS256, OAuth 2.0
        JWT bearer grant). A new assertion, valid for one hour, is signed for
        each request. The `google-credentials` keyword is mandatory. The token
        endpoint is the `token_uri` of the credential file, or
        `https://oauth2.googleapis.com/token`, and `token-endpoint` replaces
        it. `token-scopes` sets the scopes of the token, which is otherwise
        only granted the read accesses to the storage, the scope
        `devstorage.read_only` under `https://www.googleapis.com/auth/`. It is
        only usable with the `bearer` signer.

    - `container`: with `provider s3`, the temporary access key of the IAM role
        of an Amazon ECS task, fetched from the credential endpoint of the
        task, as an AWS SDK does: `http://169.254.170.2` followed by the
        relative URI of the `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`
        environment variable, otherwise the full URI of
        `AWS_CONTAINER_CREDENTIALS_FULL_URI`, with the authorization token of
        `AWS_CONTAINER_AUTHORIZATION_TOKEN` if set, sent as is in the
        Authorization header. These variables are set by the platform and read
        when the section is parsed, and `token-endpoint` replaces the endpoint.
        An HTTP endpoint must be on the loopback or be one of the container
        credential agents of AWS (169.254.170.2, 169.254.170.23 and
        fd00:ec2::23), so that the authorization token does not cross the
        network in clear, as the AWS SDKs require, while an HTTPS endpoint may
        be anywhere. The access key is refreshed once half of its lifetime has
        elapsed, the agent providing a new one some time before the expiration.
        It is only usable with the `sigv4` signer.

    - `pod-identity`: with `provider s3`, the temporary access key of the IAM
        role associated with the service account of a pod by EKS Pod Identity,
        fetched from the EKS Pod Identity Agent with the token of the service
        account, the `authorization-token` input (see `input`), sent as is in
        the Authorization header. It is the token in the file named by
        `AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE`, which kubelet renews before
        it expires. The endpoint is the full URI of
        `AWS_CONTAINER_CREDENTIALS_FULL_URI` if set, read when the section is
        parsed, otherwise `http://169.254.170.23/v1/credentials`, and
        `token-endpoint` replaces it, with the same restrictions as for
        `container`. It is only usable with the `sigv4` signer.

    - `instance-metadata`: with `provider s3`, the temporary access key of the
        IAM role of the EC2 instance (instance profile), fetched from the
        Instance Metadata Service with IMDSv2: a session token valid for 5
        minutes is requested with a PUT request, then the name of the role and
        its credentials are requested with this token. IMDSv1 is never used.
        The endpoint is `http://169.254.169.254`, and `token-endpoint` replaces
        it, for instance with `http://[fd00:ec2::254]` over IPv6. An HTTP
        endpoint must be on the loopback or be the Instance Metadata Service
        itself, since the session token grants access to the metadata, while an
        HTTPS endpoint may be anywhere. Note that the response to the PUT
        request is limited to one hop by default, so HAProxy running in a
        container on the instance requires a higher hop limit of the metadata
        options of the instance (HttpPutResponseHopLimit). AWS provides new
        credentials at least five minutes before they expire. It is only usable
        with the `sigv4` signer.

With the `sigv4` signer, which must then be set first, the access key may also
be given in two or three parts, as the storages usually provide it: the access
key identifier, the secret and, for a temporary key, the session token, each
one read with `env:<variable>` or `file:<path>` like a token. HAProxy joins
them internally with colons into the token `<access-key-id>:<secret>` or
`<access-key-id>:<secret>:<session-token>`, which is then checked and used
exactly like a token read at once. So a part must not contain a colon, and a
token injected from the CLI to replace it must be given in the joined form. The
variables are removed from the environment like the other ones, and
`show cloudauth` reports all the parts as the source of the token. For
instance:

```
token env:AWS_ACCESS_KEY_ID env:AWS_SECRET_ACCESS_KEY env:AWS_SESSION_TOKEN
```

The token endpoints must be reachable directly by HAProxy, since the internal
HTTP client does not support the explicit HTTP proxies (no CONNECT request). A
transparent proxy inspecting TLS may be used, as long as its certificate
authority is trusted with `httpclient.ssl.ca-file`.

The token is sent in a header or in the query string, so it must only contain
visible ASCII characters, and it must suit the signer and the provider, for
instance a shared access signature with a `sig` parameter for `sas`, an account
key encoded in base64 for `sharedkey` with `provider azure`, or
`<access-key-id>:<secret>`, followed by `:<session-token>` for a temporary key,
for `sigv4`. Otherwise it is rejected, and the previous one is kept. It is
never logged nor reported. If the token is a JWT (for instance a Microsoft
Entra ID or a Kubernetes service account token) with an `exp` claim, it is not
used after this date. The signature of the token is not checked, since HAProxy
only presents it.

Since the environment variable is read when the section is parsed, it is
affected by the `setenv`, `presetenv`, `unsetenv` and `resetenv` global
keywords declared before the section. Note that setting a secret with `setenv`
or `presetenv` puts it in the configuration again, which `env:` is meant to
avoid.

The environment variables carrying secrets, those read with `env:` by `token`,
`input`, `azure-client-secret`, `azure-client-certificate`,
`azure-client-certificate-password` and `google-credentials`, and
`IDENTITY_HEADER` and `AWS_CONTAINER_AUTHORIZATION_TOKEN`, are wiped and
removed from the environment once the configuration is parsed, so that they
cannot be read anymore at runtime, for instance with the `env` sample fetch or
from Lua. In master-worker mode, the master process does not parse the
`cloudauth` sections and keeps them, so they are still available after a
reload. Thus they cannot be used anywhere else in the configuration at runtime.

Example:

```
global
    expose-experimental-directives

cloudauth storage-token
    signer bearer
    token env:STORAGE_TOKEN
```

Example with Azure Blob Storage, the container name being added to the path:

```
cloudauth azure-entra
    provider azure
    signer bearer
    token cli

cloudauth azure-managed-identity
    provider azure
    signer bearer
    token managed-identity

cloudauth azure-application
    provider azure
    signer bearer
    token client-secret
    azure-tenant-id env:AZURE_TENANT_ID
    azure-client-id env:AZURE_CLIENT_ID
    azure-client-secret env:AZURE_CLIENT_SECRET

cloudauth azure-application-certificate
    provider azure
    signer bearer
    token client-certificate
    azure-tenant-id env:AZURE_TENANT_ID
    azure-client-id env:AZURE_CLIENT_ID
    azure-client-certificate "file:${AZURE_CLIENT_CERTIFICATE_PATH}"
    azure-client-certificate-password env:AZURE_CLIENT_CERTIFICATE_PASSWORD

# AKS workload identity, the federated token being pushed from the CLI
# before it expires
cloudauth azure-workload-identity
    provider azure
    signer bearer
    token workload-identity
    input federated-token "file:${AZURE_FEDERATED_TOKEN_FILE}"
    azure-tenant-id env:AZURE_TENANT_ID
    azure-client-id env:AZURE_CLIENT_ID

cloudauth azure-sas
    provider azure
    signer sas
    token env:AZURE_STORAGE_SAS_TOKEN

cloudauth azure-key
    provider azure
    signer sharedkey
    account mystorageaccount
    token env:AZURE_STORAGE_KEY

backend azure
    mode http
    http-request normalize-uri path-strip-dotdot full
    http-request set-path /media%[path]
    filter-config cloudauth enabled profile azure-sas host mystorageaccount.blob.core.windows.net
    server blob mystorageaccount.blob.core.windows.net:443 ssl verify required ca-file @system-ca
```

Example with Google Cloud Storage, the bucket name being added to the path:

```
cloudauth gcs-metadata
    provider google
    signer bearer
    token metadata-server
    token-scopes https://www.googleapis.com/auth/devstorage.read_only

cloudauth gcs-service-account
    provider google
    signer bearer
    token service-account
    google-credentials "file:${GOOGLE_APPLICATION_CREDENTIALS}"

# workload identity federation, the federated token being pushed from the
# CLI before it expires
cloudauth gcs-workload-identity
    provider google
    signer bearer
    token workload-identity
    input federated-token "file:/var/run/secrets/tokens/gcp-token"
    google-credentials "file:${GOOGLE_APPLICATION_CREDENTIALS}"

# an HMAC key of the XML API, as "<access-key-id>:<secret>"
cloudauth gcs-hmac
    provider google
    signer sigv4
    token env:GCS_HMAC_KEY

backend gcs
    mode http
    http-request normalize-uri path-strip-dotdot full
    http-request set-path /mybucket%[path]
    filter-config cloudauth enabled profile gcs-metadata host storage.googleapis.com
    server gcs storage.googleapis.com:443 ssl verify required ca-file @system-ca
```

Example with Amazon S3, the bucket name being added to the path:

```
# an access key read in two parts, joined into the token
# "<access-key-id>:<secret>"
cloudauth s3-key
    provider s3
    signer sigv4
    region eu-west-1
    token env:AWS_ACCESS_KEY_ID env:AWS_SECRET_ACCESS_KEY

# a temporary access key injected from the CLI, as
# "<access-key-id>:<secret>:<session-token>"
cloudauth s3-temporary
    provider s3
    signer sigv4
    region eu-west-1
    token cli

# the IAM role of an Amazon ECS task
cloudauth s3-ecs-task
    provider s3
    signer sigv4
    region eu-west-1
    token container

# EKS Pod Identity, the token of the service account being pushed from the
# CLI before it expires
cloudauth s3-pod-identity
    provider s3
    signer sigv4
    region eu-west-1
    token pod-identity
    input authorization-token file:${AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE}

# the IAM role of an EC2 instance
cloudauth s3-ec2-instance
    provider s3
    signer sigv4
    region eu-west-1
    token instance-metadata

# IAM roles for service accounts (IRSA), the token of the service account
# being pushed from the CLI before it expires
cloudauth s3-workload-identity
    provider s3
    signer sigv4
    region eu-west-1
    token workload-identity
    input federated-token file:${AWS_WEB_IDENTITY_TOKEN_FILE}
    s3-role-arn env:AWS_ROLE_ARN

backend s3
    mode http
    http-request normalize-uri path-strip-dotdot full
    http-request set-path /mybucket%[path]
    filter-config cloudauth enabled profile s3-key host s3.eu-west-1.amazonaws.com
    server s3 s3.eu-west-1.amazonaws.com:443 ssl verify required ca-file @system-ca
```

Example with OVHcloud Object Storage, through its S3 compatible API, the bucket
name being part of the host name (virtual-hosted style). The region is the one
of the endpoint `s3.<region>.io.cloud.ovh.net`, in lower case, and the access
key is the S3 credential of an OVHcloud Public Cloud user:

```
cloudauth ovh-key
    provider s3
    signer sigv4
    region gra
    token env:OVH_S3_ACCESS_KEY env:OVH_S3_SECRET_KEY

backend ovh
    mode http
    http-request normalize-uri path-strip-dotdot full
    filter-config cloudauth enabled profile ovh-key host mybucket.s3.gra.io.cloud.ovh.net
    server ovh mybucket.s3.gra.io.cloud.ovh.net:443 ssl verify required ca-file @system-ca
```

Example with STACKIT Object Storage, through its S3 compatible API, the bucket
name being added to the path. The region is the one of the endpoint
`object.storage.<region>.onstackit.cloud`, and the access key is a credential
of the Object Storage of the project:

```
cloudauth stackit-key
    provider s3
    signer sigv4
    region eu01
    token env:STACKIT_S3_ACCESS_KEY env:STACKIT_S3_SECRET_KEY

backend stackit
    mode http
    http-request normalize-uri path-strip-dotdot full
    http-request set-path /mybucket%[path]
    filter-config cloudauth enabled profile stackit-key host object.storage.eu01.onstackit.cloud
    server stackit object.storage.eu01.onstackit.cloud:443 ssl verify required ca-file @system-ca
```

### token-endpoint

```
token-endpoint <url>
```

Sets the URL of the token endpoint of the token source (see `token <source>`),
instead of its default one, for instance to reach a metadata service through
another address, or a mock in a test environment. Only the token sources whose
endpoint does not depend on other settings support it, the other ones reject
it, see each token source. It requires `token <source>`.

### token-scopes

```
token-scopes <scope> [<scope> ...]
```

Sets the OAuth 2.0 scopes of the tokens requested from the token source (see
`token <source>`), instead of its default ones, for instance to only request
the permissions needed to read the storage. Each scope is made of visible ASCII
characters except the double quote and the backslash, and the scopes are at
most 1024 characters long, including the spaces between them. The token sources
which do not support them reject it, see each token source. It requires
`token <source>`.
