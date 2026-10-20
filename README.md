## HAProxy cloud storage authentication filter (cloudauth)

The cloudauth filter lets HAProxy authenticate the requests it sends to cloud
object storages: Azure Blob Storage, Google Cloud Storage and S3 compatible
storages. The clients need no credential, and cannot use their own ones. The
credentials are given by the administrator (environment, file read at parse
time, CLI) or fetched by HAProxy itself from the usual sources of each cloud
(managed identities, workload identities, instance metadata, STS...),
refreshed in the background and never logged.

The filter is built as an addon of HAProxy, without any change to HAProxy
itself.

**Status: experimental.** The configuration must enable
`expose-experimental-directives`, and the syntax may still change.

### Requirements

- HAProxy 3.5 or newer, whose filter API allows an addon to register its
  filter class (`filter_register_class()`), built with an OpenSSL compatible
  library (`USE_OPENSSL=1`).
- No other library.

### Building

The filter is built with the HAProxy sources, by listing the directory of this
repository in the `EXTRA_MAKE` variable of the HAProxy Makefile:

```
cd /path/to/haproxy
make -j$(nproc) TARGET=linux-glibc USE_OPENSSL=1 EXTRA_MAKE=/path/to/haproxy-cloudauth
./haproxy -vv | grep cloudauth
```

All the storage providers are built by default. Each one may be left out by
setting its variable to 0: `CLOUDAUTH_AZURE=0`, `CLOUDAUTH_GOOGLE=0` or
`CLOUDAUTH_S3=0`.

The objects of the filter are built in its own `src/` directory. When it is
built with several HAProxy source trees or with other build options, run
`make clean` in the HAProxy tree before, which also removes them.

### Example

```
global
    expose-experimental-directives

# a credential profile: here, the access key of an S3 user, read from the
# environment when the configuration is parsed
cloudauth s3-key
    provider s3
    signer sigv4
    region eu-west-1
    token env:AWS_ACCESS_KEY_ID env:AWS_SECRET_ACCESS_KEY

frontend www
    mode http
    bind :8080
    default_backend s3

backend s3
    mode http
    http-request deny unless METH_GET or METH_HEAD
    http-request normalize-uri path-strip-dotdot full
    http-request set-path /mybucket%[path]
    filter-config cloudauth enabled profile s3-key host s3.eu-west-1.amazonaws.com
    server s3 s3.eu-west-1.amazonaws.com:443 ssl verify required ca-file @system-ca
```

### Documentation

- [doc/configuration.md](doc/configuration.md): the filter, the credential
  profiles and their token sources, for each provider.
- [doc/management.md](doc/management.md): the CLI commands, to inspect the
  profiles and to inject the credentials.
- [doc/internals-api.md](doc/internals-api.md): the internal API, for the
  developers of the providers.

They are written in Markdown. `make pdf` turns them into PDF documents in
`build/`, when [pandoc](https://pandoc.org/) and [typst](https://typst.app/)
are installed, otherwise it is skipped. Their paths may be set with `PANDOC`
and `TYPST`:

```
make pdf PANDOC=/path/to/pandoc TYPST=/path/to/typst
```

### Tests

The regression tests use [VTest](https://github.com/vtest/VTest2) and the
`scripts/run-regtests.sh` script of the HAProxy source tree the filter was
built in. The unit tests are run too when HAProxy was built with
`DEBUG="-DDEBUG_UNIT"`:

```
HAPROXY_DIR=/path/to/haproxy VTEST_PROGRAM=/path/to/vtest test/run.sh
```

### Container image

The `Containerfile` builds HAProxy with the filter and with the
[OpenTelemetry filter](https://github.com/haproxytech/haproxy-opentelemetry),
runs the tests, and provides a runtime image based on Debian. It follows the
layout of the HAProxy images: AWS-LC as SSL library, QUIC, the Prometheus
exporter and Lua. The first build takes long, since it builds the OpenTelemetry
C++ SDK, whose compiler jobs need a lot of memory, so their number is limited
by `JOBS` (4 by default):

```
podman build --build-arg JOBS=6 --memory 14g -t haproxy-cloudauth .
podman build --target test .
```

The HAProxy and OpenTelemetry filter versions are set with the `HAPROXY_REF`
and `OTEL_FILTER_REF` build arguments, see the `Containerfile` for the others.

### License

The license model of HAProxy applies: GPL-2.0-or-later for the files in
`src/`, LGPL-2.1-or-later for the files in `include/`, see [LICENSE](LICENSE).
