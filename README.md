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
  library (`USE_OPENSSL=1`). The development versions need commit 23591a429
  ("MINOR: filters: Set the class flags on filter class registration") or a
  later one, which added the flags argument of `filter_register_class()`.
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

### Packages and container images

The releases provide, for amd64:

- RPM packages for RHEL 8, 9 and 10 (and the compatible distributions), and
  DEB packages for Debian 12 and 13 and Ubuntu 22.04, 24.04 and 26.04;
- the container image `ghcr.io/git001/haproxy-cloudauth`, based on Debian,
  and the same image with bash and curl, tagged with `-debug`, to debug from
  inside a pod;
- the PDF manuals.

HAProxy is built with the filter and with the
[OpenTelemetry filter](https://github.com/haproxytech/haproxy-opentelemetry),
like the HAProxy images: AWS-LC as SSL library, QUIC, the Prometheus exporter
and Lua. The packages ship their own AWS-LC, curl and OpenTelemetry libraries
in `/opt/haproxy-cloudauth/lib`, and are installed next to the HAProxy of the
distribution:

```
dnf install ./haproxy-cloudauth-<version>-1.el9.x86_64.rpm
apt install ./haproxy-cloudauth_<version>-1~deb13_amd64.deb
```

HAProxy is then `/usr/sbin/haproxy-cloudauth`, its configuration
`/etc/haproxy-cloudauth/haproxy-cloudauth.cfg`, and the service
`haproxy-cloudauth.service`, which runs as an unprivileged user and is neither
enabled nor started on installation. The secrets referenced with `env:` are
set in `/etc/sysconfig/haproxy-cloudauth` (RPM) or
`/etc/default/haproxy-cloudauth` (DEB).

The image is used like the official HAProxy images: it runs HAProxy in
master-worker mode with `/usr/local/etc/haproxy/haproxy.cfg`, and the arguments
which are only options are passed to HAProxy:

```
podman run --rm -v ./haproxy.cfg:/usr/local/etc/haproxy/haproxy.cfg:ro \
    -e CLOUDAUTH_TOKEN ghcr.io/git001/haproxy-cloudauth
podman run --rm ghcr.io/git001/haproxy-cloudauth -vv
podman run --rm -v ./haproxy.cfg:/tmp/haproxy.cfg:ro \
    ghcr.io/git001/haproxy-cloudauth -c -f /tmp/haproxy.cfg
```

It runs with the default security settings of Kubernetes and OpenShift: as
the user 1001 (or any user of the group 0 on OpenShift), without capabilities,
with a read-only root file system. So HAProxy only listens on unprivileged
ports, 8080 in the default configuration, which answers on `/healthz`.

Each package and image comes with its SBOM, a build provenance attestation,
and signatures, see [SECURITY.md](SECURITY.md) and the release notes to verify
them.

#### Building

The `Containerfile` builds and tests HAProxy, the packages and the images,
on all the supported distributions. The first build takes long, since it
builds the OpenTelemetry C++ SDK, whose compiler jobs need a lot of memory, so
their number is limited by `JOBS` (4 by default):

```
podman build --build-arg JOBS=6 --memory 14g -t haproxy-cloudauth .
podman build --target test --build-arg BASE_IMAGE=almalinux:9 .
podman build --target packages --build-arg BASE_IMAGE=almalinux:9 \
    --output type=local,dest=dist .
```

The HAProxy and OpenTelemetry filter versions are set with the `HAPROXY_REF`
and `OTEL_FILTER_REF` build arguments, see the `Containerfile` and the
scripts of `ci/` for the others. The GitHub workflows of `.github/workflows`
build, test and scan everything on each change and every week, and publish
the releases.

### License

The license model of HAProxy applies: GPL-2.0-or-later for the files in
`src/`, LGPL-2.1-or-later for the files in `include/`, see [LICENSE](LICENSE).
