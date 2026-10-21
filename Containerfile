# Builds HAProxy with the cloudauth filter and the OpenTelemetry filter, runs
# the tests of the cloudauth filter, and provides a runtime image. It follows
# the layout of the HAProxy images (haproxytech/haproxy-docker-alpine), on
# Debian since the OpenTelemetry C wrapper only supports glibc distributions.
#
#   podman build -t haproxy-cloudauth .                  # runtime image
#   podman build --target test .                         # build and test only
#   podman build --build-arg HAPROXY_REF=v3.4.0 ...      # another HAProxy
#
# The build, test and package stages also run on the other supported
# distributions (see ci/install-builddeps.sh), the runtime image only on Debian:
#
#   podman build --target test --build-arg BASE_IMAGE=almalinux:8 .
#   podman build --target packages --build-arg BASE_IMAGE=almalinux:8 \
#       --output type=local,dest=dist .
#
# The C++ SDK needs 1 to 2 GB of memory per compiler job, so the number of
# jobs is limited by JOBS (4 by default), whatever the number of CPUs. The
# memory of the build may be limited too, so that a lack of memory only stops
# the build, instead of the processes of the host:
#
#   podman build --build-arg JOBS=8 --memory 16g ...
#
# The stages:
#
#   deps    : AWS-LC, then the OpenTelemetry C wrapper and its dependencies
#             (curl, the OpenTelemetry C++ SDK), built with the scripts of the
#             wrapper into PREFIX (ci/build-deps.sh). This is by far the
#             longest stage, which only depends on the distribution and on the
#             ci/ scripts it runs, so it should be cached.
#   build   : HAProxy with both filters, and vtest (ci/build-haproxy.sh).
#   test    : the regression and unit tests of the cloudauth filter.
#   package : the RPM or DEB package of the distribution (ci/package.sh), and
#             its SBOM, exported by the "packages" stage.
#   runtime : the image, which installs the Debian package.
#   runtime-debug : the same image, with bash and curl.
#
# AWS-LC is the version of the HAProxy images, instead of the FIPS one of the
# bundle of the wrapper. curl, the SDK and HAProxy are all built with it, so
# that the process only loads one SSL library. HAProxy supports QUIC with it.

ARG BASE_IMAGE=docker.io/library/debian:trixie
ARG RUNTIME_IMAGE=docker.io/library/debian:trixie-slim

FROM ${BASE_IMAGE} AS deps

ARG PREFIX=/opt/haproxy-cloudauth
ARG AWSLC_REF=v4.0.0
ARG OTELC_REF=v3.4.0
ARG JOBS=4

COPY ci/install-builddeps.sh ci/build-deps.sh /usr/src/ci/
RUN sh /usr/src/ci/install-builddeps.sh
RUN PREFIX="${PREFIX}" JOBS="${JOBS}" AWSLC_REF="${AWSLC_REF}" OTELC_REF="${OTELC_REF}" \
    sh /usr/src/ci/build-deps.sh


FROM deps AS build

ARG PREFIX=/opt/haproxy-cloudauth
ARG HAPROXY_REF=master
ARG OTEL_FILTER_REF=main
ARG JOBS=4

COPY . /usr/src/haproxy-cloudauth
RUN PREFIX="${PREFIX}" JOBS="${JOBS}" HAPROXY_REF="${HAPROXY_REF}" OTEL_FILTER_REF="${OTEL_FILTER_REF}" \
    sh /usr/src/haproxy-cloudauth/ci/build-haproxy.sh


FROM build AS test

ARG JOBS=4

RUN cd /usr/src/haproxy-cloudauth \
 && HAPROXY_DIR=/usr/src/haproxy VTEST_PROGRAM=/usr/local/bin/vtest test/run.sh --j "${JOBS}"


FROM build AS package

ARG PREFIX=/opt/haproxy-cloudauth
ARG PKG_VERSION=0.0.0~dev
ARG PKG_RELEASE=1
ARG CLOUDAUTH_COMMIT=
ARG SOURCE_DATE_EPOCH

RUN PREFIX="${PREFIX}" OUTDIR=/out PKG_VERSION="${PKG_VERSION}" PKG_RELEASE="${PKG_RELEASE}" \
    CLOUDAUTH_COMMIT="${CLOUDAUTH_COMMIT}" SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH}" \
    sh /usr/src/haproxy-cloudauth/ci/package.sh


# The package and its SBOM only, for "--output type=local,dest=<dir>"
FROM scratch AS packages
COPY --from=package /out/ /


# The image installs the Debian package. It runs on Kubernetes and OpenShift
# with their default security settings: as a non-root user (any user of the
# group 0 on OpenShift), without capabilities, with a read-only root file
# system, so it only listens on unprivileged ports (8080 in the default
# configuration).
FROM ${RUNTIME_IMAGE} AS runtime

LABEL org.opencontainers.image.title="HAProxy with the cloudauth filter"
LABEL org.opencontainers.image.description="HAProxy with the cloudauth and the OpenTelemetry filters"
LABEL org.opencontainers.image.source="https://github.com/git001/haproxy-cloudauth"
LABEL org.opencontainers.image.licenses="GPL-2.0-or-later AND LGPL-2.1-or-later"

# The package is mounted, which some builders (buildah) do not take into
# account to reuse a cached layer, so its checksum is copied first, and
# checked. The user is created before the package, which keeps it, so that its
# id is fixed. Its primary group is the group 0, like the arbitrary users of
# OpenShift.
COPY --from=package /out/haproxy-cloudauth-deb*.sha256 /usr/share/haproxy-cloudauth/package.sha256
RUN --mount=type=bind,from=package,source=/out,target=/tmp/out \
    (cd /tmp/out && sha256sum -c /usr/share/haproxy-cloudauth/package.sha256) \
 && useradd --system --uid 1001 --gid 0 --no-create-home \
        --home-dir /var/lib/haproxy --shell /usr/sbin/nologin haproxy-cloudauth \
 && apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        /tmp/out/haproxy-cloudauth_*.deb \
 && rm -rf /var/lib/apt/lists/* \
 && ln -s /usr/sbin/haproxy-cloudauth /usr/local/sbin/haproxy \
 && mkdir -p /usr/local/etc/haproxy /var/lib/haproxy \
 && cp /etc/haproxy-cloudauth/haproxy-cloudauth.cfg /usr/local/etc/haproxy/haproxy.cfg \
 && ln -s /usr/share/haproxy-cloudauth/errors /usr/local/etc/haproxy/errors \
 && ln -s /usr/local/etc/haproxy /etc/haproxy \
 && chgrp 0 /var/lib/haproxy \
 && chmod 0770 /var/lib/haproxy \
 && haproxy -vv \
 && haproxy -c -f /usr/local/etc/haproxy/haproxy.cfg

COPY --chmod=755 docker-entrypoint.sh /

USER 1001
WORKDIR /var/lib/haproxy
EXPOSE 8080

STOPSIGNAL SIGUSR1

# The entrypoint adds "-W -db" to the haproxy command, and runs haproxy as well
# when the arguments are only options (e.g. "-vv").
ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["haproxy", "-f", "/usr/local/etc/haproxy/haproxy.cfg"]


# The same image with bash and curl, to debug from inside the pod. curl must
# support telnet, to test plain TCP services.
FROM runtime AS runtime-debug

USER root
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends bash curl \
 && rm -rf /var/lib/apt/lists/* \
 && curl -V \
 && curl -V | grep '^Protocols:' | grep -qw telnet
USER 1001
