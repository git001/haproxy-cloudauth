# Builds HAProxy with the cloudauth filter and the OpenTelemetry filter, runs
# the tests of the cloudauth filter, and provides a runtime image. It follows
# the layout of the HAProxy images (haproxytech/haproxy-docker-alpine), on
# Debian since the OpenTelemetry C wrapper only supports glibc distributions.
#
#   podman build -t haproxy-cloudauth .                  # runtime image
#   podman build --target test .                         # build and test only
#   podman build --build-arg HAPROXY_REF=v3.4.0 ...      # another HAProxy
#
# The build and test stages also run on the other supported distributions
# (see ci/install-builddeps.sh), the runtime image only on Debian:
#
#   podman build --target test --build-arg BASE_IMAGE=almalinux:8 .
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
#   runtime : HAProxy and the shared libraries of PREFIX only.
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


FROM ${RUNTIME_IMAGE} AS runtime

ARG PREFIX=/opt/haproxy-cloudauth

LABEL org.opencontainers.image.title="HAProxy with the cloudauth filter"
LABEL org.opencontainers.image.source="https://github.com/git001/haproxy-cloudauth"

ENV HAPROXY_UID=haproxy
ENV HAPROXY_GID=haproxy

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        ca-certificates liblua5.4-0 libpcre2-8-0 zlib1g \
 && rm -rf /var/lib/apt/lists/*

# Only the shared libraries of PREFIX are needed. AWS-LC uses the CA
# certificates of Debian (/etc/ssl/certs) for "ca-file @system-ca".
COPY --from=build ${PREFIX}/lib/ ${PREFIX}/lib/
COPY --from=build /usr/src/haproxy/haproxy /usr/local/sbin/haproxy
COPY --from=build /usr/src/haproxy/examples/errorfiles/ /usr/local/etc/haproxy/errors
COPY --chmod=755 docker-entrypoint.sh /

RUN find "${PREFIX}/lib" -mindepth 1 -maxdepth 1 ! -name '*.so*' -exec rm -rf {} + \
 && groupadd --system "$HAPROXY_GID" \
 && useradd --system --gid "$HAPROXY_GID" --no-create-home --shell /usr/sbin/nologin "$HAPROXY_UID" \
 && ln -s /usr/local/sbin/haproxy /usr/sbin/haproxy \
 && mkdir -p /var/lib/haproxy \
 && chown "$HAPROXY_UID:$HAPROXY_GID" /var/lib/haproxy \
 && ln -s /usr/local/etc/haproxy /etc/haproxy \
 && haproxy -vv

STOPSIGNAL SIGUSR1

# The entrypoint adds "-W -db" to the haproxy command, and runs haproxy as well
# when the arguments are only options (e.g. "-vv").
ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["haproxy", "-f", "/usr/local/etc/haproxy/haproxy.cfg"]
