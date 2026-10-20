# Builds HAProxy with the cloudauth filter and the OpenTelemetry filter, runs
# the tests of the cloudauth filter, and provides a runtime image. It follows
# the layout of the HAProxy images (haproxytech/haproxy-docker-alpine), on
# Debian since the OpenTelemetry C wrapper only supports glibc distributions.
#
#   podman build -t haproxy-cloudauth .                  # runtime image
#   podman build --target test .                         # build and test only
#   podman build --build-arg HAPROXY_REF=v3.4.0 ...      # another HAProxy
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
#             wrapper into /opt. This is by far the longest stage, which only
#             depends on AWSLC_REF and OTELC_REF, so it should be cached.
#   build   : HAProxy with both filters, and vtest.
#   test    : the regression and unit tests of the cloudauth filter.
#   runtime : HAProxy and the shared libraries of /opt only.
#
# AWS-LC is the version of the HAProxy images, instead of the FIPS one of the
# bundle of the wrapper. curl, the SDK and HAProxy are all built with it, so
# that the process only loads one SSL library. HAProxy supports QUIC with it.

ARG DEBIAN_VERSION=trixie

FROM docker.io/library/debian:${DEBIAN_VERSION} AS deps

ARG OTELC_REPO=https://github.com/haproxytech/opentelemetry-c-wrapper.git
ARG OTELC_REF=v3.4.0
ARG AWSLC_REPO=https://github.com/aws/aws-lc.git
ARG AWSLC_REF=v4.0.0
ARG JOBS=4

# The packages of scripts/build/linux-update.sh of the wrapper, debhelper
# providing the package generator the build of the SDK requires, without
# libssl-dev and libcurl4-gnutls-dev since both libraries are built in /opt,
# plus the ones of HAProxy and vtest.
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        autoconf autoconf-archive automake binutils ca-certificates cmake \
        debhelper g++ gawk gcc git libc6-dev libgpg-error-dev libjemalloc-dev \
        libkeyutils-dev liblua5.4-dev liblzma-dev libpcre2-dev libsystemd-dev \
        libtool make ninja-build patch perl pkgconf python3 wget zlib1g-dev \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src
RUN git clone --depth 1 --branch "${AWSLC_REF}" "${AWSLC_REPO}" aws-lc \
 && cmake -S aws-lc -B aws-lc/build -G Ninja \
        -DCMAKE_INSTALL_PREFIX=/opt -DCMAKE_INSTALL_LIBDIR=lib \
        -DCMAKE_INSTALL_RPATH=/opt/lib -DCMAKE_BUILD_TYPE=Release \
        -DBUILD_SHARED_LIBS=ON -DBUILD_TESTING=OFF -DDISABLE_GO=ON \
 && cmake --build aws-lc/build -j "${JOBS}" \
 && cmake --install aws-lc/build \
 && rm -rf aws-lc

RUN git clone --depth 1 --branch "${OTELC_REF}" "${OTELC_REPO}" opentelemetry-c-wrapper

# The scripts expect to run from their directory, which holds the patches of
# the SDK. They run one compiler job per CPU of /proc/cpuinfo, which is
# replaced by JOBS. The bundle does not build its own AWS-LC, curl and the SDK
# find the one of /opt.
RUN cd opentelemetry-c-wrapper/scripts/build \
 && sed -i 's|^\([[:space:]]*local _var_cpu=\).*|\1"'"${JOBS}"'"|' common.sh \
 && grep -q "local _var_cpu=\"${JOBS}\"" common.sh \
 && sed -i 's|^"${SH_DIR}/aws-lc-|#&|' build-bundle.sh \
 && ! grep -q '^"${SH_DIR}/aws-lc-' build-bundle.sh \
 && ./build-bundle.sh /opt / dynamic \
 && cd .. && git clean -dffxq .

RUN cd opentelemetry-c-wrapper \
 && ./scripts/bootstrap \
 && ./configure --prefix=/opt --with-opentelemetry=/opt \
 && make -j"${JOBS}" \
 && make install \
 && git clean -dffxq


FROM deps AS build

ARG HAPROXY_REPO=https://github.com/haproxy/haproxy.git
ARG HAPROXY_REF=master
ARG OTEL_FILTER_REPO=https://github.com/haproxytech/haproxy-opentelemetry.git
ARG OTEL_FILTER_REF=main
ARG JOBS=4

WORKDIR /usr/src
RUN git clone --depth 1 --branch "${HAPROXY_REF}" "${HAPROXY_REPO}" haproxy \
 && git clone --depth 1 --branch "${OTEL_FILTER_REF}" "${OTEL_FILTER_REPO}" haproxy-opentelemetry \
 && cd haproxy && CPUS="${JOBS}" DESTDIR=/usr/local/bin TMPDIR=/tmp/vtest sh scripts/build-vtest.sh \
 && rm -rf /tmp/vtest

COPY . /usr/src/haproxy-cloudauth

# The build options of the HAProxy images, with the AWS-LC of /opt. The
# objects of the filter are built in its own tree, which must not carry the
# ones of a build of the host.
RUN cd haproxy-cloudauth && rm -f src/*.o \
 && cd ../haproxy \
 && make -j"${JOBS}" TARGET=linux-glibc \
        USE_PCRE2=1 USE_PCRE2_JIT=1 USE_TFO=1 USE_LINUX_TPROXY=1 \
        USE_GETADDRINFO=1 USE_LUA=1 LUA_INC=/usr/include/lua5.4 \
        USE_PROMEX=1 USE_SLZ=1 \
        USE_OPENSSL_AWSLC=1 SSL_INC=/opt/include SSL_LIB=/opt/lib USE_QUIC=1 \
        ADDLIB="-ljemalloc -Wl,-rpath,/opt/lib" \
        PKG_CONFIG_PATH=/opt/lib/pkgconfig \
        EXTRA_MAKE="/usr/src/haproxy-cloudauth /usr/src/haproxy-opentelemetry" \
        all \
 && ./haproxy -vv


FROM build AS test

ARG JOBS=4

RUN cd haproxy-cloudauth \
 && HAPROXY_DIR=/usr/src/haproxy VTEST_PROGRAM=/usr/local/bin/vtest test/run.sh --j "${JOBS}"


FROM docker.io/library/debian:${DEBIAN_VERSION}-slim AS runtime

LABEL org.opencontainers.image.title="HAProxy with the cloudauth filter"
LABEL org.opencontainers.image.source="https://github.com/git001/haproxy-cloudauth"

ENV HAPROXY_UID=haproxy
ENV HAPROXY_GID=haproxy

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        ca-certificates libjemalloc2 liblua5.4-0 libpcre2-8-0 zlib1g \
 && rm -rf /var/lib/apt/lists/*

# Only the shared libraries of /opt are needed. Some of them record a run path
# through /opt/lib/pkgconfig, which is removed, so /opt/lib is added to the
# paths of the dynamic linker, as the HAProxy images do. AWS-LC uses the CA
# certificates of Debian (/etc/ssl/certs) for "ca-file @system-ca".
COPY --from=build /opt/lib/ /opt/lib/
COPY --from=build /usr/src/haproxy/haproxy /usr/local/sbin/haproxy
COPY --from=build /usr/src/haproxy/examples/errorfiles/ /usr/local/etc/haproxy/errors

RUN find /opt/lib -mindepth 1 -maxdepth 1 ! -name '*.so*' -exec rm -rf {} + \
 && echo /opt/lib > /etc/ld.so.conf.d/opt.conf \
 && ldconfig \
 && groupadd --system "$HAPROXY_GID" \
 && useradd --system --gid "$HAPROXY_GID" --no-create-home --shell /usr/sbin/nologin "$HAPROXY_UID" \
 && ln -s /usr/local/sbin/haproxy /usr/sbin/haproxy \
 && mkdir -p /var/lib/haproxy \
 && chown "$HAPROXY_UID:$HAPROXY_GID" /var/lib/haproxy \
 && ln -s /usr/local/etc/haproxy /etc/haproxy \
 && haproxy -vv

STOPSIGNAL SIGUSR1

CMD ["haproxy", "-W", "-db", "-f", "/usr/local/etc/haproxy/haproxy.cfg"]
