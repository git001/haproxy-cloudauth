#!/bin/sh
#
# Builds HAProxy with the cloudauth and the OpenTelemetry filters against the
# libraries of PREFIX (see build-deps.sh), and vtest for the tests. HAProxy is
# built in SRCDIR/haproxy, vtest is installed in /usr/local/bin.
#
# Environment:
#   PREFIX          directory of the libraries   (/opt/haproxy-cloudauth)
#   JOBS            number of compiler jobs       (4)
#   SRCDIR          directory of the sources      (/usr/src)
#   CLOUDAUTH_DIR   sources of the cloudauth filter (SRCDIR/haproxy-cloudauth)
#   HAPROXY_REPO, HAPROXY_REF                     HAProxy repository and ref
#   OTEL_FILTER_REPO, OTEL_FILTER_REF             OpenTelemetry filter
#
# The build options are the ones of the HAProxy images, with the AWS-LC of
# PREFIX, which supports QUIC.

set -eu

PREFIX="${PREFIX:-/opt/haproxy-cloudauth}"
JOBS="${JOBS:-4}"
SRCDIR="${SRCDIR:-/usr/src}"
CLOUDAUTH_DIR="${CLOUDAUTH_DIR:-${SRCDIR}/haproxy-cloudauth}"
HAPROXY_REPO="${HAPROXY_REPO:-https://github.com/haproxy/haproxy.git}"
HAPROXY_REF="${HAPROXY_REF:-master}"
OTEL_FILTER_REPO="${OTEL_FILTER_REPO:-https://github.com/haproxytech/haproxy-opentelemetry.git}"
OTEL_FILTER_REF="${OTEL_FILTER_REF:-main}"

libdir="${PREFIX}/lib"
sources="${PREFIX}/share/haproxy-cloudauth/sources"

# Clones <repo> at <ref> into <dir> and records it as <name>
clone() {
	git clone --depth 1 --branch "$3" "$2" "$4"
	echo "$1 $2 $3 $(git -C "$4" rev-parse HEAD)" >> "${sources}"
}

cd "${SRCDIR}"
clone haproxy "${HAPROXY_REPO}" "${HAPROXY_REF}" haproxy
clone haproxy-opentelemetry "${OTEL_FILTER_REPO}" "${OTEL_FILTER_REF}" haproxy-opentelemetry

# vtest is only used by the tests, it is not recorded
(cd haproxy && CPUS="${JOBS}" DESTDIR=/usr/local/bin TMPDIR="$(mktemp -d)" \
	sh scripts/build-vtest.sh)

# The objects of the filter are built in its own tree, which must not carry
# the ones of a build of the host.
rm -f "${CLOUDAUTH_DIR}"/src/*.o

# pkg-config is run by $(shell), which only sees the variables of the command
# line with make 4.4 or later, so PKG_CONFIG_PATH is exported.
export PKG_CONFIG_PATH="${libdir}/pkgconfig"
cd haproxy
make -j"${JOBS}" TARGET=linux-glibc \
	USE_PCRE2=1 USE_PCRE2_JIT=1 USE_TFO=1 USE_LINUX_TPROXY=1 \
	USE_GETADDRINFO=1 USE_LUA=1 USE_PROMEX=1 USE_SLZ=1 \
	USE_OPENSSL_AWSLC=1 SSL_INC="${PREFIX}/include" SSL_LIB="${libdir}" \
	USE_QUIC=1 \
	ADDLIB="-Wl,-rpath,${libdir}" \
	EXTRA_MAKE="${CLOUDAUTH_DIR} ${SRCDIR}/haproxy-opentelemetry" \
	all
./haproxy -vv
