#!/bin/sh
#
# Installs the packages needed to build HAProxy with the cloudauth and the
# OpenTelemetry filters, the dependencies of the OpenTelemetry C wrapper and
# vtest, on the supported distributions:
#
#   RHEL 8, 9 and 10 (or AlmaLinux, Rocky Linux), Debian 12 and 13,
#   Ubuntu 22.04, 24.04 and 26.04
#
# The packages are the ones of scripts/build/linux-update.sh of the wrapper,
# without the SSL and curl development packages, since both libraries are
# built, plus the ones of HAProxy (PCRE2, Lua, zlib) and of the packaging.

set -eu

. /etc/os-release

case "${ID}" in
debian | ubuntu)
	export DEBIAN_FRONTEND=noninteractive
	apt-get update
	apt-get install -y --no-install-recommends \
		autoconf autoconf-archive automake binutils ca-certificates cmake \
		debhelper file g++ gawk gcc git libc6-dev libgpg-error-dev \
		libkeyutils-dev liblua5.4-dev liblzma-dev libpcre2-dev libtool make \
		patch perl pkgconf python3 wget zlib1g-dev
	rm -rf /var/lib/apt/lists/*
	;;

rhel | almalinux | rocky | centos | ol)
	# Lua and autoconf-archive come from the CodeReady Builder repository
	# (PowerTools on version 8). The OpenTelemetry C++ SDK needs a more
	# recent compiler than the one of version 8, which the wrapper takes
	# from gcc-toolset-10.
	dnf install -y dnf-plugins-core
	case "${VERSION_ID%%.*}" in
	8)
		dnf config-manager --set-enabled powertools
		extra="gcc-toolset-10"
		;;
	*)
		dnf config-manager --set-enabled crb
		extra=""
		;;
	esac
	dnf install -y \
		autoconf autoconf-archive automake binutils ca-certificates cmake \
		diffutils file findutils gawk gcc gcc-c++ git glibc-devel \
		keyutils-libs-devel libgpg-error-devel libtool lua-devel make patch \
		pcre2-devel perl pkgconf-pkg-config python3 rpm-build wget xz-devel \
		zlib-devel ${extra}
	dnf clean all
	;;

*)
	echo "unsupported distribution: ${ID} ${VERSION_ID}" >&2
	exit 1
	;;
esac
