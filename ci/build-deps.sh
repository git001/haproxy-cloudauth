#!/bin/sh
#
# Builds the libraries shipped with HAProxy into PREFIX: AWS-LC, then the
# OpenTelemetry C wrapper and its dependencies (curl, the OpenTelemetry C++
# SDK and the libraries the SDK builds itself), with the scripts of the
# wrapper. All of them use AWS-LC, so that the process only loads one SSL
# library.
#
# Environment:
#   PREFIX      installation directory      (/opt/haproxy-cloudauth)
#   JOBS        number of compiler jobs     (4)
#   AWSLC_REPO, AWSLC_REF                   AWS-LC repository and tag
#   OTELC_REPO, OTELC_REF                   wrapper repository and tag
#   CURL_VERSION, GRPC_VERSION              versions replacing the ones of the
#                                           wrapper, with security fixes
#
# The C++ SDK needs 1 to 2 GB of memory per compiler job, so JOBS is used
# whatever the number of CPUs. The repositories and commits of the sources are
# recorded in PREFIX/share/haproxy-cloudauth/sources, and the versions of the
# libraries built by the SDK in third_party_release next to it, for the SBOM.

set -eu

PREFIX="${PREFIX:-/opt/haproxy-cloudauth}"
JOBS="${JOBS:-4}"
AWSLC_REPO="${AWSLC_REPO:-https://github.com/aws/aws-lc.git}"
AWSLC_REF="${AWSLC_REF:-v5.11.0}"
OTELC_REPO="${OTELC_REPO:-https://github.com/haproxytech/opentelemetry-c-wrapper.git}"
OTELC_REF="${OTELC_REF:-v3.4.0}"
CURL_VERSION="${CURL_VERSION:-8.22.0}"
GRPC_VERSION="${GRPC_VERSION:-1.82.2}"

# The libraries are installed into PREFIX/lib on all the distributions
libdir="${PREFIX}/lib"

src="$(mktemp -d)"
sources="${PREFIX}/share/haproxy-cloudauth/sources"
mkdir -p "$(dirname "${sources}")"
: > "${sources}"

# Clones <repo> at <ref> into <dir> and records it as <name>
clone() {
	git clone --depth 1 --branch "$3" "$2" "$4"
	echo "$1 $2 $3 $(git -C "$4" rev-parse HEAD)" >> "${sources}"
}

clone aws-lc "${AWSLC_REPO}" "${AWSLC_REF}" "${src}/aws-lc"
cmake -S "${src}/aws-lc" -B "${src}/aws-lc/build" \
	-DCMAKE_INSTALL_PREFIX="${PREFIX}" -DCMAKE_INSTALL_LIBDIR="${libdir##*/}" \
	-DCMAKE_INSTALL_RPATH="${libdir}" -DCMAKE_BUILD_TYPE=Release \
	-DBUILD_SHARED_LIBS=ON -DBUILD_TESTING=OFF -DDISABLE_GO=ON
cmake --build "${src}/aws-lc/build" -j "${JOBS}"
cmake --install "${src}/aws-lc/build"

clone opentelemetry-c-wrapper "${OTELC_REPO}" "${OTELC_REF}" "${src}/otelc"

# The scripts expect to run from their directory, which holds the patches of
# the SDK. They run one compiler job per CPU, which is replaced by JOBS. The
# bundle does not build its own AWS-LC: curl and the SDK find the one of
# PREFIX. On the RHEL family, they install into lib64 and then move the
# libraries of the SDK there, which fails, so lib is used there too.
cd "${src}/otelc/scripts/build"
sed -i 's|^\([[:space:]]*local _var_cpu=\).*|\1"'"${JOBS}"'"|' common.sh
grep -q "local _var_cpu=\"${JOBS}\"" common.sh
sed -i 's|^"${SH_DIR}/aws-lc-|#&|' build-bundle.sh
sed -i 's|^\([[:space:]]*SH_LIBDIR_EXT=\)"64"|\1""|' common.sh
! grep -q 'SH_LIBDIR_EXT="64"' common.sh
! grep -q '^"${SH_DIR}/aws-lc-' build-bundle.sh

# The wrapper pins curl 8.21.0 and the SDK gRPC 1.82.1, which have known
# vulnerabilities. curl is built by an install script named after its version,
# gRPC is fetched by the SDK with the tag of its third_party_release file,
# which is changed by a patch of the SDK, applied by the wrapper like its own.
curl_tag="curl-$(echo "${CURL_VERSION}" | tr . _)"
curl_old="$(ls curl-curl-*-install.sh)"
curl_new="curl-${curl_tag}-install.sh"
if [ "${curl_old}" != "${curl_new}" ]; then
	sed "s|/curl-[0-9_]*\.tar\.gz\"|/${curl_tag}.tar.gz\"|" "${curl_old}" > "${curl_new}"
	grep -q "/tags/${curl_tag}.tar.gz\"" "${curl_new}"
	chmod 755 "${curl_new}"
	sed -i "s|/${curl_old}\"|/${curl_new}\"|" build-bundle.sh
	grep -q "^\"\${SH_DIR}/${curl_new}\"" build-bundle.sh
fi
sdk="$(ls opentelemetry-cpp-*-install.sh)"
sdk="${sdk%-install.sh}"
cat > "0099-${sdk}.patch" <<EOF
--- a/third_party_release
+++ b/third_party_release
@@ -18,4 +18,4 @@
-curl=curl-8_21_0
+curl=${curl_tag}
 protobuf=v35.1
-grpc=v1.82.1
+grpc=v${GRPC_VERSION}
 benchmark=v1.9.4
EOF
./build-bundle.sh "${PREFIX}" / dynamic

# The versions of the libraries the SDK builds itself, for the SBOM
cp opentelemetry-cpp-*/third_party_release "$(dirname "${sources}")/"

# The versions actually built
grep -q "^grpc=v${GRPC_VERSION}\$" "$(dirname "${sources}")/third_party_release"
grep -q "set(PACKAGE_VERSION \"${GRPC_VERSION}\")" "${libdir}"/cmake/grpc/gRPCConfigVersion.cmake
grep -q "set(PACKAGE_VERSION \"${CURL_VERSION}" "${libdir}"/cmake/CURL/CURLConfigVersion.cmake

# The pkg-config files of the SDK locate PREFIX from their own directory,
# which the libraries linked with them, such as the wrapper, keep in their run
# path. The pkgconfig directory is not shipped, so PREFIX is set instead.
sed -i 's|^prefix=${pcfiledir}/../..$|prefix='"${PREFIX}"'|' "${libdir}"/pkgconfig/*.pc
! grep -l 'pcfiledir' "${libdir}"/pkgconfig/*.pc

# The wrapper is built with the compiler of the SDK on RHEL 8
if [ -x /opt/rh/gcc-toolset-10/root/bin/g++ ]; then
	export CC=/opt/rh/gcc-toolset-10/root/bin/gcc
	export CXX=/opt/rh/gcc-toolset-10/root/bin/g++
fi
cd "${src}/otelc"
# The includes and the action on failure of AC_COMPUTE_INT are swapped, which
# autoconf 2.69 (RHEL 8) turns into a syntax error.
perl -0pi -e 's|\[\],(\s*)\[#include <opentelemetry/version\.h>\]|[#include <opentelemetry/version.h>],$1\[\]|' \
	m4/am-with-opentelemetry.m4
grep -q '^[[:space:]]*\[#include <opentelemetry/version.h>\],$' m4/am-with-opentelemetry.m4
./scripts/bootstrap
./configure --prefix="${PREFIX}" --libdir="${libdir}" \
	--with-opentelemetry="${PREFIX}"
make -j"${JOBS}"
make install

cd /
rm -rf "${src}"
