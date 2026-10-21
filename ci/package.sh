#!/bin/sh
#
# Builds the haproxy-cloudauth package of the distribution it runs on, RPM or
# DEB, from the build of build-deps.sh and build-haproxy.sh, with nfpm. The
# package is written in OUTDIR.
#
# Environment:
#   PREFIX        directory of the libraries   (/opt/haproxy-cloudauth)
#   SRCDIR        directory of the sources      (/usr/src)
#   OUTDIR        directory of the package      (/out)
#   PKG_VERSION   version of the package        (0.0.0~dev)
#   PKG_RELEASE   release of the package        (1)
#   CLOUDAUTH_COMMIT  commit of the filter, for the SBOM
#
# The CycloneDX SBOM of the package (ci/sbom.py) and its checksum are written
# next to it.
#
# The package is installed next to the HAProxy of the distribution:
#
#   /usr/sbin/haproxy-cloudauth                     HAProxy
#   PREFIX/lib                                      the shipped libraries
#   /etc/haproxy-cloudauth/                         the configuration
#   /etc/default/haproxy-cloudauth (DEB)            the environment of the
#   /etc/sysconfig/haproxy-cloudauth (RPM)          service, for the secrets
#   /usr/lib/systemd/system/haproxy-cloudauth.service
#   /usr/share/doc/haproxy-cloudauth/               the documentation
#   /usr/share/haproxy-cloudauth/sbom/              the SBOM and the sources

set -eu

PREFIX="${PREFIX:-/opt/haproxy-cloudauth}"
SRCDIR="${SRCDIR:-/usr/src}"
OUTDIR="${OUTDIR:-/out}"
PKG_VERSION="${PKG_VERSION:-0.0.0~dev}"
PKG_RELEASE="${PKG_RELEASE:-1}"

NFPM_VERSION=2.48.0
NFPM_SHA256=6d7f9a28b2f397934403950fcbba83f598b08d02edbe79a0815b3b4897341750

. /etc/os-release

cloudauth="${SRCDIR}/haproxy-cloudauth"
libdir="${PREFIX}/lib"

# The format, the release suffix and the runtime dependencies of the
# distribution. The system libraries are the ones HAProxy and the shipped
# libraries are linked with, checked by the installation tests.
case "${ID}" in
rhel | almalinux | rocky | centos | ol)
	format=rpm
	dist="el${VERSION_ID%%.*}"
	release="${PKG_RELEASE}.${dist}"
	envfile=etc/sysconfig/haproxy-cloudauth
	depends="glibc libstdc++ lua-libs pcre2 zlib ca-certificates shadow-utils"
	;;
debian | ubuntu)
	format=deb
	case "${ID}" in
	debian) dist="deb${VERSION_ID}" ;;
	ubuntu) dist="ubuntu${VERSION_ID}" ;;
	esac
	release="${PKG_RELEASE}~${dist}"
	envfile=etc/default/haproxy-cloudauth
	depends="libc6 libstdc++6 liblua5.4-0 libpcre2-8-0 zlib1g ca-certificates passwd"
	;;
*)
	echo "unsupported distribution: ${ID} ${VERSION_ID}" >&2
	exit 1
	;;
esac

# nfpm, checked against the checksum of its release
tools="$(mktemp -d)"
wget -q -O "${tools}/nfpm.tar.gz" \
	"https://github.com/goreleaser/nfpm/releases/download/v${NFPM_VERSION}/nfpm_${NFPM_VERSION}_Linux_x86_64.tar.gz"
echo "${NFPM_SHA256}  ${tools}/nfpm.tar.gz" | sha256sum -c -
tar -xzf "${tools}/nfpm.tar.gz" -C "${tools}" nfpm

# The tree of the package. Only the shared libraries of PREFIX are shipped.
stage="$(mktemp -d)"
install -D -m 755 "${SRCDIR}/haproxy/haproxy" "${stage}/usr/sbin/haproxy-cloudauth"
mkdir -p "${stage}${libdir}"
cp -a "${libdir}"/*.so* "${stage}${libdir}/"
strip --strip-unneeded "${stage}/usr/sbin/haproxy-cloudauth"
find "${stage}${libdir}" -type f -name '*.so*' -exec strip --strip-unneeded {} +

# The shipped binaries only look for libraries in the shipped directory
find "${stage}" -type f \( -name '*.so*' -o -path '*/sbin/*' \) | while read -r f; do
	readelf -d "${f}" | sed -n 's/.*(\(RUNPATH\|RPATH\)).*\[\(.*\)\]/\2/p' | tr ':' '\n' |
	while read -r p; do
		case "${p}" in
		"${libdir}" | '$ORIGIN') ;;
		*) echo "unexpected run path ${p} in ${f}" >&2; exit 1 ;;
		esac
	done
done

install -D -m 644 "${cloudauth}/packaging/haproxy-cloudauth.cfg" \
	"${stage}/etc/haproxy-cloudauth/haproxy-cloudauth.cfg"
mkdir -p "${stage}/etc/haproxy-cloudauth/conf.d"
cat > "${tools}/envfile" <<EOF
# Environment of the haproxy-cloudauth service, for the secrets referenced
# with "env:" in the configuration, such as:
#
# AWS_ACCESS_KEY_ID=...
# AWS_SECRET_ACCESS_KEY=...
#
# Additional options of HAProxy:
#
# EXTRAOPTS="-S /run/haproxy-cloudauth/master.sock"
EOF
install -D -m 600 "${tools}/envfile" "${stage}/${envfile}"
install -D -m 644 "${cloudauth}/packaging/haproxy-cloudauth.service" \
	"${stage}/usr/lib/systemd/system/haproxy-cloudauth.service"

mkdir -p "${stage}/usr/share/haproxy-cloudauth/errors"
cp "${SRCDIR}"/haproxy/examples/errorfiles/*.http "${stage}/usr/share/haproxy-cloudauth/errors/"

doc="${stage}/usr/share/doc/haproxy-cloudauth"
mkdir -p "${doc}"
cp "${cloudauth}/README.md" "${cloudauth}/doc/configuration.md" "${doc}/"
cp "${cloudauth}/LICENSE" "${doc}/copyright"

# The SBOM and the list of the sources, shipped in the package and next to it.
# The scanners read the SBOM from the images where the package is installed,
# as the bundled libraries are not known to the package managers. It is not
# in the documentation, which slim images do not install.
sbom="${stage}/usr/share/haproxy-cloudauth/sbom"
mkdir -p "${sbom}"
cp "${PREFIX}/share/haproxy-cloudauth/sources" "${sbom}/"
python3 "${cloudauth}/ci/sbom.py" "${PREFIX}" "${stage}/usr/sbin/haproxy-cloudauth" \
	"${stage}${libdir}" "${PKG_VERSION}-${release}" "${sbom}/haproxy-cloudauth.cdx.json"
mkdir -p "${OUTDIR}"
cp "${sbom}/haproxy-cloudauth.cdx.json" "${OUTDIR}/haproxy-cloudauth-${dist}.cdx.json"

# The configuration of nfpm, the contents being listed from the tree
conf="${tools}/nfpm.yaml"
{
	cat <<EOF
name: haproxy-cloudauth
arch: amd64
platform: linux
version: "${PKG_VERSION}"
version_schema: none
release: "${release}"
section: net
priority: optional
maintainer: Aleksandar Lazic <al-haproxy@none.at>
vendor: haproxy-cloudauth
homepage: https://github.com/git001/haproxy-cloudauth
license: GPL-2.0-or-later
description: |
  HAProxy with the cloudauth filter
  HAProxy built with the cloudauth filter, which authenticates the requests
  sent to cloud object storages (Azure Blob Storage, Google Cloud Storage,
  Amazon S3 and S3 compatible storages), and with the OpenTelemetry filter.
  It is installed next to the HAProxy of the distribution, and ships its own
  AWS-LC, curl and OpenTelemetry libraries.
depends:
EOF
	for d in ${depends}; do
		echo "  - ${d}"
	done
	cat <<EOF
scripts:
  preinstall: ${cloudauth}/packaging/scripts/preinstall.sh
  postinstall: ${cloudauth}/packaging/scripts/postinstall.sh
  preremove: ${cloudauth}/packaging/scripts/preremove.sh
  postremove: ${cloudauth}/packaging/scripts/postremove.sh
contents:
EOF
	(cd "${stage}" && find . ! -type d | sort) | while read -r f; do
		f="${f#.}"
		if [ -L "${stage}${f}" ]; then
			echo "  - src: $(readlink "${stage}${f}")"
			echo "    dst: ${f}"
			echo "    type: symlink"
			continue
		fi
		case "${f}" in
		/etc/*) type="config|noreplace" ;;
		*)      type="" ;;
		esac
		echo "  - src: ${stage}${f}"
		echo "    dst: ${f}"
		[ -z "${type}" ] || echo "    type: ${type}"
		echo "    file_info:"
		echo "      mode: 0$(stat -c %a "${stage}${f}")"
	done
	echo "  - dst: /etc/haproxy-cloudauth/conf.d"
	echo "    type: dir"
	echo "    file_info:"
	echo "      mode: 0755"
} > "${conf}"

mkdir -p "${OUTDIR}"
"${tools}/nfpm" package --config "${conf}" --packager "${format}" --target "${OUTDIR}"
# The checksum of the package, which the image copies before installing it
(cd "${OUTDIR}" && sha256sum haproxy-cloudauth[-_]*."${format}") > "${OUTDIR}/haproxy-cloudauth-${dist}.sha256"
ls -l "${OUTDIR}"
rm -rf "${stage}" "${tools}"
