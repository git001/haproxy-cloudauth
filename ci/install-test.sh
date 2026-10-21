#!/bin/sh
#
# Installs the haproxy-cloudauth package of DIR on the distribution it runs on,
# a container of the target distribution, with the dependencies of its
# repositories, checks the installation, reinstalls and removes it.
#
#   install-test.sh DIR

set -eu

dir="$1"

. /etc/os-release

case "${ID}" in
debian | ubuntu)
	export DEBIAN_FRONTEND=noninteractive
	apt-get update
	install() { apt-get install -y --no-install-recommends "$@"; }
	reinstall() { apt-get install -y --reinstall "$@"; }
	remove() { apt-get purge -y haproxy-cloudauth; }
	pkg="$(ls "${dir}"/haproxy-cloudauth_*.deb)"
	envfile=/etc/default/haproxy-cloudauth
	;;
*)
	install() { dnf install -y "$@"; }
	reinstall() { dnf reinstall -y "$@"; }
	remove() { dnf remove -y haproxy-cloudauth; }
	pkg="$(ls "${dir}"/haproxy-cloudauth-*.rpm)"
	envfile=/etc/sysconfig/haproxy-cloudauth
	;;
esac

echo "=== install ${pkg}"
install "${pkg}"

echo "=== check"
haproxy-cloudauth -vv
haproxy-cloudauth -vv | grep -q "Built with the cloudauth provider"
haproxy-cloudauth -vv | grep -q "+QUIC"

# all the libraries are found, the SSL library is the shipped one
for f in /usr/sbin/haproxy-cloudauth /opt/haproxy-cloudauth/lib/*.so*; do
	if ldd "${f}" | grep "not found"; then
		echo "missing library for ${f}" >&2
		exit 1
	fi
done
ldd /usr/sbin/haproxy-cloudauth | grep -q "libssl.so => /opt/haproxy-cloudauth/"

haproxy-cloudauth -c -f /etc/haproxy-cloudauth/haproxy-cloudauth.cfg -f /etc/haproxy-cloudauth/conf.d

getent passwd haproxy-cloudauth
[ "$(stat -c %a "${envfile}")" = 600 ]
test -s /usr/share/haproxy-cloudauth/sbom/haproxy-cloudauth.cdx.json
test -f /usr/lib/systemd/system/haproxy-cloudauth.service

echo "=== reinstall"
echo "# local change" >> /etc/haproxy-cloudauth/haproxy-cloudauth.cfg
reinstall "${pkg}"
grep -q "# local change" /etc/haproxy-cloudauth/haproxy-cloudauth.cfg

echo "=== remove"
remove
! command -v haproxy-cloudauth
! ls /opt/haproxy-cloudauth/lib/*.so* 2>/dev/null
echo "=== ok"
