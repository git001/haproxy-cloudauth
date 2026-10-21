#!/bin/sh
# Creates the system user of the service, which is kept on removal, as the
# files it may own.
set -e

if ! getent group haproxy-cloudauth >/dev/null; then
	groupadd --system haproxy-cloudauth
fi
if ! getent passwd haproxy-cloudauth >/dev/null; then
	useradd --system --gid haproxy-cloudauth --no-create-home \
		--home-dir /var/lib/haproxy-cloudauth --shell /usr/sbin/nologin \
		--comment "HAProxy with the cloudauth filter" haproxy-cloudauth
fi
