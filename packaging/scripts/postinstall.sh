#!/bin/sh
# The service is neither enabled nor started: the configuration must be
# adapted first. It is restarted on an upgrade if it was running.
set -e

if [ -d /run/systemd/system ]; then
	systemctl daemon-reload >/dev/null 2>&1 || :
	# rpm: $1 >= 2 on an upgrade, deb: "configure" with the old version
	if [ "${1:-}" = "configure" ] && [ -n "${2:-}" ] || [ "${1:-0}" -ge 2 ] 2>/dev/null; then
		systemctl try-restart haproxy-cloudauth.service >/dev/null 2>&1 || :
	fi
fi
