#!/bin/sh
#
# Runs the regression tests of the cloudauth filter, and its unit tests when
# HAProxy was built with them (DEBUG="-DDEBUG_UNIT"), with an HAProxy built
# with the filter :
#
#   HAPROXY_DIR=/path/to/haproxy test/run.sh [<run-regtests.sh options>] [<test>...]
#
# HAPROXY_DIR is the HAProxy source tree the filter was built in, which also
# provides scripts/run-regtests.sh. The HAProxy binary defaults to the one of
# this tree and may be set with HAPROXY_PROGRAM. VTEST_PROGRAM points to vtest,
# as for the regression tests of HAProxy. Without any test, all the tests of
# this directory are run.

set -e

dir=$(cd "$(dirname "$0")" && pwd)

if [ -z "$HAPROXY_DIR" ]; then
	echo "HAPROXY_DIR must be set to the HAProxy source tree the filter was built in." >&2
	exit 1
fi

HAPROXY_PROGRAM=${HAPROXY_PROGRAM:-$HAPROXY_DIR/haproxy}
export HAPROXY_PROGRAM

has_test=0
for arg in "$@"; do
	case "$arg" in
		*.vtc|*/) has_test=1 ;;
	esac
done
if [ "$has_test" = 0 ]; then
	set -- "$@" "$dir"
fi

"$HAPROXY_DIR/scripts/run-regtests.sh" "$@"

if sh "$dir/unit/cloudauth.sh" check; then
	sh "$dir/unit/cloudauth.sh" run
	echo "Unit tests passed."
fi
