#!/bin/sh
# Verifies `smcroutectl -j` emits valid JSON for every show subcommand,
# and that the documented fields are present.
#set -x

# shellcheck source=/dev/null
. "$(dirname "$0")/lib.sh"

check_dep python3

CTL="../src/smcroutectl -u /tmp/$NM/sock"

# Validate JSON parses, optionally apply a path check via python (read
# from $PYEXPR to avoid the shell mangling embedded quotes).
check_json()
{
	label=$1
	output=$2
	PYEXPR=$3
	export PYEXPR

	echo "--- $label ---"
	echo "$output"
	echo "$output" | python3 -c 'import json, sys; json.loads(sys.stdin.read())' \
		|| FAIL "$label: output is not valid JSON"
	if [ -n "$PYEXPR" ]; then
		echo "$output" | python3 -c '
import json, os, sys
d = json.loads(sys.stdin.read())
assert eval(os.environ["PYEXPR"]), "predicate failed"' \
			|| FAIL "$label: $PYEXPR"
	fi
}

print "Creating world ..."
ip link add a1 type dummy; ip link set a1 multicast on; ip link set a1 up
ip addr add 10.0.0.1/24 dev a1
ip link add a2 type dummy; ip link set a2 multicast on; ip link set a2 up
ip addr add 20.0.0.1/24 dev a2

print "Creating config ..."
cat <<EOF > "/tmp/$NM/conf"
phyint a1 enable
phyint a2 enable

mgroup from a1 group 225.1.1.1
mroute from a1 group 225.3.3.3 to a2
mroute from a1 source 10.0.0.5 group 225.4.4.4 to a2
mroute from wg0 group 239.5.5.5 to a2
EOF
cat "/tmp/$NM/conf"

print "Starting smcrouted ..."
../src/smcrouted -f "/tmp/$NM/conf" -n -P "/tmp/$NM/pid" -u "/tmp/$NM/sock" &
sleep 1

print "Validating JSON output for each show subcommand ..."

check_json "show interfaces" \
	"$($CTL -j show interfaces)" \
	"any(i['name'] == 'a1' and i['vif'] == 0 for i in d['interfaces'])"

check_json "show groups" \
	"$($CTL -j show groups)" \
	"any(g['group'] == '225.1.1.1' and g['iif'] == 'a1' for g in d['groups']['conf'])"

check_json "show routes" \
	"$($CTL -j show routes)" \
	"any(r['group'] == '225.3.3.3' and r['iif'] == 'a1' and r['oifs'] == ['a2'] for r in d['routes']['asm']) \
	 and any(r['group'] == '225.4.4.4' and r['source'] == '10.0.0.5' for r in d['routes']['ssm'])"

check_json "show pending" \
	"$($CTL -j show pending)" \
	"any(p['iif'] == 'wg0' and p['group'] == '239.5.5.5' and p['oifs'] == ['a2'] for p in d['pending'])"

check_json "show (default = routes)" \
	"$($CTL -j show)" \
	"'routes' in d and 'asm' in d['routes'] and 'ssm' in d['routes'] and 'kernel' in d['routes']"

OK
