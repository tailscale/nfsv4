#!/usr/bin/env bash
# Run the frozen selection with a disposable fixture and an owned server.
set -euo pipefail
HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
: "${PYNFS_ROOT:?Set PYNFS_ROOT to the prepared pinned upstream checkout}"
: "${PYNFS_RESULTS:?Set PYNFS_RESULTS to a new results directory}"
PYTHON=${PYNFS_PYTHON:-python3}
export PYNFS_ROOT=$(cd "$PYNFS_ROOT" && pwd)
export PYNFS_HOST=${PYNFS_HOST:-127.0.0.1}
export PYNFS_PORT=${PYNFS_PORT:-22049}
LEASE=${PYNFS_LEASE:-90s}
MODE=${1:-original}
case "$MODE" in original|adapted|all) ;; *) echo 'Usage: pynfs-run.sh [original|adapted|all]' >&2; exit 2 ;; esac
REV=cd4701827a8261fedbfb4c6e39029fb9671321a6
[[ $(git -C "$PYNFS_ROOT" rev-parse HEAD) == "$REV" ]]
git -C "$PYNFS_ROOT" diff --exit-code
# Refuse an existing directory to preserve earlier failures and logs.
mkdir "$PYNFS_RESULTS"
export PYNFS_RESULTS=$(cd "$PYNFS_RESULTS" && pwd)
"$PYTHON" - <<'PY'
import os, socket
with socket.socket() as s:
    s.bind((os.environ['PYNFS_HOST'], int(os.environ['PYNFS_PORT'])))
PY
SERVER=${PYNFS_SERVER:-$PYNFS_RESULTS/nfs4serve}
if [[ -z ${PYNFS_SERVER:-} ]]; then
    (cd "$REPO" && go build -o "$SERVER" ./cmd/nfs4serve) >"$PYNFS_RESULTS/build.log" 2>&1
fi
mkdir -p "$PYNFS_RESULTS/fixtures/tmp" "$PYNFS_RESULTS/fixtures/tree/dir"
printf 'This is the file test data.' >"$PYNFS_RESULTS/fixtures/tree/file"
ln -s /etc/X11 "$PYNFS_RESULTS/fixtures/tree/link"
{
    git -C "$REPO" rev-parse HEAD
    git -C "$REPO" status --short
    "$PYTHON" --version
    go version
    printf 'source=working tree (not a commit snapshot)\nupstream=%s\nhost=%s\nport=%s\nlease=%s\nmode=%s\n' "$REV" "$PYNFS_HOST" "$PYNFS_PORT" "$LEASE" "$MODE"
    sha256sum "$SERVER" "$HERE/pynfs-selection.json" "$HERE/pynfs-probes.py" "$HERE/pynfs-use-options.py"
} >"$PYNFS_RESULTS/config.txt"
pid=
cleanup() {
    if [[ -n $pid ]]; then
        kill -TERM "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
"$SERVER" -listen "$PYNFS_HOST:$PYNFS_PORT" -dir "$PYNFS_RESULTS/fixtures" -lease "$LEASE" -v >"$PYNFS_RESULTS/server.log" 2>&1 &
pid=$!
printf '%s\n' "$pid" >"$PYNFS_RESULTS/server.pid"
"$PYTHON" - "$pid" <<'PY'
import os, socket, sys, time
for _ in range(100):
    os.kill(int(sys.argv[1]), 0)
    try:
        with socket.create_connection((os.environ['PYNFS_HOST'], int(os.environ['PYNFS_PORT'])), .2):
            break
    except OSError:
        time.sleep(.05)
else:
    raise SystemExit('Server did not start')
PY
codes() {
    "$PYTHON" - "$HERE/pynfs-selection.json" "$1" <<'PY'
import json, sys
print(' '.join(json.load(open(sys.argv[1]))[sys.argv[2]]))
PY
}
cd "$PYNFS_ROOT/nfs4.1"
invoke() {
    local name=$1; shift
    local status=0
    "$@" >"$PYNFS_RESULTS/$name.log" 2>&1 || status=$?
    printf '%s exit=%s\n' "$name" "$status" | tee -a "$PYNFS_RESULTS/exits.txt"
}
for minor in 1 2; do
    if [[ $MODE != adapted ]]; then
        read -ra independent <<<"$(codes filesystem_independent)"
        name=strict-independent-v4.$minor
        invoke "$name" "$PYTHON" testserver.py "$PYNFS_HOST:$PYNFS_PORT/" --noinit --nocleanup --minorversion="$minor" --security=sys --force -v --jsonout="$PYNFS_RESULTS/$name.json" "${independent[@]}"
        read -ra fixtures <<<"$(codes readonly_fixture_selection)"
        for security in sys none; do
            name=readonly-$security-v4.$minor
            invoke "$name" "$PYTHON" "$HERE/pynfs-use-options.py" "$PYNFS_HOST:$PYNFS_PORT/" --noinit --nocleanup --minorversion="$minor" --security="$security" --usefile=/tree/file --usedir=/tree/dir --uselink=/tree/link --force -v --jsonout="$PYNFS_RESULTS/$name.json" "${fixtures[@]}"
        done
        name=lease-v4.$minor
        invoke "$name" "$PYTHON" testserver.py "$PYNFS_HOST:$PYNFS_PORT/" --noinit --nocleanup --minorversion="$minor" --security=sys --force -v --jsonout="$PYNFS_RESULTS/$name.json" EID9
    fi
    if [[ $MODE != original ]]; then
        for security in sys none; do
            name=adapted-$security-v4.$minor
            invoke "$name" "$PYTHON" "$HERE/pynfs-probes.py" --minorversion="$minor" --security="$security" --output="$PYNFS_RESULTS/$name.json"
        done
    fi
done
# Upstream can exit zero when tests fail. Inspect JSON and exact selected IDs.
"$PYTHON" - "$HERE/pynfs-selection.json" "$MODE" <<'PY'
import json, os, pathlib, sys
manifest = json.load(open(sys.argv[1]))
root = pathlib.Path(os.environ['PYNFS_RESULTS'])
summary = {}
bad = False
for minor in (1, 2):
    names = {}
    if sys.argv[2] != 'adapted':
        names[f'strict-independent-v4.{minor}'] = manifest['filesystem_independent']
        names[f'lease-v4.{minor}'] = manifest['slow_filesystem_independent']
        for security in ('sys', 'none'):
            names[f'readonly-{security}-v4.{minor}'] = manifest['readonly_fixture_selection']
    if sys.argv[2] != 'original':
        for security in ('sys', 'none'):
            names[f'adapted-{security}-v4.{minor}'] = None
    for name, selected in names.items():
        try:
            data = json.load(open(root / (name + '.json')))
            cases = [t for t in data['testcase'] if not t.get('skipped')]
            passed = [t['code'] for t in cases if t.get('result') == 'PASS' or ('result' not in t and 'failure' not in t and 'error' not in t)]
            failed = [t['code'] for t in cases if t['code'] not in passed]
            missing = sorted(set(selected or []) - {t['code'] for t in cases})
            unexpected = sorted({t['code'] for t in cases} - set(selected)) if selected else []
            summary[name] = dict(executed=len(cases), passed=passed, failed=failed, missing=missing, unexpected=unexpected)
            bad |= bool(failed or missing or unexpected)
        except Exception as exc:
            summary[name] = dict(error=str(exc))
            bad = True
json.dump(summary, open(root / 'summary.json', 'w'), indent=2)
for name, row in summary.items():
    print(name, row.get('executed'), 'failed=', row.get('failed'), 'missing=', row.get('missing'), row.get('error', ''))
sys.exit(1 if bad else 0)
PY
