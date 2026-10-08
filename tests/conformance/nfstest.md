# NFSTest read-only kernel checks

Pinned upstream: `git://git.linux-nfs.org/projects/mora/nfstest.git`, revision
`94089545caa18bbe4be1b055125d0721fe8dee80` (NFStest 3.2). See the
[upstream documentation](https://www.linux-nfs.org/~mora/nfstest/index.html).

`nfstest_readonly.py` uses upstream TestUtil with new read-only scenarios.
These are adaptations, not passes of the stock cache, delegation, or POSIX
suites, whose setup requires writes. Mutations use memfs with SetServer and
recall before mutation; immutable data is never changed.

## Setup and adapted scenarios

Requirements: Linux with an NFS client, Go, Python with venv support, curl,
tcpdump, mount/umount, and permission to run the mount/capture commands via
passwordless `sudo -n`. Use a dedicated test machine. Port 23049 must be
free. Run commands from the nfsv4 repository root:

```sh
WORK=$(mktemp -d)
export NFSTEST_ROOT="$WORK/nfstest"
git clone git://git.linux-nfs.org/projects/mora/nfstest.git "$NFSTEST_ROOT"
git -C "$NFSTEST_ROOT" checkout --detach 94089545caa18bbe4be1b055125d0721fe8dee80
python3 -m venv "$WORK/venv"
export PYTHONPATH="$NFSTEST_ROOT"

for vers in 4.1 4.2; do
    export NFSTEST_RESULTS="$WORK/results-$vers"
    mkdir "$NFSTEST_RESULTS"
    go build -o "$NFSTEST_RESULTS/nfstestserve" ./tests/conformance/cmd/nfstestserve
    "$WORK/venv/bin/python" tests/conformance/nfstest_readonly.py \
      --server 127.0.0.1 --nomount --nocleanup --nfsversion "$vers" --tverbose normal
    # Inspect failures even if the runner exits nonzero; continue to the next version.
done
```

Upstream supports source execution through PYTHONPATH; a package install is
not required. `NFSTEST_RESULTS` is required and must contain the built
`nfstestserve` binary. Keep output outside the repository and use a separate
directory for each run: the runner overwrites its logs and capture.

Despite the framework's `--nomount` option, this adaptation owns its mount:
it starts/reaps its server and capture, mounts `ro,actimeo=1,port=23049`,
then unmounts. Control uses a Unix socket in the output directory. The
scenario names are `read`, `traverse`, `cache`, `recall`, `dir_recall`,
`live`, and `restart`; use `--runtest` for a subset.

The recorded all-scenarios runs passed 75/77 assertions per minor version.
An existing fd briefly read old data after recall, and a deleted name
briefly remained lookup-visible despite a fresh listing. Delayed checks
passed. These observations are not established server RFC violations, and
the failed assertions are retained. See the
[report](../../doc/conformance-testing.md) for interpretation.

## Compatible unmodified workloads

For a stock read-only workload, start the harness with explicit socket and
listen options, mount it read-only, and seed the expected namespace through
the control socket rather than an NFS write. For example, with a built
harness and a fresh output directory:

```sh
# Start the harness in a separate terminal with the same NFSTEST_RESULTS value.
# It stops on SIGTERM or Ctrl-C.
"$NFSTEST_RESULTS/nfstestserve" -control "$NFSTEST_RESULTS/control.sock"

# Prepare a disposable fixture and mountpoint.
mkdir -p "$NFSTEST_RESULTS/mnt"
dd if=/dev/zero of="$NFSTEST_RESULTS/seed" bs=1M count=1
curl --fail --unix-socket "$NFSTEST_RESULTS/control.sock" \
  --data-binary "@$NFSTEST_RESULTS/seed" \
  'http://localhost/write?path=live/stock/f00000001'
sudo -n mount -t nfs4 -o vers=4.1,port=23049,ro \
  127.0.0.1:/ "$NFSTEST_RESULTS/mnt"

"$WORK/venv/bin/python" "$NFSTEST_ROOT/test/nfstest_io" \
  -d "$NFSTEST_RESULTS/mnt/live/stock" -s 20261007 -n 1 -r 3 -v info \
  --read 100 --write 0 --rdwr 0 --create 0 --minfiles 0 \
  --rename 0 --remove 0 --trunc 0 --ftrunc 0 --link 0 --slink 0 \
  --readdir 0 --lock 0 --lockfull 0 --tlock 0 --unlock 0 \
  --rsize 64k --rsizedev 0
sudo -n umount "$NFSTEST_RESULTS/mnt"
```

Repeat with `--direct` for direct reads, or set `--readdir 100` for directory
operations. All mutation probabilities and forced creation must remain zero.
The workload does not compare read bytes; adapted `read` checks do.

`nfstest_xid --error --unpack-error True CAPTURE.pcap` checks captured
operation lists. Supply a trace from tcpdump or an adapted run and inspect
its output: it can report mismatches without a failing exit status. Neither
these workloads nor that packet check establishes full-suite conformance.
