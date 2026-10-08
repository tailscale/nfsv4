# pynfs read-only protocol checks

Pinned tool: [linux-nfs/pynfs](https://github.com/linux-nfs/pynfs), revision
`cd4701827a8261fedbfb4c6e39029fb9671321a6`. It is GPL-licensed and is an
external testing tool, not a library dependency.

The [selection manifest](pynfs-selection.json) lists 66 independent cases,
33 fixture cases, and EID9 lease cleanup, plus exclusions and dependencies.
Both minor versions are selected explicitly; pynfs otherwise defaults to
minor version 2. All runs use `--noinit --nocleanup`. Do not use writable
initialization, `--maketree`, or an unreviewed `all` selection against a
read-only server.

## Prepare the tool

Use Python 3.12 or another version supported by the pinned upstream. Follow
its README for build dependencies. Debian/Ubuntu packages include
`libkrb5-dev`, `python3-dev`, `swig`, `python3-gssapi`, `python3-ply`, and
`python3-setuptools`. GSS bindings are an import dependency; these checks do
not use Kerberos. Newer Python versions may also need upstream's documented
xdrlib replacement.

Run these commands from the nfsv4 repository root:

```sh
WORK=$(mktemp -d)
export PYNFS_ROOT="$WORK/pynfs"
export PYNFS_PYTHON=python3
git clone https://github.com/linux-nfs/pynfs.git "$PYNFS_ROOT"
git -C "$PYNFS_ROOT" checkout --detach cd4701827a8261fedbfb4c6e39029fb9671321a6
(cd "$PYNFS_ROOT" && "$PYNFS_PYTHON" setup.py build)

export PYNFS_RESULTS="$WORK/upstream-results"
bash tests/conformance/pynfs-run.sh original
# The retained COMP3 expectation mismatch can make this exit nonzero.
export PYNFS_RESULTS="$WORK/adapted-results"
bash tests/conformance/pynfs-run.sh adapted
```

Each output directory must be new. The runner builds the current checkout,
creates fixtures without NFS writes, starts its server, and reaps only that
child on exit. It refuses an occupied address. Logs, JSON, and configuration
are written to the selected output directory, not committed test results.

`PYNFS_SERVER` can select an existing server binary. `PYNFS_HOST` (default
`127.0.0.1`), `PYNFS_PORT` (22049), `PYNFS_PYTHON` (python3), and
`PYNFS_LEASE` (90s) are configurable. Use a loopback address. EID9 waits for
lease expiry, so the upstream run takes several minutes; a shorter lease
is a separate test configuration, not evidence for the default lease.

## Interpretation

The original mode runs exactly the manifest IDs under AUTH_SYS in v4.1,
then v4.2; fixtures also run under AUTH_NONE. `--force` prevents implicit
dependency expansion. CSESS6 depends on CSESS9, so a forced result after
that dependency fails is not an independent defect. The wrapper checks
executed IDs and failures because upstream can exit zero with failed cases.

`pynfs-use-options.py` fixes only the pinned CLI's Python-3 indexing of
`--use*` path options. It does not change test functions or assertions.
The symlink target `/etc/X11` is fixture text; these checks do not follow it.

The adapted mode uses the upstream codec but is not an upstream-suite pass:

- Existing-file OPEN/SECINFO and rejected WRITE replace writable setup.
- `READ-BADSTATE` expects OK to record the documented macOS restart
  workaround. This is not strict stateid-validation conformance.
- Response-size probes separate unusable-channel negotiation from RPC
  header accounting. Replay probes require successful SEQUENCE metadata
  and RETRY_UNCACHED_REP on the following operation.

The pinned COMP3 list includes valid UTF-8 for noncharacter U+FFFE and
incorrectly expects INVAL. RFC 3629 permits the encoding, and RFC 8881's
`nfs4_cs_prep` profile does not prohibit stringprep C.4. Do not reject valid
noncharacters or remove the case just to make the result green.

Other failures also need RFC review: CSESS25 tests SHOULD-level guidance;
CSESS28 assumes a minimum request-size rule not established by its cited
text; CSESS15's unknown-flag expectation has a less direct normative basis.
Read-only setup errors are not evidence that writes should be implemented.
See the [report](../../doc/conformance-testing.md) for recorded counts and
identified defects. Rerun against the server revision under review rather
than treating historical counts as expected results for every checkout.
