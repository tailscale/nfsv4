# Read-only NFS conformance testing

This report records pynfs and NFSTest testing performed on 2026-10-07. It
covers NFSv4.1/v4.2 reads and state management, not writes, NFSv4.0,
Kerberos, ACLs, extended attributes, or pNFS. It is conformance sampling,
not a certification of complete RFC compliance.

## Environment and method

- Baseline revision: `1a7ea68506c450781e53b0b3b03ec00b78eca352`.
- Linux `7.0.0-1012-aws`, Go `1.27.1`, Python `3.12.3`, nfs-utils `2.6.4`.
- [pynfs](https://github.com/linux-nfs/pynfs) revision
  `cd4701827a8261fedbfb4c6e39029fb9671321a6`.
- [NFSTest](https://www.linux-nfs.org/~mora/nfstest/index.html) revision
  `94089545caa18bbe4be1b055125d0721fe8dee80` (NFStest 3.2).

Existing Go tests use a minimal protocol client and Linux/macOS kernel
clients. The independent tools complement those tests with different
request encoders, negative cases, and packet-level checks. No new macOS
run or sustained fuzzing was performed.

The pinned selections and reproducible runners are in
[`tests/conformance/`](../tests/conformance/README.md). Upstream test
assertions were not changed. Tests that require writable setup were
excluded or replaced with explicitly labeled adaptations. Generated logs,
per-case results, and captures are not checked into the repository.

## pynfs

The selection contains 100 unique upstream IDs: 66 filesystem-independent
cases, 33 fixture cases, and EID9 lease cleanup. Each runs with AUTH_SYS
under both minor versions; fixture cases also run with AUTH_NONE. Fixtures
are created before serving, not through NFS. Initialization and cleanup
are disabled with `--noinit --nocleanup`; `--maketree` is not used.

Recorded results per minor version, before and after applying the fixes:

| Selection | Before: pass / fail | After: pass / fail |
| --- | ---: | ---: |
| Independent, SYS | 55 / 11 | 66 / 0 |
| Fixtures, SYS | 27 / 6 | 32 / 1 |
| Fixtures, NONE | 27 / 6 | 32 / 1 |
| Lease cleanup EID9, SYS | 1 / 0 | 1 / 0 |

The remaining `COMP3` failure is a tool expectation mismatch. It treats
U+FFFE as malformed UTF-8 and requires INVAL. RFC 3629 permits that
encoding, and RFC 8881's `nfs4_cs_prep` profile does not prohibit stringprep
table C.4. Genuinely malformed tags are rejected; valid noncharacters
remain accepted. Thus the fixed implementation passes 99/100 selected
upstream cases per minor version, not an unconditional 100/100.

Separately adapted probes cover existing-file OPEN/READ/CLOSE, attributes,
VERIFY/NVERIFY, names, stateids, directory operations, security information,
replay, and v4.2 SEEK. Final runs passed 72/72 checks in v4.1 and 75/75 in
v4.2 with both auth flavors. These are not upstream-suite passes. In
particular, accepting unknown/old READ stateids is the documented macOS
restart workaround, not evidence of strict stateid conformance.

Do not select broad upstream flags blindly: `create_session` also selects
`DELEG5/6/7`, whose setup tries writable OPENs. `CSESS6` depends on
`CSESS9`; forcing it after that dependency fails provides corroborating
evidence, not an independent defect. See [pynfs.md](../tests/conformance/pynfs.md)
for setup, selection exclusions, and probe semantics.

### Defects identified

| Area | Evidence | Applicable RFC 8881 sections |
| --- | --- | --- |
| Client identity and confirmation | CSESS9, EID5e/5g/6g; missing credential matching and collision handling | 18.35.4, 18.36.4 |
| EXCHANGE_ID flags | EID4/EID7; undefined or response-only bits accepted | 18.35.3 |
| Session binding/destruction | DSESS9001/9004; unbound destruction and incorrect operation position | 18.34.3, 18.37.3 |
| RPC size limits | SEQ6 and boundary probes; request slack and omitted reply headers | 18.36.3, 2.10.6.4 |
| Replay | Uncached retry failed SEQUENCE rather than the following operation; metadata was lost | 2.10.6.1.1, 2.10.6.1.3 |
| Filehandles | PUTFH2; invalid handles accepted before backend validation | 15.1.2.1, 15.2 |
| Parent lookup | LKPP1r/LKPP1a; LOOKUPP succeeded on files and symlinks | 18.14.3 |
| Name lengths | Complete long components returned BADXDR rather than NAMETOOLONG | 3.2, 15.1.7.3 |
| Tags | COMP3; malformed UTF-8 accepted | 16.2.1, 16.2.4 |

Not all tool expectations are unconditional MUSTs. Unusable response-channel
sizes and tag validation include SHOULD-level guidance; minimum request
sizes and unknown CREATE_SESSION flags also involve robustness policy.
Review failures against the RFC and supported server scope before treating
them as defects.

## NFSTest and kernel clients

Three unmodified `nfstest_io` workloads completed with mutations disabled:
buffered reads, direct reads, and directory enumeration. The stock workload
does not compare read bytes; adapted tests supply exact-byte assertions.
The stock `nfstest_xid` checker found no captured operation-list mismatches.
The high-volume workload capture dropped packets, so that check covers only
captured traffic; adapted captures had no kernel drops. Inspect checker
output, not just its exit status.

Seven adapted scenarios exercise exact reads/EOF/offsets/symlinks,
directory traversal, delegation caching, file recall, directory recall,
nondelegated live changes, and restart with open descriptors and a deep
working directory. Mutations use memfs with SetServer and recall before
mutation. Immutable data is never changed.

Both minor versions passed 75/77 assertions. The two failures are bounded
immediate-visibility observations on the tested Linux client:

- An existing descriptor can read old bytes immediately after recall and
  mutation with `actimeo=1`, then obtain new bytes after revalidation.
  A focused v4.1 probe with `actimeo=0` eliminated this window.
- A deleted name can remain lookup-visible briefly despite a fresh listing.
  Later the server returns STALE for its old handle and NOENT for lookup.
  A focused v4.1 probe with `lookupcache=none` eliminated this window.

Traces showed successful CB_RECALL and DELEGRETURN before mutation and
correct file/parent change attributes. No missing mandatory notification
was established. The name-cache behavior was not fully root-caused; this
is not proof of a Linux bug or of complete client RFC compliance. Recall
releases a delegation, but does not disable ordinary client caching.

Full stock cache, delegation, and POSIX suites were not declared passed:
their setup creates or truncates files even for many read-oriented cases.
See [nfstest.md](../tests/conformance/nfstest.md) for compatible workloads
and the explicit adaptations.

## Validation and limitations

Go unit tests, race tests, vet, and opt-in Linux kernel tests passed after
the fixes. An initial `TestKernelDelegations` zero-traffic assertion failed
once, then passed isolated repeats and the full race suite; no deterministic
protocol defect was established. Cache-sensitive workloads must run
sequentially because existing restart tests drop system-wide caches.

The counts above describe recorded runs with the fixes applied, not a
promise that every revision or client will reproduce them. When reporting
new results, record the server revision, tool revisions, client/kernel,
mount options, and selected IDs. Keep upstream cases, adapted assertions,
Go parent/subtests, and syscall counts separate. Neither these runs nor a
green Go suite establishes exhaustive protocol, concurrency, or optional
feature coverage.
