# Read-only conformance checks

These optional runners complement the Go protocol and kernel-client tests.
They do not certify complete RFC compliance. See the
[findings report](../../doc/conformance-testing.md) for recorded results,
scope, and limitations.

- [pynfs](pynfs.md): pinned upstream revision, explicit
  [selection](pynfs-selection.json), disposable fixture/server runner,
  Python-3 path-option shim, and separately labeled protocol probes.
- [NFSTest](nfstest.md): pinned upstream revision, compatible unmodified
  read-only workloads, and adaptations using its reporting framework.

Use output directories outside the repository. Do not check in generated
per-case results, logs, or packet captures. Record the server revision,
tool versions, selected tests, and relevant client/mount settings when
contributing a result or reporting a failure.

Inspect failures rather than relying on process exit status alone. pynfs
can exit zero with failed cases; the wrapper checks its JSON. The pinned
COMP3 case incorrectly requires INVAL for valid UTF-8 encoding of U+FFFE.
NFSTest adaptations retain two immediate-cache-visibility assertions that
failed on the tested Linux client. Neither is silently suppressed.

Privileged cache-sensitive workloads must run sequentially. Existing kernel
restart tests affect system-wide caches even when servers use different
TCP ports.
