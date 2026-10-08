#!/usr/bin/env python3
"""NFSTest TestUtil adaptations, not stock upstream suite passes.

The runner owns its server, mount, and capture. Mutations use memfs control.
Set PYTHONPATH to the pinned, unchanged upstream NFSTest checkout.
"""
import json
import os
from pathlib import Path
import signal
import subprocess
import time
import traceback

from nfstest.test_util import TestUtil

if not os.environ.get("NFSTEST_RESULTS"):
    raise SystemExit("Set NFSTEST_RESULTS to an output directory containing nfstestserve")
RESULTS = Path(os.environ["NFSTEST_RESULTS"]).resolve()
BINARY = RESULTS / "nfstestserve"
SOCKET = RESULTS / "control.sock"
MOUNT = RESULTS / "mnt"
DATA = bytes(i % 251 for i in range(1024 * 1024))


class ReadonlyTest(TestUtil):
    def __init__(self):
        super().__init__(testnames=["read", "traverse", "cache", "recall", "dir_recall", "live", "restart"])
        self.scan_options()
        self.nomount = True
        self.nocleanup = True
        self.server_process = None
        self.capture = None
        self.mount_owned = False
        self.server_log = None
        self.observations = {}

    def ctl(self, route, data=None):
        cmd = ["curl", "--silent", "--show-error", "--fail", "--max-time", "130", "--unix-socket", str(SOCKET)]
        if data is not None:
            cmd += ["-X", "POST", "--data-binary", "@-"]
        cmd += ["http://localhost/" + route]
        return json.loads(subprocess.check_output(cmd, input=data, cwd=RESULTS))

    def start_server(self):
        self.server_process = subprocess.Popen([str(BINARY), "--control", str(SOCKET)], stdout=self.server_log, stderr=subprocess.STDOUT, cwd=RESULTS)
        for _ in range(100):
            try:
                self.ctl("stats")
                return
            except subprocess.CalledProcessError:
                if self.server_process.poll() is not None:
                    raise RuntimeError("server exited")
                time.sleep(0.05)
        raise RuntimeError("control socket not ready")

    def start_owned(self):
        RESULTS.mkdir(parents=True, exist_ok=True)
        MOUNT.mkdir(exist_ok=True)
        if os.path.ismount(MOUNT):
            raise RuntimeError("refuse to use an existing mount")
        self.server_log = open(RESULTS / "adapted-server.log", "w")
        self.start_server()
        self.capture_log = open(RESULTS / "adapted-tcpdump.log", "w")
        self.capture = subprocess.Popen(["sudo", "-n", "tcpdump", "-i", "lo", "-B", "4096", "-s", "0", "-U", "-w", str(RESULTS / "adapted.pcap"), "tcp port 23049"], stdout=self.capture_log, stderr=subprocess.STDOUT)
        time.sleep(0.3)
        subprocess.run(["sudo", "-n", "mount", "-t", "nfs4", "-o", "vers=%s,port=23049,ro,actimeo=1" % self.nfsversion, "127.0.0.1:/", str(MOUNT)], check=True)
        self.mount_owned = True

    def stop_owned(self):
        if self.mount_owned:
            out = subprocess.run(["sudo", "-n", "umount", str(MOUNT)], timeout=20)
            if out.returncode:
                subprocess.run(["sudo", "-n", "umount", "-l", str(MOUNT)], check=True)
            self.mount_owned = False
        if self.capture:
            subprocess.run(["sudo", "-n", "kill", "-INT", str(self.capture.pid)], check=False)
            self.capture.wait(timeout=10)
        if self.server_process:
            self.server_process.terminate()
            self.server_process.wait(timeout=10)
        if self.server_log:
            self.server_log.close()
        if hasattr(self, "capture_log"):
            self.capture_log.close()
        (RESULTS / "observations.json").write_text(json.dumps(self.observations, indent=2))

    def check(self, condition, message):
        self.test(condition, "ADAPTED: " + message)

    def read_test(self):
        self.test_group("ADAPTED RO-READ: exact bytes, EOF, offsets, seek, symlink")
        for tree in ["immutable", "delegated", "live"]:
            with open(MOUNT / tree / "blob", "rb") as f:
                self.check(f.read() == DATA, tree + " full 1 MiB read matches")
                self.check(f.read(1) == b"", tree + " EOF")
                for offset in [0, 1, 4095, 65535, len(DATA) - 19, len(DATA), len(DATA) + 100]:
                    self.check(os.pread(f.fileno(), 7001, offset) == DATA[offset:offset + 7001], tree + " pread offset %d" % offset)
            self.check((MOUNT / tree / "link").read_bytes() == b"before\n", tree + " symlink target read")
            self.check(os.readlink(MOUNT / tree / "link") == "deep/a/b/text", tree + " readlink")

    def traverse_test(self):
        self.test_group("ADAPTED RO-DIR: directory enumeration and deep cwd")
        expected = sorted("entry" + chr(ord("A") + i // 26) + chr(ord("a") + i % 26) for i in range(256))
        for tree in ["immutable", "delegated", "live"]:
            self.check(sorted(os.listdir(MOUNT / tree / "listing")) == expected, tree + " 256 entries")
            old = os.getcwd()
            try:
                os.chdir(MOUNT / tree / "deep/a/b")
                self.check(Path("text").read_bytes() == b"before\n", tree + " cwd relative read")
                self.check(os.stat("../../..").st_ino == os.stat(MOUNT / tree).st_ino, tree + " parent traversal")
            finally:
                os.chdir(old)

    def cache_test(self):
        old = os.getcwd()
        try:
            os.chdir(MOUNT / "immutable")
            self.check_cache()
        finally:
            os.chdir(old)

    def check_cache(self):
        self.test_group("ADAPTED RO-CACHE: no revalidation past actimeo=1 with delegations")
        p = Path("deep/a/b/text")
        d = Path("listing")
        for _ in range(4):
            p.read_bytes()
            os.access(d, os.R_OK)
            os.listdir(d)
            time.sleep(1.2)
        before = self.ctl("stats")
        for _ in range(3):
            self.check(p.read_bytes() == b"before\n", "cached bytes match")
            os.stat(p)
            os.access(d, os.R_OK)
            self.check(len(os.listdir(d)) == 256, "cached listing matches")
            time.sleep(1.2)
        after = self.ctl("stats")
        relevant = ["3", "9", "15", "18", "25", "26"]
        delta = {k: after["Ops"].get(k, 0) - before["Ops"].get(k, 0) for k in relevant}
        self.observations["cache"] = {"before": before, "after": after, "delta": delta}
        self.check(after["Delegations"] > 0, "delegations granted")
        self.check(not any(delta.values()), "no ACCESS/GETATTR/LOOKUP/OPEN/READ/READDIR during warm repeated access")

    def recall_test(self):
        self.test_group("ADAPTED RO-RECALL: memfs recalls before file mutation")
        p = MOUNT / "delegated/deep/a/b/text"
        with open(p, "rb") as f:
            self.check(f.read() == b"before\n", "initial delegated content")
            before = self.ctl("stats")
            after = self.ctl("write?path=delegated/deep/a/b/text", b"after-recall-content\n")
            self.observations["recall"] = {"before": before, "after": after}
            self.check(after["Recalls"] > before["Recalls"], "recall sent for mutation")
            self.check(after["Revocations"] == before["Revocations"], "no forced revocation")
            immediate = os.pread(f.fileno(), 100, 0)
            time.sleep(2.1)
            delayed = os.pread(f.fileno(), 100, 0)
            os.stat(p)
            after_stat = os.pread(f.fileno(), 100, 0)
            self.observations["recall_reads"] = {"immediate": immediate.decode(), "after_2s": delayed.decode(), "after_stat": after_stat.decode()}
            self.check(immediate == b"after-recall-content\n", "already-open fd sees recalled content immediately")
            self.check(after_stat == b"after-recall-content\n", "already-open fd sees recalled content after stat")
        self.check(p.read_bytes() == b"after-recall-content\n", "reopen sees recalled content")

    def dir_recall_test(self):
        self.test_group("ADAPTED RO-DIR-RECALL: add/remove with directory recall")
        d = MOUNT / "delegated/listing"
        for _ in range(4):
            os.access(d, os.R_OK)
            os.listdir(d)
            os.path.exists(d / "added")
            time.sleep(1.2)
        before = self.ctl("stats")
        after = self.ctl("write?path=delegated/listing/added", b"added\n")
        self.observations["dir_recall"] = {"before": before, "after": after}
        self.check(after["Recalls"] > before["Recalls"], "directory recall sent before add")
        self.check("added" in os.listdir(d), "new listing entry visible")
        self.check((d / "added").read_bytes() == b"added\n", "negative lookup cache invalidated")
        self.ctl("remove?path=delegated/listing/added", b"")
        self.check("added" not in os.listdir(d), "removed entry absent")
        immediate = (d / "added").exists()
        time.sleep(2.1)
        delayed = (d / "added").exists()
        self.observations["removed_lookup"] = {"immediate_exists": immediate, "after_2s_exists": delayed}
        self.check(not immediate, "removed lookup absent immediately")
        self.check(not delayed, "removed lookup absent after timeout")

    def live_test(self):
        self.test_group("ADAPTED RO-LIVE: nondelegated change visible after attribute timeout")
        p = MOUNT / "live/deep/a/b/text"
        with open(p, "rb") as f:
            self.check(f.read() == b"before\n", "initial live bytes")
            before = self.ctl("stats")
            after = self.ctl("write?path=live/deep/a/b/text", b"after-live-content\n")
            self.check(after["Recalls"] == before["Recalls"], "no recall for nondelegated live file")
            start = time.monotonic()
            while time.monotonic() - start < 5:
                if p.read_bytes() == b"after-live-content\n":
                    break
                time.sleep(0.2)
            self.observations["live_latency"] = time.monotonic() - start
            self.check(p.read_bytes() == b"after-live-content\n", "reopen sees live mutation within 5s")
            self.check(os.pread(f.fileno(), 100, 0) == b"after-live-content\n", "already-open fd sees revalidated live content")
        d = MOUNT / "live/listing"
        os.listdir(d)
        self.ctl("write?path=live/listing/added", b"live added\n")
        time.sleep(2.1)
        self.check("added" in os.listdir(d), "live directory add visible")
        self.ctl("remove?path=live/listing/added", b"")
        time.sleep(2.1)
        self.check("added" not in os.listdir(d), "live directory remove visible")

    def restart_test(self):
        self.test_group("ADAPTED RO-RESTART: fresh memfs, persistent open filehandles and cwd")
        fds = [os.open(MOUNT / tree / "blob", os.O_RDONLY) for tree in ["immutable", "delegated", "live"]]
        old = os.getcwd()
        try:
            os.chdir(MOUNT / "live/deep/a/b")
            for fd in fds:
                self.check(os.pread(fd, 100, 777) == DATA[777:877], "pre-restart fd read")
                os.posix_fadvise(fd, 0, 0, os.POSIX_FADV_DONTNEED)
            self.server_process.terminate()
            self.server_process.wait(timeout=10)
            time.sleep(1.2)
            self.start_server()
            time.sleep(2.1)
            for fd in fds:
                self.check(os.pread(fd, 65536, 70000) == DATA[70000:135536], "persistent open fd reads after restart")
            self.check(Path("text").read_bytes() == b"before\n", "deep cwd resolves fresh tree after restart")
            self.check(len(os.listdir("../../../listing")) == 256, "relative directory traversal survives restart")
            stats = self.ctl("stats")
            self.observations["restart"] = stats
            self.check(stats["Sessions"] > 0 and stats["Ops"].get("25", 0) > 0, "new session and actual server READ after restart")
        finally:
            os.chdir(old)
            for fd in fds:
                os.close(fd)


if __name__ == "__main__":
    x = ReadonlyTest()
    try:
        x.start_owned()
        x.run_tests()
    except Exception:
        x.test(False, "ADAPTED runner exception: " + traceback.format_exc())
    finally:
        x.stop_owned()
    x.exit()
