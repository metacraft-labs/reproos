"""The Evidence zone: an append-only sink the controller cannot rewrite.

The M0 contract makes the controller's local journal a convenience and
the off-host sink the authority: "Append-only Evidence-zone sink durably
acknowledges hash-chained starts before executing the action ... host
mirror cannot overwrite accepted evidence." This module is that sink and
its client.

Protocol: one JSON request per line over a UNIX socket, one JSON reply.

  append     {"op":"append","stream":<plan id>,"record":"<canonical json>"}
             The sink checks the record is canonical, that it continues
             ITS OWN copy of the chain (prev == the sink's head for the
             stream, seq == next) and belongs to the stream, then appends
             it with fsync and replies {"ok":true,"seq":n,"head":<sha256>}.
             A record that forks the chain is refused and alerted: the
             sink never accepts a rewritten history.
  alert      {"op":"alert","stream":...,"kind":...,"detail":...}
  heartbeat  {"op":"heartbeat","stream":...}

Nothing else exists. read, list, delete, truncate and every unknown verb
are refused AND recorded as an alert attributed to the requesting peer
(UNIX socket credentials). Loss of heartbeat on an open stream for longer
than the configured window raises a "heartbeat-lost" alert.

Deployment requirement (not provable on one host by one user, and so not
claimed by the fixtures): the sink runs under its own account on its own
host, so the controller's credentials cannot reach its files except
through this protocol. The tests run it as the same Unix user and prove
the protocol-level boundary only.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os
import socket
import struct
import threading
import time
from pathlib import Path
from typing import Any

from . import canon

MAX_REQUEST = 4 * 1024 * 1024


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _fsync_append(path: Path, line: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        os.write(fd, line + b"\n")
        os.fsync(fd)
    finally:
        os.close(fd)


class Sink:
    def __init__(self, directory: Path, socket_path: str, heartbeat_window: float = 30.0):
        self.dir = directory
        self.streams = directory / "streams"
        self.streams.mkdir(parents=True, exist_ok=True)
        self.alerts = directory / "alerts.jsonl"
        self.socket_path = socket_path
        self.window = heartbeat_window
        self.heads: dict[str, tuple[int, str]] = {}
        self.seen: dict[str, float] = {}
        self.lock = threading.Lock()
        self.stop = threading.Event()
        for f in self.streams.glob("*.jsonl"):
            self._load(f.stem)

    def _load(self, stream: str) -> tuple[int, str]:
        if stream in self.heads:
            return self.heads[stream]
        seq, head = 0, stream
        path = self.streams / f"{stream}.jsonl"
        if path.exists():
            for line in path.read_bytes().splitlines():
                seq += 1
                head = hashlib.sha256(line).hexdigest()
        self.heads[stream] = (seq, head)
        return seq, head

    def alert(self, stream: str, kind: str, detail: str, peer: str = "", origin: str = "sink") -> None:
        record = {"time": _now(), "stream": stream, "kind": kind, "detail": detail[:4000], "peer": peer,
                  "origin": origin}
        _fsync_append(self.alerts, canon.encode(record))

    def handle(self, request: dict, peer: str) -> dict:
        op = request.get("op")
        stream = request.get("stream", "")
        if not isinstance(stream, str) or len(stream) != 64 or not all(c in "0123456789abcdef" for c in stream):
            self.alert(str(stream)[:80], "malformed-request", json.dumps(request)[:500], peer)
            return {"ok": False, "error": "stream must be a plan identity"}
        if op == "append":
            data = request.get("record", "").encode("ascii", "replace")
            try:
                record = canon.decode(data)
            except canon.CanonError as error:
                self.alert(stream, "non-canonical-record", str(error), peer)
                return {"ok": False, "error": f"non-canonical record: {error}"}
            with self.lock:
                seq, head = self._load(stream)
                if record.get("plan") != stream or record.get("prev") != head or record.get("seq") != seq + 1:
                    self.alert(stream, "chain-fork", f"record seq {record.get('seq')} prev {record.get('prev')} "
                               f"does not continue seq {seq} head {head}", peer)
                    return {"ok": False, "error": "record does not continue the accepted chain"}
                _fsync_append(self.streams / f"{stream}.jsonl", data)
                head = hashlib.sha256(data).hexdigest()
                self.heads[stream] = (seq + 1, head)
                self.seen[stream] = time.monotonic()
            return {"ok": True, "seq": seq + 1, "head": head}
        if op == "heartbeat":
            self.seen[stream] = time.monotonic()
            return {"ok": True}
        if op == "close":
            self.seen.pop(stream, None)
            return {"ok": True}
        if op == "alert":
            self.alert(stream, str(request.get("kind", "?"))[:80], str(request.get("detail", "")), peer,
                       origin="controller")
            return {"ok": True}
        self.alert(stream, "denied-operation", f"op {op!r} refused", peer)
        return {"ok": False, "error": f"operation {op!r} is not permitted; this sink only appends"}

    def _peer(self, conn: socket.socket) -> str:
        try:
            pid, uid, gid = struct.unpack("3i", conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                                                                struct.calcsize("3i")))
            return f"pid={pid} uid={uid} gid={gid}"
        except OSError:
            return "unknown"

    def _serve(self, conn: socket.socket) -> None:
        peer = self._peer(conn)
        with conn, conn.makefile("rwb") as f:
            while True:
                line = f.readline(MAX_REQUEST + 1)
                if not line:
                    return
                try:
                    request = json.loads(line)
                    reply = self.handle(request, peer) if isinstance(request, dict) else \
                        {"ok": False, "error": "request must be an object"}
                except json.JSONDecodeError:
                    reply = {"ok": False, "error": "not JSON"}
                f.write(json.dumps(reply).encode() + b"\n")
                f.flush()

    def _watch(self) -> None:
        while not self.stop.wait(1.0):
            now = time.monotonic()
            for stream, last in list(self.seen.items()):
                if now - last > self.window:
                    self.alert(stream, "heartbeat-lost",
                               f"no append or heartbeat for {int(now - last)}s on an open apply")
                    self.seen.pop(stream, None)

    def serve_forever(self) -> None:
        if os.path.exists(self.socket_path):
            os.unlink(self.socket_path)
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(self.socket_path)
        os.chmod(self.socket_path, 0o660)
        server.listen(16)
        threading.Thread(target=self._watch, daemon=True).start()
        server.settimeout(1.0)
        while not self.stop.is_set():
            try:
                conn, _ = server.accept()
            except socket.timeout:
                continue
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()
        server.close()


class SinkError(RuntimeError):
    pass


class Client:
    """The controller side. ``append`` is a journal sink: it raises unless
    the sink durably acknowledged the record, so unrecorded progress stops."""

    def __init__(self, socket_path: str, stream: str):
        self.socket_path = socket_path
        self.stream = stream
        self.lock = threading.Lock()

    def request(self, payload: dict[str, Any]) -> dict:
        with self.lock, socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(30)
            try:
                s.connect(self.socket_path)
                s.sendall(json.dumps(payload).encode() + b"\n")
                data = b""
                while not data.endswith(b"\n"):
                    chunk = s.recv(65536)
                    if not chunk:
                        break
                    data += chunk
            except OSError as error:
                raise SinkError(f"evidence sink {self.socket_path} unavailable: {error}") from error
        try:
            return json.loads(data)
        except json.JSONDecodeError as error:
            raise SinkError("evidence sink sent no verdict") from error

    def append(self, record: bytes) -> None:
        reply = self.request({"op": "append", "stream": self.stream, "record": record.decode("ascii")})
        if not reply.get("ok"):
            raise SinkError(f"evidence sink refused the record: {reply.get('error')}")

    def heartbeat(self) -> None:
        self.request({"op": "heartbeat", "stream": self.stream})

    def alert(self, kind: str, detail: str) -> None:
        self.request({"op": "alert", "stream": self.stream, "kind": kind, "detail": detail})

    def close(self) -> None:
        self.request({"op": "close", "stream": self.stream})
