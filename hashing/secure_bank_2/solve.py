"""
Candy Land Bank 2 - audit fingerprint collision.

The audit fingerprint is a TRUNCATED SHA-256. Truncation kills collision
resistance: if it keeps n hex chars, a birthday search finds two different valid
payments with the same fingerprint in ~2^(2n) hashes. Two such payments are
indistinguishable in the audit log - that's the bug.

Protocol notes learned from the server:
  * fingerprint = truncated SHA-256 (length discovered from a probe)
  * timestamp must be within the last minute -> we base it on the server's own
    "Current time:" line, so clock skew can't bite us, and do the collision
    search + submit inside one connection so the timestamp stays fresh
  * one JSON payment per line, two lines per session

Usage: python3 solve.py
"""
import hashlib
import json
import re
import socket
from datetime import datetime, timedelta

HOST = "cns-test.idlab.uantwerpen.be"
PORT = 50003


def canonicalize(payment):
    return json.dumps(payment, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def record(reference, timestamp):
    return {
        "reference": reference,
        "from_account": "SIM-ALICE",
        "to_account": "SIM-BOB",          # must differ from from_account
        "amount": 10,                      # must equal 10 (number)
        "currency": "EUR",
        "timestamp": timestamp,            # ISO 8601, within the last minute
    }


def open_session():
    """Open a connection, read the banner, derive a fresh server-based timestamp."""
    s = socket.create_connection((HOST, PORT), timeout=15)
    s.settimeout(6)
    banner = b""
    try:
        while b"Payment 1" not in banner:
            chunk = s.recv(4096)
            if not chunk:
                break
            banner += chunk
    except socket.timeout:
        pass
    m = re.search(rb"Current time:\s*([0-9T:\-.\+]+)", banner)
    now = datetime.fromisoformat(m.group(1).decode()) if m else datetime.utcnow()
    ts = (now - timedelta(seconds=2)).isoformat()
    return s, ts, banner.decode(errors="replace")


def send_pair(s, ref1, ref2, ts):
    s.sendall(canonicalize(record(ref1, ts)) + b"\n" +
              canonicalize(record(ref2, ts)) + b"\n")
    out = b""
    try:
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            out += chunk
    except socket.timeout:
        pass
    s.close()
    return out.decode(errors="replace")


def detect_length(reply, ts):
    probe_hash = hashlib.sha256(canonicalize(record("probe-a", ts))).hexdigest()
    for fp in re.findall(r"\b[0-9a-fA-F]{4,}\b", reply):
        fp = fp.lower()
        if len(fp) < len(probe_hash) and probe_hash.startswith(fp):
            return len(fp)
    return None


def find_collision(length, ts):
    seen = {}
    i = 0
    while True:
        ref = f"ref-{i}"
        fp = hashlib.sha256(canonicalize(record(ref, ts))).hexdigest()[:length]
        if fp in seen:
            return seen[fp], ref, fp
        seen[fp] = ref
        i += 1


def main():
    # 1. Probe: two valid records -> learn the SHA-256 truncation length.
    s, ts, banner = open_session()
    reply = banner + send_pair(s, "probe-a", "probe-b", ts)
    print("=== probe reply ===")
    print(reply.strip())

    length = detect_length(reply, ts)
    if not length:
        print("\nNo returned fingerprint matched SHA-256 of our record. "
              "Paste the reply and I'll adjust.")
        return
    print(f"\n[+] Fingerprint = SHA-256 truncated to {length} hex chars "
          f"({length * 4} bits, ~2^{length * 2} birthday work)")

    # 2. Fresh session: find a colliding pair for this session's timestamp and
    #    submit it immediately (search is sub-second, so it stays within the minute).
    s, ts, _ = open_session()
    ref1, ref2, fp = find_collision(length, ts)
    print(f"[+] Collision for ts {ts}: {ref1!r} and {ref2!r} -> {fp}")

    response = send_pair(s, ref1, ref2, ts)
    print("\n=== server response ===")
    print(response.strip())


if __name__ == "__main__":
    main()
