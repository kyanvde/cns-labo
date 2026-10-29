"""
Space Race 1 - Mars Relay authentication, predictable hash chain.

Each 64-hex "authentication code" is a SHA-256 digest, and the next code is
derived deterministically from the current one ("hashed orbital telemetry").
That makes it a hash chain: next = sha256(current) under some encoding. A wrong
guess just closes the connection, so we can't learn the rule from feedback -
instead we try each plausible encoding on a fresh connection until one is
accepted, then keep applying it to ride the chain until the flag appears.

Usage: python3 solve.py
"""
import hashlib
import re
import socket

HOST = "cns-test.idlab.uantwerpen.be"
PORT = 50006

CODE_RE = re.compile(rb"CURRENT CODE:\s*([0-9a-fA-F]{64})")

# Candidate rules for next = f(current_hex). All must output 64 hex chars.
RULES = {
    "sha256(raw bytes)":   lambda c: hashlib.sha256(bytes.fromhex(c)).hexdigest(),
    "sha256(hex ascii)":   lambda c: hashlib.sha256(c.encode()).hexdigest(),
    "sha256(hex+newline)": lambda c: hashlib.sha256((c + "\n").encode()).hexdigest(),
    "sha256(HEX ascii)":   lambda c: hashlib.sha256(c.upper().encode()).hexdigest(),
    "double sha256(raw)":  lambda c: hashlib.sha256(hashlib.sha256(bytes.fromhex(c)).digest()).hexdigest(),
    "sha3_256(raw)":       lambda c: hashlib.sha3_256(bytes.fromhex(c)).hexdigest(),
    "blake2b-256(raw)":    lambda c: hashlib.blake2b(bytes.fromhex(c), digest_size=32).hexdigest(),
}


def recv_until(sock, markers, limit=1 << 16):
    buf = b""
    sock.settimeout(6)
    try:
        while len(buf) < limit:
            if any(m in buf for m in markers):
                break
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
    except socket.timeout:
        pass
    return buf


def try_rule(name, rule):
    """Open a session and keep predicting with `rule`. Return flag text or None."""
    s = socket.create_connection((HOST, PORT), timeout=15)
    transcript = recv_until(s, [b"CURRENT CODE"])
    round_no = 0
    while True:
        if b"cns{" in transcript or b"CNS{" in transcript:
            s.close()
            return transcript.decode(errors="replace")
        m = CODE_RE.search(transcript)
        if not m:
            s.close()
            return None
        current = m.group(1).decode().lower()
        s.sendall(rule(current).encode() + b"\n")
        transcript = recv_until(s, [b"CURRENT CODE", b"Wrong", b"cns{", b"CNS{"])
        if b"Wrong" in transcript:
            s.close()
            return None            # this rule is wrong; caller tries the next
        round_no += 1
        if round_no > 200:         # safety valve
            s.close()
            return transcript.decode(errors="replace")


def main():
    for name, rule in RULES.items():
        print(f"[*] Trying rule: {name}")
        result = try_rule(name, rule)
        if result is not None:
            print(f"\n[+] Correct rule: next = {name}")
            print("=== server response ===")
            print(result.strip())
            return
    print("\nNone of the candidate rules worked. Paste a run and I'll add more encodings.")


if __name__ == "__main__":
    main()
