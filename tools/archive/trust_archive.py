#!/usr/bin/env python3
"""Archive signed trust lists (spec/envelope-format.md §9.2, §12.3).

A trust-list publisher serves its signed list as two files: `trust.json` (the payload) and
`trust.json.jws`, a compact JWS with ES256 and a detached payload (`header..signature`). This tool
checks the signature against pinned trust-list keys and files each new list under its sequence
number, so the repository keeps the history of every list ever published: a document can then be
verified years later with the list of its time.

    trust_archive.py verify  --keys KEYS --payload trust.json --jws trust.json.jws
    trust_archive.py archive --keys KEYS --payload trust.json --jws trust.json.jws --dir DIR

`KEYS` is a JSON file `{"keys": [<public P-256 JWK>, ...]}`: the trust-list key chain the
clients pin, in order (the key in use first, then the `next_keys` it pre-committed). With no
pinned key the tool refuses everything.

`archive` writes `DIR/<sequence, 8 digits>.json` and `.jws` (the exact bytes served) and appends a
line to `DIR/index.tsv` (sequence, issued_at, expires_at, SHA-256 of the payload, key id). It
prints `unchanged` when that sequence is already archived with the same bytes, and refuses the
same sequence with other bytes. As the clients do (the key-chain rule, spec §9.2), the key's
position in `KEYS` decides first: a list signed by a key later in the chain than the last
archived list's is archived whatever its sequence, one signed by an earlier key is refused, and
under the same key the sequence must be newer than the last archived one.

Standard library only (the P-256 arithmetic is below), so the archive job installs nothing.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sys

# --- P-256 (FIPS 186-5, SEC 2) --------------------------------------------------------------

P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
A = P - 3
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
G = (
    0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
    0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
)


def _on_curve(pt) -> bool:
    x, y = pt
    return 0 <= x < P and 0 <= y < P and (y * y - (x * x * x + A * x + B)) % P == 0


def _add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    (x1, y1), (x2, y2) = p1, p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if p1 == p2:
        lam = (3 * x1 * x1 + A) * pow(2 * y1, -1, P) % P
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, P) % P
    x3 = (lam * lam - x1 - x2) % P
    return (x3, (lam * (x1 - x3) - y1) % P)


def _mul(k: int, pt):
    acc = None
    while k:
        if k & 1:
            acc = _add(acc, pt)
        pt = _add(pt, pt)
        k >>= 1
    return acc


def es256_verify(x: int, y: int, message: bytes, sig: bytes) -> bool:
    """ECDSA P-256 / SHA-256 over `message`, with a 64-byte `r || s` signature (RFC 7518)."""
    if len(sig) != 64 or not _on_curve((x, y)):
        return False
    r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
    if not (0 < r < N and 0 < s < N):
        return False
    e = int.from_bytes(hashlib.sha256(message).digest(), "big")
    w = pow(s, -1, N)
    pt = _add(_mul(e * w % N, G), _mul(r * w % N, (x, y)))
    return pt is not None and pt[0] % N == r


# --- JWS ----------------------------------------------------------------------------------------


def b64url_decode(s: str) -> bytes:
    if any(c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for c in s):
        raise ValueError("not base64url")
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def thumbprint(jwk: dict) -> str:
    """RFC 7638 thumbprint of a P-256 public JWK."""
    canonical = json.dumps(
        {"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"], "y": jwk["y"]},
        separators=(",", ":"),
        sort_keys=True,
    )
    return b64url(hashlib.sha256(canonical.encode()).digest())


class Refused(Exception):
    """The list is not archived; the message says why."""


def position(pinned: list[dict], kid: str) -> int:
    """The position in the chain `pinned` of the key whose thumbprint is `kid` (-1: none)."""
    for i, k in enumerate(pinned):
        if k.get("kty") == "EC" and k.get("crv") == "P-256" and thumbprint(k) == kid:
            return i
    return -1


def verify(payload: bytes, jws: str, pinned: list[dict]) -> dict:
    """Check the detached JWS over `payload` against `pinned`; return the protected header."""
    if not pinned:
        raise Refused("no trust-list key is pinned: refusing to archive anything")
    parts = jws.strip().split(".")
    if len(parts) != 3 or parts[1] != "":
        raise Refused("not a detached compact JWS (header..signature)")
    try:
        header = json.loads(b64url_decode(parts[0]))
        sig = b64url_decode(parts[2])
    except (ValueError, json.JSONDecodeError) as e:
        raise Refused(f"unreadable JWS: {e}") from None
    if header.get("alg") != "ES256":
        raise Refused("alg must be ES256")
    if "b64" in header or "crit" in header:
        raise Refused("unencoded payloads and critical header parameters are not accepted")
    kid = header.get("kid", "")
    key = next(
        (
            k
            for k in pinned
            if k.get("kty") == "EC" and k.get("crv") == "P-256" and thumbprint(k) == kid
        ),
        None,
    )
    if key is None:
        raise Refused(f"signed with key {kid!r}, which is not pinned")
    x = int.from_bytes(b64url_decode(key["x"]), "big")
    y = int.from_bytes(b64url_decode(key["y"]), "big")
    signing_input = (parts[0] + "." + b64url(payload)).encode()
    if not es256_verify(x, y, signing_input, sig):
        raise Refused("the signature does not verify")
    return header


def archive(payload: bytes, jws: str, pinned: list[dict], directory: str) -> str:
    """Verify, then file the list under its sequence number. Returns `archived` or `unchanged`."""
    header = verify(payload, jws, pinned)
    try:
        body = json.loads(payload)
    except json.JSONDecodeError as e:
        raise Refused(f"the payload is not JSON: {e}") from None
    seq = body.get("sequence")
    if not isinstance(seq, int) or isinstance(seq, bool) or seq < 1:
        raise Refused("the list has no positive integer `sequence`")
    os.makedirs(directory, exist_ok=True)
    name = os.path.join(directory, f"{seq:08d}")
    if os.path.exists(name + ".json"):
        with open(name + ".json", "rb") as f:
            if f.read() == payload:
                return "unchanged"
        raise Refused(f"sequence {seq} is archived with other content: a list was changed")
    last = None  # (sequence, key id) of the last list archived
    index = os.path.join(directory, "index.tsv")
    if os.path.exists(index):
        with open(index, encoding="utf-8") as f:
            rows = [line.split("\t") for line in f.read().splitlines() if line.strip()]
        if rows:
            last = (int(rows[-1][0]), rows[-1][4] if len(rows[-1]) > 4 else "")
    if last:
        mine, theirs = position(pinned, header.get("kid", "")), position(pinned, last[1])
        if mine < theirs:
            raise Refused(
                f"sequence {seq} is signed by a trust-list key earlier in the chain than the last "
                f"archived list ({last[0]}): an old key's list after a rotation"
            )
        if mine == theirs and seq <= last[0]:
            raise Refused(f"sequence {seq} is not newer than the last archived one ({last[0]})")
    with open(name + ".json", "wb") as f:
        f.write(payload)
    with open(name + ".jws", "w", encoding="ascii", newline="\n") as f:
        f.write(jws.strip() + "\n")
    with open(os.path.join(directory, "index.tsv"), "a", encoding="utf-8", newline="\n") as f:
        f.write(
            "\t".join(
                [
                    str(seq),
                    str(body.get("issued_at", "")),
                    str(body.get("expires_at", "")),
                    hashlib.sha256(payload).hexdigest(),
                    str(header.get("kid", "")),
                ]
            )
            + "\n"
        )
    return "archived"


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("command", choices=["verify", "archive"])
    ap.add_argument("--keys", required=True, help="pinned trust-list keys ({\"keys\": [...]})")
    ap.add_argument("--payload", required=True, help="trust.json, as served")
    ap.add_argument("--jws", required=True, help="trust.json.jws, as served")
    ap.add_argument("--dir", help="archive directory (archive only)")
    args = ap.parse_args(argv)
    with open(args.keys, encoding="utf-8") as f:
        pinned = json.load(f).get("keys", [])
    with open(args.payload, "rb") as f:
        payload = f.read()
    with open(args.jws, encoding="ascii") as f:
        jws = f.read()
    try:
        if args.command == "verify":
            header = verify(payload, jws, pinned)
            print(f"verified: signed by {header.get('kid')}")
        else:
            if not args.dir:
                ap.error("archive needs --dir")
            print(archive(payload, jws, pinned, args.dir))
    except Refused as e:
        print(f"refused: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
