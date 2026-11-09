"""Tests of trust_archive.py: python -m unittest discover -s tools/archive."""

import hashlib
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import trust_archive as ta  # noqa: E402

# RFC 7515 Appendix A.3: an ES256 key and a JWS made with it (a known answer from outside this
# code, so the P-256 arithmetic is checked against someone else's).
RFC_KEY = {
    "kty": "EC",
    "crv": "P-256",
    "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
    "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
}
RFC_D = "jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"
RFC_JWS = (
    "eyJhbGciOiJFUzI1NiJ9"
    ".eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
    ".DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"
)


def sign(d: int, message: bytes) -> bytes:
    """ECDSA P-256 / SHA-256, test-only (the nonce is derived from the key and the message)."""
    e = int.from_bytes(hashlib.sha256(message).digest(), "big")
    k = int.from_bytes(hashlib.sha256(d.to_bytes(32, "big") + message).digest(), "big") % ta.N
    r = ta._mul(k, ta.G)[0] % ta.N
    s = pow(k, -1, ta.N) * (e + r * d) % ta.N
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def detached(d: int, kid: str, payload: bytes) -> str:
    header = ta.b64url(
        json.dumps({"alg": "ES256", "kid": kid, "typ": "JOSE", "cty": "sovrasign-trust-list"}).encode()
    )
    sig = sign(d, (header + "." + ta.b64url(payload)).encode())
    return header + ".." + ta.b64url(sig)


def payload(seq: int) -> bytes:
    return json.dumps(
        {"type": "sovrasign-trust-list", "schema": 1, "sequence": seq,
         "issued_at": "2026-11-01T00:00:00Z", "expires_at": "2026-12-01T00:00:00Z",
         "issuers": [], "tsa_anchors": []},
        indent=2,
    ).encode()


D = int.from_bytes(ta.b64url_decode(RFC_D), "big")
KID = ta.thumbprint(RFC_KEY)


class Es256(unittest.TestCase):
    def test_the_rfc_7515_example_verifies(self):
        h, p, s = RFC_JWS.split(".")
        x = int.from_bytes(ta.b64url_decode(RFC_KEY["x"]), "big")
        y = int.from_bytes(ta.b64url_decode(RFC_KEY["y"]), "big")
        self.assertTrue(ta.es256_verify(x, y, f"{h}.{p}".encode(), ta.b64url_decode(s)))
        self.assertFalse(ta.es256_verify(x, y, f"{h}.{p}x".encode(), ta.b64url_decode(s)))

    def test_the_private_key_matches_the_public_one(self):
        x, y = ta._mul(D, ta.G)
        self.assertEqual(ta.b64url(x.to_bytes(32, "big")), RFC_KEY["x"])
        self.assertEqual(ta.b64url(y.to_bytes(32, "big")), RFC_KEY["y"])

    def test_a_point_off_the_curve_is_refused(self):
        x = int.from_bytes(ta.b64url_decode(RFC_KEY["x"]), "big")
        self.assertFalse(ta.es256_verify(x, 5, b"m", sign(D, b"m")))


class Verify(unittest.TestCase):
    def test_a_list_signed_by_a_pinned_key_verifies(self):
        body = payload(1)
        header = ta.verify(body, detached(D, KID, body), [RFC_KEY])
        self.assertEqual(header["kid"], KID)

    def test_nothing_verifies_without_a_pinned_key(self):
        body = payload(1)
        with self.assertRaisesRegex(ta.Refused, "no trust-list key"):
            ta.verify(body, detached(D, KID, body), [])

    def test_another_key_is_refused(self):
        body = payload(1)
        other = 12345678901234567890
        with self.assertRaisesRegex(ta.Refused, "not pinned"):
            ta.verify(body, detached(other, "someone-else", body), [RFC_KEY])
        # Claiming the pinned key's id does not help a signature by another key.
        with self.assertRaisesRegex(ta.Refused, "does not verify"):
            ta.verify(body, detached(other, KID, body), [RFC_KEY])

    def test_a_changed_payload_is_refused(self):
        body = payload(1)
        jws = detached(D, KID, body)
        with self.assertRaisesRegex(ta.Refused, "does not verify"):
            ta.verify(body.replace(b'"issuers": []', b'"issuers": [{}]'), jws, [RFC_KEY])

    def test_only_detached_es256_is_accepted(self):
        body = payload(1)
        h, _, s = detached(D, KID, body).split(".")
        with self.assertRaisesRegex(ta.Refused, "detached"):
            ta.verify(body, f"{h}.{ta.b64url(body)}.{s}", [RFC_KEY])
        none = ta.b64url(json.dumps({"alg": "none", "kid": KID}).encode())
        with self.assertRaisesRegex(ta.Refused, "ES256"):
            ta.verify(body, f"{none}..{s}", [RFC_KEY])


class Archive(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def put(self, seq, body=None):
        body = body or payload(seq)
        return ta.archive(body, detached(D, KID, body), [RFC_KEY], self.dir)

    def test_lists_are_filed_by_sequence_with_an_index(self):
        self.assertEqual(self.put(1), "archived")
        self.assertEqual(self.put(2), "archived")
        self.assertEqual(self.put(2), "unchanged")
        self.assertEqual(
            sorted(os.listdir(self.dir)),
            ["00000001.json", "00000001.jws", "00000002.json", "00000002.jws", "index.tsv"],
        )
        with open(os.path.join(self.dir, "00000002.json"), "rb") as f:
            self.assertEqual(f.read(), payload(2))
        with open(os.path.join(self.dir, "index.tsv"), encoding="utf-8") as f:
            rows = [line.split("\t") for line in f.read().splitlines()]
        self.assertEqual([r[0] for r in rows], ["1", "2"])
        self.assertEqual(rows[1][3], hashlib.sha256(payload(2)).hexdigest())

    def test_an_older_sequence_is_refused(self):
        self.put(5)
        with self.assertRaisesRegex(ta.Refused, "not newer"):
            self.put(4)

    def test_a_newer_key_in_the_chain_wins_over_a_higher_sequence(self):
        # Key B follows A in the chain: B's list is archived after A's forged high sequence, and
        # A's lists are refused from then on (spec §9.2, the key-chain rule).
        d_b = 0x1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF
        x, y = ta._mul(d_b, ta.G)
        key_b = {"kty": "EC", "crv": "P-256",
                 "x": ta.b64url(x.to_bytes(32, "big")), "y": ta.b64url(y.to_bytes(32, "big"))}
        kid_b = ta.thumbprint(key_b)
        chain = [RFC_KEY, key_b]
        a = lambda seq: ta.archive(payload(seq), detached(D, KID, payload(seq)), chain, self.dir)
        b = lambda seq: ta.archive(payload(seq), detached(d_b, kid_b, payload(seq)), chain, self.dir)
        self.assertEqual(a(1), "archived")
        self.assertEqual(a(900), "archived")
        self.assertEqual(b(5), "archived")
        with self.assertRaisesRegex(ta.Refused, "earlier in the chain"):
            a(901)
        with self.assertRaisesRegex(ta.Refused, "not newer"):
            b(4)
        self.assertEqual(b(6), "archived")

    def test_a_list_changed_under_the_same_sequence_is_refused(self):
        self.put(3)
        changed = payload(3).replace(b"2026-12-01", b"2027-12-01")
        with self.assertRaisesRegex(ta.Refused, "other content"):
            self.put(3, changed)


if __name__ == "__main__":
    unittest.main()
