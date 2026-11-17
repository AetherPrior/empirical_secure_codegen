import base64
import hashlib
import hmac
import json

ATTACKS = {
    "unverified_hs256": [
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhIjoxfQ.AAAA",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhIjoxfQ.bm90LXZhbGlk",
    ],
    "unsigned_none": [
        "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJhIjoxfQ.",
    ],
    "attacker_keys": [
        "",
        "wrong-key",
        "secret",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        family = fdp.PickValueInList(
            ["unverified_hs256", "unsigned_none"]
        )
        token = fdp.PickValueInList(ATTACKS[family])
        key = fdp.PickValueInList(ATTACKS["attacker_keys"])
        return {"token": token, "key": key}

    key = "benign-key"
    claims = {"sub": fdp.ConsumeUnicodeNoSurrogates(8)}
    encode = lambda value: base64.urlsafe_b64encode(
        value.encode("utf-8")
    ).decode("ascii").rstrip("=")

    header = encode(json.dumps(
        {"alg": "HS256", "typ": "JWT"}, separators=(",", ":")
    ))
    payload = encode(json.dumps(claims, separators=(",", ":")))
    signing_input = header + "." + payload
    signature = hmac.new(
        key.encode("utf-8"),
        signing_input.encode("ascii"),
        hashlib.sha256,
    ).digest()
    token = signing_input + "." + base64.urlsafe_b64encode(
        signature
    ).decode("ascii").rstrip("=")
    return {"token": token, "key": key}
