import base64
import hashlib
import hmac
import json

ATTACKS = {
    "unsigned_algorithm": ['{"alg":"none","typ":"JWT"}'],
    "disallowed_algorithm": [
        '{"alg":"HS384","typ":"JWT"}',
        '{"alg":"HS512","typ":"JWT"}',
    ],
    "forged_hs256": ['{"alg":"HS256","typ":"JWT"}'],
    "forged_claims": [
        '{"sub":"attacker","role":"admin","is_admin":true}',
        '{"sub":"forged-user","permissions":["read","write","delete"]}',
    ],
    "invalid_signature": [
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "ZmFrZS1zaWduYXR1cmU",
    ],
    "unsigned_signature": [""],
}


def make_input(fdp, sandbox):
    def encode_segment(value):
        raw = value if isinstance(value, bytes) else value.encode("utf-8")
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

    key = fdp.ConsumeUnicodeNoSurrogates(16)

    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(
            ["unsigned_algorithm", "disallowed_algorithm", "forged_hs256"]
        )
        header = json.loads(fdp.PickValueInList(ATTACKS[technique]))
        claims = json.loads(fdp.PickValueInList(ATTACKS["forged_claims"]))
        claims["fuzz"] = fdp.ConsumeUnicodeNoSurrogates(12)

        signature_family = (
            "unsigned_signature"
            if technique == "unsigned_algorithm"
            else "invalid_signature"
        )
        token = ".".join(
            [
                encode_segment(json.dumps(header, separators=(",", ":"))),
                encode_segment(json.dumps(claims, separators=(",", ":"))),
                fdp.PickValueInList(ATTACKS[signature_family]),
            ]
        )
    else:
        claims = {
            "sub": fdp.PickValueInList(["user", "guest", "reader"]),
            "role": fdp.PickValueInList(["reader", "viewer"]),
        }
        header = {"alg": "HS256", "typ": "JWT"}
        signing_input = ".".join(
            [
                encode_segment(json.dumps(header, separators=(",", ":"))),
                encode_segment(json.dumps(claims, separators=(",", ":"))),
            ]
        )
        signature = hmac.new(
            key.encode("utf-8"), signing_input.encode("ascii"), hashlib.sha256
        ).digest()
        token = signing_input + "." + encode_segment(signature)

    return {"token": token, "key": key}
