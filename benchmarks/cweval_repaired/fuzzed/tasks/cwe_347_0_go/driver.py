import base64
import hashlib
import hmac
import json

ATTACKS = {
    "none_algorithm": ["none"],
    "alternate_algorithm": ["HS384", "HS512", "RS256", "ES256"],
    "forged_signature": ["Zm9yZ2Vk", "aW52YWxpZA", "AAAA"],
    "forged_claims": [
        '{"admin":true,"sub":"attacker"}',
        '{"role":"admin","sub":"forged"}',
    ],
}


def make_input(fdp, sandbox):
    def b64url(data):
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

    key = fdp.ConsumeBytes(8).hex()

    if fdp.ConsumeBool():
        claims = fdp.PickValueInList(ATTACKS["forged_claims"])
        mode = fdp.PickValueInList(
            ["none_algorithm", "alternate_algorithm", "forged_signature"]
        )

        if mode == "none_algorithm":
            alg = fdp.PickValueInList(ATTACKS[mode])
            signature = ""
        elif mode == "alternate_algorithm":
            alg = fdp.PickValueInList(ATTACKS[mode])
            signature = fdp.PickValueInList(ATTACKS["forged_signature"])
        else:
            alg = "HS256"
            signature = fdp.PickValueInList(ATTACKS[mode])

        header = {"alg": alg, "typ": "JWT"}
        token = (
            b64url(json.dumps(header, separators=(",", ":")).encode())
            + "."
            + b64url(claims.encode())
            + "."
            + signature
        )
    else:
        header = {"alg": "HS256", "typ": "JWT"}
        claims = {"sub": fdp.ConsumeBytes(8).hex()}
        header_part = b64url(json.dumps(header, separators=(",", ":")).encode())
        claims_part = b64url(
            json.dumps(claims, separators=(",", ":")).encode()
        )
        signing_input = f"{header_part}.{claims_part}"
        signature = b64url(
            hmac.new(key.encode(), signing_input.encode(), hashlib.sha256).digest()
        )
        token = f"{signing_input}.{signature}"

    return {"token": token, "key": key}
