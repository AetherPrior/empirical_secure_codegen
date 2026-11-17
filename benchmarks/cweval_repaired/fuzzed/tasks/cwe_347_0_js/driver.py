ATTACKS = {
    "unsigned_none": [
        '{"alg":"none","typ":"JWT"}',
        '{"typ":"JWT","alg":"none"}',
    ],
    "disallowed_algorithm": [
        '{"alg":"HS384","typ":"JWT"}',
        '{"alg":"RS256","typ":"JWT"}',
    ],
    "tampered_signature": [
        "AAAA",
        "eA",
        "not-a-signature",
    ],
    "forged_claims": [
        '{"sub":"attacker","admin":true}',
        '{"role":"admin","verified":true}',
        '{"user":"root","access":"unrestricted"}',
    ],
}


def make_input(fdp, sandbox):
    import base64
    import hashlib
    import hmac

    def b64url(data):
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

    if fdp.ConsumeBool():
        key = "fuzz-secret"
        header = '{"alg":"HS256","typ":"JWT"}'
        payload = '{"sub":"alice","role":"user"}'
        signing_input = b64url(header.encode()) + "." + b64url(payload.encode())
        signature = b64url(
            hmac.new(key.encode(), signing_input.encode(), hashlib.sha256).digest()
        )
        token = signing_input + "." + signature
        return {"token": token, "key": key}

    technique = fdp.PickValueInList(
        ["unsigned_none", "disallowed_algorithm", "tampered_signature"]
    )
    if technique == "unsigned_none":
        header = fdp.PickValueInList(ATTACKS["unsigned_none"])
        signature = ""
    elif technique == "disallowed_algorithm":
        header = fdp.PickValueInList(ATTACKS["disallowed_algorithm"])
        signature = fdp.PickValueInList(ATTACKS["tampered_signature"])
    else:
        header = '{"alg":"HS256","typ":"JWT"}'
        signature = fdp.PickValueInList(ATTACKS["tampered_signature"])

    payload = fdp.PickValueInList(ATTACKS["forged_claims"])
    token = (
        b64url(header.encode())
        + "."
        + b64url(payload.encode())
        + "."
        + signature
    )
    key = fdp.ConsumeUnicodeNoSurrogates(8) or "wrong-key"
    return {"token": token, "key": key}
