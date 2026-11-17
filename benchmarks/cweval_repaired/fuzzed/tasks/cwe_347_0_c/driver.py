ATTACKS = {
    "forged_hs256": [
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJyb290IiwiYWRtaW4iOnRydWV9.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQ",
    ],
    "unsigned_none": [
        "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.",
    ],
    "unverified_other_algorithm": [
        "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    ],
}


def make_input(fdp, sandbox):
    import base64
    import hashlib
    import hmac
    import json

    def b64url(data):
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

    if fdp.ConsumeBool():
        family = fdp.PickValueInList(sorted(ATTACKS))
        token = fdp.PickValueInList(ATTACKS[family])
        key = fdp.PickValueInList(["secret", "wrong-key", "test-key"])
        return {"token": token, "key": key}

    key = fdp.PickValueInList(["benign-key", "test-secret"])
    header = b64url(b'{"alg":"HS256","typ":"JWT"}')
    payload = b64url(b'{"sub":"alice","role":"user"}')
    signing_input = (header + "." + payload).encode("ascii")
    signature = hmac.new(key.encode("utf-8"), signing_input, hashlib.sha256).digest()
    token = header + "." + payload + "." + b64url(signature)
    return {"token": token, "key": key}
