ATTACKS = {
    "scheme_and_authority": [
        "http://127.0.0.1",
        "https://localhost",
        "//169.254.169.254/latest/meta-data/",
    ],
    "userinfo_authority": [
        "@127.0.0.1",
        "user@localhost",
    ],
    "path_manipulation": [
        "../admin",
        "/../admin",
        "a/b",
    ],
    "query_and_fragment": [
        "?url=http://127.0.0.1",
        "#@localhost",
    ],
    "encoded_delimiters": [
        "%2f%2f127.0.0.1",
        "%40localhost",
    ],
}


def make_input(fdp, sandbox):
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

    def fuzz_text(max_len):
        raw = fdp.ConsumeBytes(max_len)
        return "".join(alphabet[b % len(alphabet)] for b in raw)

    api_samples = [
        "https://example.com/api/user",
        "http://api.example.test/v1/users",
        "",
    ]
    api_url = fdp.PickValueInList(api_samples)
    if fdp.ConsumeBool():
        api_url += fuzz_text(6)

    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        user_id = fuzz_text(3) + payload + fuzz_text(3)
    else:
        user_id = fdp.PickValueInList(["aBc123", "user7", "42", ""])

    return {"api_url": api_url, "user_id": user_id}
