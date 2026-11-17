ATTACKS = {
    "path_injection": [
        "../admin",
        "../../internal",
        "users/../../admin",
        "/admin",
    ],
    "query_injection": [
        "?url=http://127.0.0.1/",
        "?url=http://169.254.169.254/latest/meta-data/",
        "&redirect=http://127.0.0.1/",
    ],
    "authority_injection": [
        "//127.0.0.1",
        "//169.254.169.254",
        "http://127.0.0.1/",
        "gopher://127.0.0.1:6379/",
    ],
    "encoded_delimiters": [
        "%2f%2f127.0.0.1",
        "%3furl=http%3a%2f%2f127.0.0.1",
        "%252f%252f169.254.169.254",
    ],
    "fragment_injection": [
        "#@127.0.0.1",
        "#/../../admin",
    ],
    "control_characters": [
        "id\r\nX-Forwarded-Host: 127.0.0.1",
        "id\nLocation: http://127.0.0.1/",
    ],
}


def make_input(fdp, sandbox):
    benign_api_urls = [
        "https://example.com/api/user",
        "http://localhost:8080/api/user",
        "https://service.internal/users",
    ]
    benign_user_ids = ["aBc123", "user7", "42", ""]

    api_url = fdp.PickValueInList(benign_api_urls)

    if fdp.ConsumeBool():
        family = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[family])
        if fdp.ConsumeBool():
            fuzz = fdp.ConsumeUnicodeNoSurrogates(4).replace("\x00", "")
            if fdp.ConsumeBool():
                payload = fuzz + payload
            else:
                payload = payload + fuzz
        user_id = payload
    else:
        user_id = fdp.PickValueInList(benign_user_ids)

    return {"api_url": api_url, "user_id": user_id}
