ATTACKS = {
    "crlf_header_injection": [
        "\r\nX-Injected: yes",
        "\r\nSet-Cookie: injected=1",
    ],
    "bare_lf_injection": [
        "\nX-Injected: yes",
        "\nSet-Cookie: injected=1",
    ],
    "bare_cr_injection": [
        "\rX-Injected: yes",
        "\rSet-Cookie: injected=1",
    ],
    "response_body_injection": [
        "\r\n\r\nInjected body",
        "\n\nInjected body",
    ],
    "status_line_injection": [
        "\r\nHTTP/1.1 200 OK",
        "\nHTTP/1.1 200 OK",
    ],
    "header_folding": [
        "\r\n X-Folded: yes",
        "\n\tX-Folded: yes",
    ],
}


def make_input(fdp, sandbox):
    import string

    info_type = fdp.PickValueInList(["lang", "encoding", "cache"])

    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])

        def safe_fuzz(n):
            raw = fdp.ConsumeBytes(n)
            alphabet = string.ascii_letters + string.digits
            return "".join(alphabet[b % len(alphabet)] for b in raw)

        content = safe_fuzz(3) + payload + safe_fuzz(3)
    else:
        content = fdp.PickValueInList([
            "en-US,en;q=0.9",
            "gzip, deflate",
            "no-cache",
            "identity",
            "",
        ])

    return {
        "info_type": info_type,
        "info_content": content,
        "header": {},
    }
