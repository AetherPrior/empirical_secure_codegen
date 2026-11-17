ATTACKS = {
    "crlf_header": [
        "\r\nX-Injected: yes",
        "header\r\nAnother-Bad-Header: yes",
    ],
    "crlf_multiple_headers": [
        "\r\nX-One: 1\r\nX-Two: 2",
    ],
    "crlf_body_boundary": [
        "\r\n\r\nInjected body",
    ],
    "bare_lf": [
        "\nX-Injected: yes",
        "header\nAnother-Bad-Header: yes",
    ],
    "bare_cr": [
        "\rX-Injected: yes",
        "header\rAnother-Bad-Header: yes",
    ],
    "obs_fold": [
        "\r\n X-Folded: yes",
        "\r\n\tX-Folded: yes",
    ],
    "control_characters": [
        "\x00X-Injected: yes",
        "\x1fX-Injected: yes",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        prefix = fdp.ConsumeUnicodeNoSurrogates(3)
        suffix = fdp.ConsumeUnicodeNoSurrogates(3)
        value = prefix + payload + suffix
    else:
        value = fdp.PickValueInList(["userInput", "Content-Type: text/plain", ""])
    return {"response_header": value}
