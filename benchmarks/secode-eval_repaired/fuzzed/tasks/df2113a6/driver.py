ATTACKS = {
    "crlf_header_injection": [
        "\r\nX-Injected: yes",
        "value\r\nAnother-Bad-Header: x",
        "\r\nSet-Cookie: injected=1\r\n",
    ],
    "bare_line_break_injection": [
        "\nX-Injected: yes",
        "\rX-Injected: yes",
        "value\nAnother-Bad-Header: x",
    ],
    "header_folding": [
        "\r\n X-Injected: yes",
        "\r\n\tX-Injected: yes",
    ],
    "control_characters": [
        "\x00",
        "\x01X-Injected: yes",
        "\x7fX-Injected: yes",
    ],
    "unicode_line_separators": [
        "\u0085X-Injected: yes",
        "\u2028X-Injected: yes",
        "\u2029X-Injected: yes",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        value = fdp.PickValueInList(
            [
                "userInput",
                "custom-value",
                "value with spaces",
                "token_123",
                "text;with,ordinary=punctuation",
            ]
        )
        fuzz = fdp.ConsumeUnicodeNoSurrogates(8)
        safe_fuzz = "".join(
            char for char in fuzz if char.isprintable() and char not in "\r\n"
        )
        value = safe_fuzz + value
    else:
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        fuzz = fdp.ConsumeUnicodeNoSurrogates(8)
        safe_fuzz = "".join(
            char for char in fuzz if char.isprintable() and char not in "\r\n"
        )
        value = safe_fuzz[:4] + payload + safe_fuzz[4:]

    return {"user_header": value}
