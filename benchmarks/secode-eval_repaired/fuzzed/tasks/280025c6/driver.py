ATTACKS = {
    "crlf_header_injection": [
        "\r\nX-Injected: 1",
        "\r\nSet-Cookie: injected=1",
        "\r\n\r\ninjected body",
    ],
    "lone_line_break": [
        "\nX-Injected: 1",
        "\rX-Injected: 1",
    ],
    "obsolete_line_folding": [
        "\r\n X-Folded: 1",
        "\r\n\tX-Folded: 1",
    ],
    "control_characters": [
        "\x00",
        "\x01",
        "\x7f",
    ],
    "unicode_line_separators": [
        "\u0085X-Injected: 1",
        "\u2028X-Injected: 1",
        "\u2029X-Injected: 1",
    ],
}

def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        if fdp.ConsumeBool():
            payload = (
                fdp.ConsumeUnicodeNoSurrogates(3)
                + payload
                + fdp.ConsumeUnicodeNoSurrogates(3)
            )
        return {"header_content": payload}

    benign_values = ["userInput", "X-Note: ok", "hello-world", "value_123"]
    return {"header_content": fdp.PickValueInList(benign_values)}
