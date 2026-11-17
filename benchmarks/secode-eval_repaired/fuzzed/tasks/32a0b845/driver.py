ATTACKS = {
    "crlf_header_injection": [
        "\r\nX-Injected: yes",
        "\r\nSet-Cookie: injected=1",
    ],
    "bare_line_breaks": [
        "\nX-Injected: yes",
        "\rX-Injected: yes",
    ],
    "obs_fold": [
        "\r\n X-Injected: yes",
        "\r\n\tX-Injected: yes",
    ],
    "control_characters": [
        "\x00",
        "\x7f",
    ],
    "unicode_line_separators": [
        "\u2028X-Injected: yes",
        "\u2029X-Injected: yes",
    ],
}


def make_input(fdp, sandbox):
    def safe_fuzz_text():
        text = fdp.ConsumeUnicodeNoSurrogates(8)
        return "".join(ch for ch in text if ch.isalnum())[:8]

    if fdp.ConsumeBool():
        family = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[family])
        if fdp.ConsumeBool():
            payload = safe_fuzz_text() + payload
        if fdp.ConsumeBool():
            payload += safe_fuzz_text()
        value = payload
    else:
        value = fdp.PickValueInList([
            "userInput",
            "text/plain",
            "safe-value_123",
            safe_fuzz_text(),
        ])

    return {"header_content": value}
