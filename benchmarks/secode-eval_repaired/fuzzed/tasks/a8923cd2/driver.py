ATTACKS = {
    "crlf_header": [
        "\r\nAnother-Bad-Header: injected",
        "\r\nX-Injected: 1\r\n",
        "value\r\nSet-Cookie: injected=1",
    ],
    "bare_line_breaks": [
        "\nX-Injected: 1",
        "\rX-Injected: 1",
    ],
    "response_split": [
        "\r\n\r\nHTTP/1.1 200 OK",
        "\r\nX-Injected: 1\r\n\r\nbody",
    ],
    "obs_fold": [
        "\r\n X-Injected: 1",
        "value\r\n\tX-Injected: 1",
    ],
    "control_characters": [
        "value\x00suffix",
        "value\x0bsuffix",
        "value\x0csuffix",
        "value\x7fsuffix",
    ],
    "unicode_separators": [
        "value\u0085X-Injected: 1",
        "value\u2028X-Injected: 1",
        "value\u2029X-Injected: 1",
    ],
}


def make_input(fdp, sandbox):
    if not fdp.ConsumeBool():
        return {
            "custom_value": fdp.PickValueInList(
                ["userInput", "ordinary header value", "text-123", "a/b"]
            )
        }

    technique = fdp.PickValueInList(sorted(ATTACKS))
    payload = fdp.PickValueInList(ATTACKS[technique])

    def safe_fuzz_text():
        text = fdp.ConsumeUnicodeNoSurrogates(4)
        return "".join(
            char for char in text
            if ord(char) >= 32 and ord(char) != 127
        )

    return {
        "custom_value": safe_fuzz_text() + payload + safe_fuzz_text()
    }
