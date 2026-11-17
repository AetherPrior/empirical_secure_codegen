ATTACKS = {
    "crlf_header_injection": [
        "\r\nX-Injected: yes",
        "value\r\nSet-Cookie: injected=1",
        "\r\n\r\nHTTP/1.1 200 OK",
    ],
    "bare_lf_injection": [
        "\nX-Injected: yes",
        "value\nSet-Cookie: injected=1",
    ],
    "bare_cr_injection": [
        "\rX-Injected: yes",
        "value\rSet-Cookie: injected=1",
    ],
    "obs_fold": [
        "\r\n X-Injected: yes",
        "\n\tX-Injected: yes",
    ],
    "control_characters": [
        "\x00",
        "value\x01suffix",
        "value\x7fsuffix",
    ],
    "unicode_line_separators": [
        "value\u2028X-Injected: yes",
        "value\u2029X-Injected: yes",
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
        safe_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 -_"
        data = fdp.ConsumeBytes(8)
        value = "".join(safe_chars[b % len(safe_chars)] for b in data)
        if not value:
            value = fdp.PickValueInList(["userInput", "custom-value", "hello world"])

    return {"custom_header_value": value}
