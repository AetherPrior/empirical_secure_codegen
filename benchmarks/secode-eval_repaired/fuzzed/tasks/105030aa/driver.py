ATTACKS = {
    "crlf_header_injection": [
        "\r\nAnother-Bad-Header: injected",
        "\r\nSet-Cookie: injected=1",
        "x\r\nInjected: 1",
    ],
    "bare_line_breaks": [
        "\nInjected: 1",
        "\rInjected: 1",
    ],
    "obsolete_line_folding": [
        "value\r\n Injected: 1",
        "value\r\n\tInjected: 1",
    ],
    "control_characters": [
        "value\x00Injected",
        "value\x1fInjected",
        "value\x7fInjected",
    ],
    "unicode_line_separators": [
        "value\u0085Injected: 1",
        "value\u2028Injected: 1",
        "value\u2029Injected: 1",
    ],
}


def make_input(fdp, sandbox):
    if not fdp.ConsumeBool():
        return {
            "header_value": fdp.PickValueInList(
                ["userInput", "text/plain", "safe-value", "a=b; c=d"]
            )
        }

    technique = fdp.PickValueInList(sorted(ATTACKS))
    payload = fdp.PickValueInList(ATTACKS[technique])

    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    raw = fdp.ConsumeBytes(4)
    prefix = "".join(alphabet[b % len(alphabet)] for b in raw[:2])
    suffix = "".join(alphabet[b % len(alphabet)] for b in raw[2:])
    return {"header_value": prefix + payload + suffix}
