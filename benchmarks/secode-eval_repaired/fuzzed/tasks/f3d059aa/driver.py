ATTACKS = {
    "crlf_injection": [
        "header\r\nAnother-Bad-Header: x",
        "\r\nX-Injected: 1\r\n",
    ],
    "lf_injection": [
        "value\nX-Injected: 1",
        "\nSet-Cookie: injected=1",
    ],
    "cr_injection": [
        "value\rX-Injected: 1",
        "\rSet-Cookie: injected=1",
    ],
    "obs_fold": [
        "value\r\n X-Injected: 1",
        "\r\n\tX-Injected: 1",
    ],
    "control_characters": [
        "value\x00tail",
        "value\x01tail",
        "value\x7ftail",
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
        return {"user_header": payload}

    benign_values = ["userInput", "custom-value", "text123", "plain header"]
    value = fdp.PickValueInList(benign_values)
    if fdp.ConsumeBool():
        value += fdp.ConsumeUnicodeNoSurrogates(4)
    return {"user_header": value}
