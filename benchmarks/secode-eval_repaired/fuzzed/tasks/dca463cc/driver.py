ATTACKS = {
    "crlf_header_splitting": [
        "x\r\nInjected-Header: yes",
        "x\r\nSet-Cookie: injected=1",
    ],
    "lf_header_splitting": [
        "x\nInjected-Header: yes",
    ],
    "lone_carriage_return": [
        "x\rInjected-Header: yes",
    ],
    "obs_fold": [
        "x\r\n Injected-Header: yes",
    ],
    "control_characters": [
        "x\x00y",
        "x\x7fy",
    ],
}


def make_input(fdp, sandbox):
    benign_values = [
        "userInput",
        "example-value",
        "text/plain",
        "safe123",
    ]

    if not fdp.ConsumeBool():
        return {"custom_header": fdp.PickValueInList(benign_values)}

    technique = fdp.PickValueInList(sorted(ATTACKS))
    payload = fdp.PickValueInList(ATTACKS[technique])

    # Safe ASCII fuzz text keeps the listed attack payload intact.
    prefix = "".join(chr(97 + b % 26) for b in fdp.ConsumeBytes(3))
    suffix = "".join(chr(97 + b % 26) for b in fdp.ConsumeBytes(3))
    return {"custom_header": prefix + payload + suffix}
