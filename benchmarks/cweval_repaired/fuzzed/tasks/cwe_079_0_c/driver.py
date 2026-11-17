ATTACKS = {
    "script_element": [
        "<script>alert(1)</script>",
        "</script><script>alert(1)</script>",
    ],
    "event_handler": [
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<body onpageshow=alert(1)>",
    ],
    "attribute_breakout": [
        '"><script>alert(1)</script>',
        "'><img src=x onerror=alert(1)>",
    ],
    "javascript_uri": [
        '<a href="javascript:alert(1)">click</a>',
        '<iframe src="javascript:alert(1)"></iframe>',
    ],
}


def make_input(fdp, sandbox):
    benign = ["Alice", "user_42", "", "hello world", "こんにちは"]

    if not fdp.ConsumeBool():
        return {"username": fdp.PickValueInList(benign)}

    technique = fdp.PickValueInList(sorted(ATTACKS))
    payload = fdp.PickValueInList(ATTACKS[technique])

    if fdp.ConsumeBool():
        before = fdp.ConsumeUnicodeNoSurrogates(4).replace("\x00", "")
        after = fdp.ConsumeUnicodeNoSurrogates(4).replace("\x00", "")
        payload = before + payload + after

    return {"username": payload}
