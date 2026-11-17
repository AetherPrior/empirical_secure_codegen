ATTACKS = {
    "script_element": [
        "<script>alert(1)</script>",
        "</title><script>alert(1)</script>",
    ],
    "event_handler": [
        '"><img src=x onerror=alert(1)>',
        "' onmouseover='alert(1)'",
    ],
    "svg": [
        "<svg onload=alert(1)>",
        "</div><svg><script>alert(1)</script>",
    ],
    "html_injection": [
        "<iframe src=javascript:alert(1)>",
        "<a href=javascript:alert(1)>click</a>",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        if fdp.ConsumeBool():
            payload = (
                fdp.ConsumeUnicodeNoSurrogates(4)
                + payload
                + fdp.ConsumeUnicodeNoSurrogates(4)
            )
        username = payload
    else:
        username = fdp.PickValueInList([
            "Alice",
            "user_42",
            "welcome",
            "plain-text",
            fdp.ConsumeUnicodeNoSurrogates(8),
        ])

    return {"username": username}
