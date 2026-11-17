ATTACKS = {
    "script_element": [
        "<script>alert(1)</script>",
        "<ScRiPt>alert('xss')</sCrIpT>",
        "</textarea><script>alert(1)</script>",
    ],
    "event_handler": [
        "<img src=x onerror=alert(1)>",
        "<svg/onload=alert(1)>",
        "<body onload=alert(1)>",
    ],
    "javascript_url": [
        '<a href="javascript:alert(1)">click</a>',
        '<iframe src="javascript:alert(1)">',
    ],
    "html_breakout": [
        '"><script>alert(1)</script>',
        "'><img src=x onerror=alert(1)>",
    ],
}


def make_input(fdp, sandbox):
    if not fdp.ConsumeBool():
        return {
            "comment": fdp.PickValueInList(
                ["User comment", "Hello, world!", "Nice post."]
            )
        }

    technique = fdp.PickValueInList(sorted(ATTACKS))
    payload = fdp.PickValueInList(ATTACKS[technique])

    # Usually keep the payload intact; sometimes surround it with fuzz text.
    if fdp.ConsumeBool():
        prefix = fdp.ConsumeUnicodeNoSurrogates(4)
        suffix = fdp.ConsumeUnicodeNoSurrogates(4)
        payload = prefix + payload + suffix

    return {"comment": payload}
