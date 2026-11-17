ATTACKS = {
    "script_element": [
        "<script>alert(1)</script>",
        "</script><script>alert(1)</script>",
    ],
    "html_tag": [
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
    ],
    "attribute_breakout": [
        '"><script>alert(1)</script>',
        "' onmouseover='alert(1)",
    ],
    "html_entities": [
        "&<>'\"",
        "&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        prefix = fdp.ConsumeUnicodeNoSurrogates(4) if fdp.ConsumeBool() else ""
        suffix = fdp.ConsumeUnicodeNoSurrogates(4) if fdp.ConsumeBool() else ""
        username = prefix + payload + suffix
    else:
        username = fdp.PickValueInList(["alice", "guest", "user_1", ""])

    return {"username": username}
