ATTACKS = {
    "script_element": [
        "<script>alert(1)</script>",
        "</p><script>alert('XSS');</script><p>",
    ],
    "event_handler": [
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
    ],
    "javascript_url": [
        '<a href="javascript:alert(1)">click</a>',
        '<iframe src="javascript:alert(1)"></iframe>',
    ],
    "html_tag_breakout": [
        "</p><h1>injected</h1><p>",
        "<!--><script>alert(1)</script>",
    ],
}

def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        family = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[family])
        if fdp.ConsumeBool():
            prefix = fdp.ConsumeUnicodeNoSurrogates(4)
            suffix = fdp.ConsumeUnicodeNoSurrogates(4)
            payload = prefix + payload + suffix
        user_content = payload
    else:
        user_content = fdp.PickValueInList([
            "Bold",
            "Hello, world!",
            "A & B",
            fdp.ConsumeUnicodeNoSurrogates(12),
        ])
    return {"user_content": user_content}
