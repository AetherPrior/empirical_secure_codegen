ATTACKS = {
    "script_element": [
        "<script>alert(1)</script>",
        "</p><script>alert(1)</script><p>",
    ],
    "event_handler": [
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<details open ontoggle=alert(1)>x</details>",
    ],
    "javascript_url": [
        '<a href="javascript:alert(1)">click</a>',
        '<iframe src="javascript:alert(1)"></iframe>',
    ],
}

def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        prefix = fdp.ConsumeUnicodeNoSurrogates(4)
        suffix = fdp.ConsumeUnicodeNoSurrogates(4)
        page_content = prefix + payload + suffix
    else:
        page_content = fdp.PickValueInList([
            "",
            "Bold",
            "Hello, world!",
            "A & B",
            "plain text 123",
            "café",
        ])
    return {"page_content": page_content}
