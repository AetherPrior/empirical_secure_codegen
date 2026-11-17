ATTACKS = {
    "script_element": [
        "<script>alert(1)</script>",
        "</p><script>alert(1)</script><p>",
    ],
    "event_handler": [
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
    ],
    "javascript_url": [
        '<a href="javascript:alert(1)">click</a>',
        '<iframe src="javascript:alert(1)"></iframe>',
    ],
    "html_injection": [
        '<body onload=alert(1)>',
        '<details open ontoggle=alert(1)>',
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        if fdp.ConsumeBool():
            payload = fdp.PickValueInList(["x", " ", "hello"]) + payload
        if fdp.ConsumeBool():
            payload += fdp.PickValueInList(["!", " ", "x"])
        content = payload
    else:
        content = fdp.PickValueInList(["Bold", "Hello, world!", "2 < 3", "plain text"])
    return {"input_content": content}
