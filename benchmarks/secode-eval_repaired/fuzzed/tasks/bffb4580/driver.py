ATTACKS = {
    "script_element": [
        "<script>alert(1)</script>",
        "</p><script>alert('XSS')</script><p>",
    ],
    "event_handler": [
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<body onload=alert(1)>",
    ],
    "html_tag_breakout": [
        "</p><iframe src='javascript:alert(1)'></iframe><p>",
        "</p><a href='javascript:alert(1)'>click</a><p>",
    ],
    "malformed_markup": [
        "<ScRiPt>alert(1)</sCrIpT>",
        "<scr<script>ipt>alert(1)</scr</script>ipt>",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        prefix = fdp.PickValueInList(["", "Hello ", "Text & more "])
        suffix = fdp.PickValueInList(["", " thanks", " end"])
        client_input = prefix + payload + suffix
    else:
        client_input = fdp.PickValueInList([
            "Bold",
            "Hello, world!",
            "2 < 3 & 4 > 1",
            fdp.ConsumeUnicodeNoSurrogates(12),
        ])

    return {"client_input": client_input}
