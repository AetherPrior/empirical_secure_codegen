ATTACKS = {
    "script_element": [
        "<script>alert(1)</script>",
        "</p><script>alert(1)</script>",
    ],
    "event_handler": [
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<details open ontoggle=alert(1)>",
    ],
    "embedded_document": [
        '<iframe srcdoc="<script>alert(1)</script>"></iframe>',
    ],
    "javascript_url": [
        '<a href="javascript:alert(1)">click</a>',
    ],
    "malformed_tag": [
        '"><svg/onload=alert(1)>',
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        family = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[family])
        prefix = fdp.ConsumeUnicodeNoSurrogates(4) if fdp.ConsumeBool() else ""
        suffix = fdp.ConsumeUnicodeNoSurrogates(4) if fdp.ConsumeBool() else ""
        user_input = prefix + payload + suffix
    else:
        user_input = fdp.PickValueInList(["Bold", "Hello, world!", "", "5 < 7"])
        if fdp.ConsumeBool():
            user_input += fdp.ConsumeUnicodeNoSurrogates(8)

    return {"user_input": user_input}
