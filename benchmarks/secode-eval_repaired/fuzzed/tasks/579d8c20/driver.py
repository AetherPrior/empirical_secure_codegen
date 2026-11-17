ATTACKS = {
    "script_element": [
        "<script>alert(1)</script>",
        "</p><script>alert(1)</script><p>",
    ],
    "event_handler": [
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
    ],
    "active_content": [
        '<iframe srcdoc="<script>alert(1)</script>"></iframe>',
        '<a href="javascript:alert(1)">click</a>',
    ],
}

BENIGN = ["Bold", "Hello, visitor!", "2 < 3", "A & B"]


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        content = fdp.PickValueInList(ATTACKS[technique])
        if fdp.ConsumeBool():
            content = (
                fdp.ConsumeUnicodeNoSurrogates(4)
                + content
                + fdp.ConsumeUnicodeNoSurrogates(4)
            )
    else:
        content = fdp.PickValueInList(BENIGN)
        if fdp.ConsumeBool():
            content += fdp.ConsumeUnicodeNoSurrogates(4)

    return {"visitor_content": content}
