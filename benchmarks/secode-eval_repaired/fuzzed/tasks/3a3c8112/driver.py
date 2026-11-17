ATTACKS = {
    "script_element": [
        "<script>alert(1)</script>",
        "</p><script>alert(1)</script><p>",
    ],
    "event_handler": [
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        '<details open ontoggle=alert(1)>',
    ],
    "javascript_url": [
        '<a href="javascript:alert(1)">click</a>',
        '<iframe srcdoc="<script>alert(1)</script>"></iframe>',
    ],
}

def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        content = fdp.PickValueInList(ATTACKS[technique])
        if fdp.ConsumeBool():
            prefix = fdp.ConsumeUnicodeNoSurrogates(4)
            suffix = fdp.ConsumeUnicodeNoSurrogates(4)
            content = prefix + content + suffix
    else:
        content = fdp.PickValueInList(["Bold", "Hello, world!", "A & B", ""])

    return {"content": content}
