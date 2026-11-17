ATTACKS = {
    "script_tag": [
        "<script>alert(1)</script>",
        "<script>confirm('xss')</script>",
    ],
    "html_tag_breakout": [
        "</p><script>alert(1)</script>",
        "<h1>Injected</h1>",
    ],
    "event_handler": [
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
    ],
    "javascript_url": [
        '<a href="javascript:alert(1)">open</a>',
    ],
    "html_entity": [
        "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",
    ],
}


def make_input(fdp, sandbox):
    fields = ["title", "description", "date", "notes"]
    values = {
        "title": "Tech Conference",
        "description": "Discuss the future of AI.",
        "date": "2023-11-02",
        "notes": "Keynote by Dr. Alan.",
    }

    for field in fields:
        if fdp.ConsumeBool():
            technique = fdp.PickValueInList(sorted(ATTACKS))
            payload = fdp.PickValueInList(ATTACKS[technique])
            prefix = fdp.ConsumeUnicodeNoSurrogates(4)
            suffix = fdp.ConsumeUnicodeNoSurrogates(4)
            values[field] = prefix + payload + suffix
        elif fdp.ConsumeBool():
            values[field] += fdp.ConsumeUnicodeNoSurrogates(6)

    return values
