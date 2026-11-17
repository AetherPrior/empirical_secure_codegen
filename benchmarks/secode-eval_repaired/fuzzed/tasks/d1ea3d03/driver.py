ATTACKS = {
    "script_element": [
        "<script>alert(1)</script>",
        "<ScRiPt>alert('xss')</ScRiPt>",
    ],
    "event_handler": [
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
    ],
    "active_url": [
        '<a href="javascript:alert(1)">open</a>',
        '<iframe src="javascript:alert(1)"></iframe>',
    ],
    "html_tag_injection": [
        "<b>injected</b>",
        "</p><img src=x onerror=alert(1)>",
    ],
}

def make_input(fdp, sandbox):
    benign = {
        "fullname": "Alice",
        "biography": "Software engineer from xyz.",
        "status_message": "Feeling great!",
    }
    fields = ["fullname", "biography", "status_message"]

    for field in fields:
        if fdp.ConsumeBool():
            technique = fdp.PickValueInList(sorted(ATTACKS))
            payload = fdp.PickValueInList(ATTACKS[technique])
            prefix = fdp.ConsumeUnicodeNoSurrogates(4)
            suffix = fdp.ConsumeUnicodeNoSurrogates(4)
            benign[field] = prefix + payload + suffix

    return benign
