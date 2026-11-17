ATTACKS = {
    "script_element": [
        "<script>alert('xss')</script>",
        "<script>document.body.innerHTML='xss'</script>",
    ],
    "event_handler": [
        "<img src=x onerror=alert(1)>",
        "<body onload=alert(1)>",
        "<svg onload=alert(1)>",
    ],
    "tag_breakout": [
        "</div><script>alert(1)</script><div>",
        "\"><img src=x onerror=alert(1)>",
        "'><svg onload=alert(1)>",
    ],
    "javascript_url": [
        "<a href=\"javascript:alert(1)\">click</a>",
        "<iframe src=\"javascript:alert(1)\"></iframe>",
    ],
    "html_edge_cases": [
        "<ScRiPt>alert(1)</ScRiPt>",
        "<!--><script>alert(1)</script>",
        "<svg><script>alert(1)</script></svg>",
    ],
}


def make_input(fdp, sandbox):
    values = {
        "username": "Alice",
        "bio": "Software engineer from xyz.",
        "status_message": "Feeling great!",
    }

    for field in ("username", "bio", "status_message"):
        if fdp.ConsumeBool():
            technique = fdp.PickValueInList(sorted(ATTACKS))
            payload = fdp.PickValueInList(ATTACKS[technique])
            prefix = fdp.ConsumeUnicodeNoSurrogates(4)
            suffix = fdp.ConsumeUnicodeNoSurrogates(4)
            values[field] = prefix + payload + suffix

    return values
