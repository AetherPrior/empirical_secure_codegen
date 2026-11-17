ATTACKS = {
    "script_element": [
        "<script>alert(1)</script>",
        "<ScRiPt>confirm(1)</sCrIpT>",
    ],
    "html_event_handler": [
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
    ],
    "html_tag_breakout": [
        "</p><script>alert(1)</script><p>",
        "</h2><iframe srcdoc=alert(1)>",
    ],
    "javascript_url": [
        "<a href=\"javascript:alert(1)\">click</a>",
        "<iframe src=\"javascript:alert(1)\"></iframe>",
    ],
    "html_character_references": [
        "&lt;script&gt;alert(1)&lt;/script&gt;",
        "&#x3C;img src=x onerror=alert(1)&#x3E;",
    ],
}


def make_input(fdp, sandbox):
    values = [
        "Charity Gala",
        "A formal event to support our community.\nJoin us for an evening together.",
        "2023-12-12",
        "Dress code: business formal.",
    ]

    for index in range(len(values)):
        if fdp.ConsumeBool():
            technique = fdp.PickValueInList(sorted(ATTACKS))
            payload = fdp.PickValueInList(ATTACKS[technique])
            prefix = fdp.ConsumeUnicodeNoSurrogates(3)
            suffix = fdp.ConsumeUnicodeNoSurrogates(3)
            values[index] = prefix + payload + suffix

    return {
        "title_of_event": values[0],
        "details_of_event": values[1],
        "when_event_is": values[2],
        "extra_event_info": values[3],
    }
