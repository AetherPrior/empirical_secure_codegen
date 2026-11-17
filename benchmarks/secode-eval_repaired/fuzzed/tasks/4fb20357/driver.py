ATTACKS = {
    "script_element": [
        "<script>alert(1)</script>",
        "</h1><script>alert(1)</script>",
        "</p><script>alert(1)</script>",
    ],
    "event_handler_element": [
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<body onload=alert(1)>",
    ],
    "svg_and_mathml": [
        "<svg><script>alert(1)</script></svg>",
        "<math><mtext></mtext><img src=x onerror=alert(1)></math>",
    ],
    "case_and_whitespace_variants": [
        "<ScRiPt>alert(1)</ScRiPt>",
        "<img src=x onerror = alert(1)>",
        "<svg/onload=alert(1)>",
    ],
    "markup_breakout": [
        "</p><img src=x onerror=alert(1)>",
        "</h1><svg onload=alert(1)>",
    ],
}

def make_input(fdp, sandbox):
    benign_headings = [
        "My First Blog",
        "Travel Notes",
        "A Short Update",
    ]
    benign_descriptions = [
        "This is an introductory post.",
        "A few notes from today.",
        "Thanks for reading.",
    ]

    def choose_value(benign_values):
        if fdp.ConsumeBool():
            technique = fdp.PickValueInList(sorted(ATTACKS))
            payload = fdp.PickValueInList(ATTACKS[technique])
            if fdp.ConsumeBool():
                prefix = fdp.ConsumeUnicodeNoSurrogates(4)
                payload = prefix + payload
            if fdp.ConsumeBool():
                suffix = fdp.ConsumeUnicodeNoSurrogates(4)
                payload += suffix
            return payload
        return fdp.PickValueInList(benign_values)

    return {
        "heading": choose_value(benign_headings),
        "description": choose_value(benign_descriptions),
    }
