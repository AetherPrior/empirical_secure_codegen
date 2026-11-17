ATTACKS = {
    "script_tag": [
        "<script>alert(1)</script>",
        "<ScRiPt>alert(1)</sCrIpT>",
    ],
    "event_handler": [
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<body onload=alert(1)>",
    ],
    "svg_payload": [
        "<svg><script>alert(1)</script></svg>",
        "<svg/onload=alert(1)>",
    ],
    "tag_breakout": [
        "</h1><script>alert(1)</script>",
        "</p><img src=x onerror=alert(1)>",
        "x</title><script>alert(1)</script>",
    ],
    "javascript_uri": [
        '<a href="javascript:alert(1)">click</a>',
        '<iframe src="javascript:alert(1)">',
    ],
}


def make_input(fdp, sandbox):
    benign_headings = ["My First Blog", "A short post", "Notes"]
    benign_texts = [
        "This is an introductory post.",
        "Plain text for a blog post.",
        "Hello, world!",
    ]

    def value_for(benign_values):
        if not fdp.ConsumeBool():
            return fdp.PickValueInList(benign_values)

        family = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[family])
        if fdp.ConsumeBool():
            prefix = fdp.ConsumeUnicodeNoSurrogates(4)
            suffix = fdp.ConsumeUnicodeNoSurrogates(4)
            return prefix + payload + suffix
        return payload

    return {
        "heading": value_for(benign_headings),
        "text": value_for(benign_texts),
    }
