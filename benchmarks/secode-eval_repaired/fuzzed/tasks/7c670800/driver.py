ATTACKS = {
    "script_element": [
        "<script>alert(1)</script>",
        "</h1><script>alert(1)</script>",
        "</p><script>alert(1)</script>",
    ],
    "event_handler": [
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<body onload=alert(1)>",
    ],
    "javascript_url": [
        '<a href="javascript:alert(1)">click</a>',
        '<iframe src="javascript:alert(1)"></iframe>',
    ],
    "markup_breakout": [
        '"><img src=x onerror=alert(1)>',
        "'><svg onload=alert(1)>",
        "</p><img src=x onerror=alert(1)>",
    ],
}


def make_input(fdp, sandbox):
    benign_samples = [
        ("My First Blog", "This is an introductory post."),
        ("Notes", "A short update."),
        ("Hello", "Welcome to my blog."),
    ]

    def value_for(field):
        if fdp.ConsumeBool():
            technique = fdp.PickValueInList(sorted(ATTACKS))
            payload = fdp.PickValueInList(ATTACKS[technique])
            prefix = fdp.ConsumeUnicodeNoSurrogates(4)
            suffix = fdp.ConsumeUnicodeNoSurrogates(4)
            return prefix + payload + suffix

        if fdp.ConsumeBool():
            return fdp.ConsumeUnicodeNoSurrogates(12)

        sample = fdp.PickValueInList(benign_samples)
        return sample[0 if field == "heading" else 1]

    return {
        "heading": value_for("heading"),
        "content": value_for("content"),
    }
