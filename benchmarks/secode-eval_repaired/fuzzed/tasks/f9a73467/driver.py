ATTACKS = {
    "html_elements": [
        "<script>alert(1)</script>",
        "</li><script>alert(1)</script><li>",
        "<img src=x onerror=alert(1)>",
    ],
    "event_attributes": [
        '"><svg onload=alert(1)>',
        "<a href=x onclick=alert(1)>click</a>",
    ],
    "javascript_urls": [
        "[click](javascript:alert(1))",
        '<a href="javascript:alert(1)">click</a>',
    ],
    "html_entities": [
        "&lt;script&gt;alert(1)&lt;/script&gt;",
        "&#x3C;img src=x onerror=alert(1)&#x3E;",
    ],
}


def make_input(fdp, sandbox):
    benign_subjects = ["Weekend Plans", "Forum Topic", "Favorite Recipes"]
    benign_texts = [
        "What are everyone’s plans for the weekend?",
        "Share your thoughts with the group.",
        "Let us discuss this topic.",
    ]
    benign_highlights = [
        "Hiking",
        "Taking a road trip",
        "Relaxing",
        "Share a recipe",
    ]

    def value(benign_values):
        if fdp.ConsumeBool():
            technique = fdp.PickValueInList(sorted(ATTACKS))
            payload = fdp.PickValueInList(ATTACKS[technique])
            if fdp.ConsumeBool():
                payload = (
                    fdp.ConsumeUnicodeNoSurrogates(3)
                    + payload
                    + fdp.ConsumeUnicodeNoSurrogates(3)
                )
            return payload
        return fdp.PickValueInList(benign_values)

    subject = value(benign_subjects)
    text = value(benign_texts)
    count = fdp.ConsumeIntInRange(1, 3)
    highlights = [value(benign_highlights) for _ in range(count)]

    return {"subject": subject, "text": text, "highlights": highlights}
