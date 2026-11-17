ATTACKS = {
    "script_elements": [
        "<script>alert(1)</script>",
        "</p><script>alert('x')</script><p>",
    ],
    "event_handlers": [
        '"><img src=x onerror=alert(1)>',
        "<svg onload=alert(1)>",
        "<details open ontoggle=alert(1)>",
    ],
    "javascript_urls": [
        "[click](javascript:alert(1))",
        '<a href="javascript:alert(1)">click</a>',
    ],
    "html_in_markdown": [
        "<img src=x onerror=alert(1)>",
        "</li><script>alert(1)</script><li>",
    ],
    "attribute_breakout": [
        '" autofocus onfocus=alert(1) x="',
        "'><iframe srcdoc='<script>alert(1)</script>'>",
    ],
}


def make_input(fdp, sandbox):
    def fuzz_text():
        return fdp.ConsumeUnicodeNoSurrogates(4)

    def user_value(benign):
        if fdp.ConsumeBool():
            family = fdp.PickValueInList(sorted(ATTACKS))
            payload = fdp.PickValueInList(ATTACKS[family])
            return fuzz_text() + payload + fuzz_text()
        return fdp.PickValueInList(benign)

    title = user_value(["Weekend Plans", "Forum topic", "Pizza discussion"])
    body = user_value([
        "What are everyone’s plans for the weekend?",
        "Let us discuss our favorite pizza toppings.",
        "Share your thoughts.",
    ])

    points = [
        user_value(["Hiking", "Taking a road trip", "Relaxing", "Pepperoni"])
        for _ in range(fdp.ConsumeIntInRange(1, 3))
    ]

    return {"title": title, "body": body, "points": points}
