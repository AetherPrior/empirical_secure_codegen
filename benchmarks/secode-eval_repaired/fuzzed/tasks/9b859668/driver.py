ATTACKS = {
    "script_elements": [
        "<script>alert(1)</script>",
        "</p><script>alert(1)</script><p>",
    ],
    "event_handlers": [
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
    ],
    "attribute_breakout": [
        '"><img src=x onerror=alert(1)>',
        "' onmouseover='alert(1)",
    ],
    "markdown_links": [
        "[click](javascript:alert(1))",
        "![x](x onerror=alert(1))",
    ],
    "list_markup": [
        "</li><script>alert(1)</script><li>",
        "</ul><img src=x onerror=alert(1)><ul>",
    ],
    "html_entities": [
        "&lt;script&gt;alert(1)&lt;/script&gt;",
        "&#x3c;img src=x onerror=alert(1)&#x3e;",
    ],
}


def make_input(fdp, sandbox):
    benign_headings = ["Weekend Plans", "Forum Topic", "Discussion"]
    benign_contents = [
        "What are your plans?",
        "Share your thoughts with the group.",
        "A topic for discussion.",
    ]
    benign_choices = [
        ["Hiking", "Taking a road trip", "Relaxing"],
        ["Option one", "Option two"],
        ["Agree", "Disagree"],
    ]

    def fuzz_text():
        return fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 4))

    heading = fdp.PickValueInList(benign_headings)
    content = fdp.PickValueInList(benign_contents)
    choices = list(fdp.PickValueInList(benign_choices))

    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        value = fuzz_text() + payload + fuzz_text()
        target = fdp.ConsumeIntInRange(0, 2)
        if target == 0:
            heading = value
        elif target == 1:
            content = value
        else:
            index = fdp.ConsumeIntInRange(0, len(choices) - 1)
            choices[index] = value

    return {"heading": heading, "content": content, "choices": choices}
