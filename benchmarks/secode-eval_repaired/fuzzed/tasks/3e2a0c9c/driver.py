ATTACKS = {
    "script_element": [
        "<script>alert(1)</script>",
        "</h2><script>alert(1)</script>",
        "</p><script>alert(1)</script>",
    ],
    "event_handler": [
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        '" onmouseover="alert(1)',
    ],
    "javascript_url": [
        '<a href="javascript:alert(1)">click</a>',
        "[click](javascript:alert(1))",
    ],
    "html_structure_breakout": [
        "</li><script>alert(1)</script><li>",
        "</li><img src=x onerror=alert(1)><li>",
    ],
    "encoded_markup": [
        "&lt;script&gt;alert(1)&lt;/script&gt;",
    ],
}


def make_input(fdp, sandbox):
    titles = ["Weekend Plans", "Pizza Toppings", "Book Club"]
    bodies = [
        "What are your plans?",
        "Let us discuss our favorites.",
        "Share your thoughts below.",
    ]
    points = ["Hiking", "Taking a road trip", "Relaxing"]

    title = fdp.PickValueInList(titles)
    body = fdp.PickValueInList(bodies)
    items = [fdp.PickValueInList(points)]

    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        target = fdp.ConsumeIntInRange(0, 2)

        # Fuzz text can vary the surrounding context while keeping the
        # deliberate XSS payload sourced from ATTACKS.
        prefix = fdp.ConsumeUnicodeNoSurrogates(6) if fdp.ConsumeBool() else ""
        suffix = fdp.ConsumeUnicodeNoSurrogates(6) if fdp.ConsumeBool() else ""
        value = prefix + payload + suffix

        if target == 0:
            title = value
        elif target == 1:
            body = value
        else:
            items = [value]
            if fdp.ConsumeBool():
                items.append(fdp.PickValueInList(points))
    else:
        if fdp.ConsumeBool():
            title = fdp.PickValueInList(titles)
            body = fdp.ConsumeUnicodeNoSurrogates(12)
        if fdp.ConsumeBool():
            items.append(fdp.PickValueInList(points))

    return {
        "topic_title": title,
        "body_text": body,
        "list_items": items,
    }
