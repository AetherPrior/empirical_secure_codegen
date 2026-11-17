ATTACKS = {
    "script_elements": [
        "<script>alert(1)</script>",
        "</p><img src=x onerror=alert(1)>",
        "<svg/onload=alert(1)>",
    ],
    "attribute_breakout": [
        '" onmouseover="alert(1)',
        "'><iframe src=javascript:alert(1)>",
        '"><body onload=alert(1)>',
    ],
    "javascript_urls": [
        '<a href="javascript:alert(1)">click</a>',
        "[click](javascript:alert(1))",
    ],
    "markdown_html": [
        "<details open ontoggle=alert(1)>x</details>",
        "<!-- --><script>alert(1)</script>",
    ],
    "entity_encoded_markup": [
        "&lt;script&gt;alert(1)&lt;/script&gt;",
        "&#x3C;img src=x onerror=alert(1)&#x3E;",
    ],
}


def make_input(fdp, sandbox):
    benign_titles = ["Weekend Plans", "Forum topic", "Favorite recipes"]
    benign_bodies = [
        "What are your plans for the weekend?",
        "Share your thoughts with the group.",
        "Which option do you prefer?",
    ]
    benign_points = ["Hiking", "Taking a road trip", "Relaxing", "Option one"]

    def value(benign_values):
        if fdp.ConsumeBool():
            return fdp.PickValueInList(benign_values)

        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        if fdp.ConsumeBool():
            return (
                fdp.ConsumeUnicodeNoSurrogates(6)
                + payload
                + fdp.ConsumeUnicodeNoSurrogates(6)
            )
        return payload

    post_title = value(benign_titles)
    post_body = value(benign_bodies)

    bullet_points = []
    for _ in range(fdp.ConsumeIntInRange(1, 3)):
        bullet_points.append(value(benign_points))

    return {
        "post_title": post_title,
        "post_body": post_body,
        "bullet_points": bullet_points,
    }
