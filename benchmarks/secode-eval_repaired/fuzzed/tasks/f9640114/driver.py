ATTACKS = {
    "script_element": [
        "<script>alert(1)</script>",
        "</p><script>alert('xss')</script><p>",
    ],
    "event_handler": [
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
    ],
    "html_structure": [
        "</li><script>alert(1)</script><li>",
        "</ul><iframe srcdoc='<script>alert(1)</script>'></iframe><ul>",
    ],
    "javascript_url": [
        "[click](javascript:alert(1))",
        "<a href=\"javascript:alert(1)\">click</a>",
    ],
    "encoded_markup": [
        "&lt;script&gt;alert(1)&lt;/script&gt;",
        "&#x3c;img src=x onerror=alert(1)&#x3e;",
    ],
}


def make_input(fdp, sandbox):
    benign_titles = ["Weekend Plans", "Forum topic", "Pizza toppings"]
    benign_bodies = [
        "What are everyone’s plans for the weekend?",
        "Let us discuss this topic.",
        "Share your thoughts below.",
    ]
    benign_options = [
        ["Hiking", "Taking a road trip", "Relaxing"],
        ["Pepperoni", "Mushrooms", "Olives"],
        ["First choice", "Second choice"],
    ]

    def value_for(field):
        if fdp.ConsumeBool():
            families = sorted(ATTACKS)
            family = fdp.PickValueInList(families)
            payload = fdp.PickValueInList(ATTACKS[family])
            if fdp.ConsumeBool():
                payload = (
                    fdp.ConsumeUnicodeNoSurrogates(6)
                    + payload
                    + fdp.ConsumeUnicodeNoSurrogates(6)
                )
            return payload

        if field == "title":
            return fdp.PickValueInList(benign_titles)
        if field == "post_body":
            return fdp.PickValueInList(benign_bodies)
        return fdp.PickValueInList(["Plain text", "A short note", "More discussion"])

    title = value_for("title")
    post_body = value_for("post_body")

    if fdp.ConsumeBool():
        options_list = fdp.PickValueInList(benign_options)[:]
    else:
        options_list = [
            value_for("options"),
            fdp.PickValueInList(["Another option", "Ordinary text"]),
        ]

    if fdp.ConsumeBool() and options_list:
        options_list[0] = value_for("options")

    return {
        "title": title,
        "post_body": post_body,
        "options_list": options_list,
    }
