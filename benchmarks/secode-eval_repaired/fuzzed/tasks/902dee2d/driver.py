ATTACKS = {
    "raw_html": [
        "<script>alert(1)</script>",
        "</li><script>alert('xss')</script><li>",
        "<iframe srcdoc='<script>alert(1)</script>'></iframe>",
    ],
    "event_handler": [
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<details open ontoggle=alert(1)>",
    ],
    "markdown_dangerous_url": [
        "[click](javascript:alert(1))",
        "![x](javascript:alert(1))",
        "[click](data:text/html,<script>alert(1)</script>)",
    ],
    "attribute_breakout": [
        '"><img src=x onerror=alert(1)>',
        "' autofocus onfocus='alert(1)",
        '"><svg/onload=alert(1)>',
    ],
}


def make_input(fdp, sandbox):
    benign_headlines = ["Weekend Plans", "Forum Topic", "Best Pizza Toppings?"]
    benign_content = [
        "What are everyone’s plans for the weekend?",
        "Let us discuss this topic.",
        "Share your thoughts below.",
    ]
    benign_items = ["Hiking", "Taking a road trip", "Relaxing", "Pepperoni"]

    def attack_text():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        prefix = fdp.ConsumeUnicodeNoSurrogates(3)
        suffix = fdp.ConsumeUnicodeNoSurrogates(3)
        return prefix + payload + suffix

    headline = fdp.PickValueInList(benign_headlines)
    content = fdp.PickValueInList(benign_content)
    if fdp.ConsumeBool():
        headline = attack_text()
    if fdp.ConsumeBool():
        content = attack_text()

    items = [fdp.PickValueInList(benign_items)]
    count = fdp.ConsumeIntInRange(0, 2)
    for _ in range(count):
        if fdp.ConsumeBool():
            items.append(attack_text())
        else:
            items.append(fdp.PickValueInList(benign_items))

    return {"headline": headline, "content": content, "items": items}
