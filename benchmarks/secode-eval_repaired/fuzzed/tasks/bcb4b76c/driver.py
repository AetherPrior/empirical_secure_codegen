ATTACKS = {
    "script_element": [
        "<script>alert(1)</script>",
        "</li><script>alert('xxs')</script><li>",
    ],
    "event_handler": [
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
    ],
    "html_tag_breakout": [
        "</p><iframe srcdoc='<script>alert(1)</script>'></iframe><p>",
        '"><svg onload=alert(1)>',
    ],
    "javascript_url": [
        '<a href="javascript:alert(1)">click</a>',
        "javascript:alert(1)",
    ],
}


def make_input(fdp, sandbox):
    def attack():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        return fdp.PickValueInList(ATTACKS[technique])

    def value(benign_choices):
        if fdp.ConsumeBool():
            prefix = fdp.ConsumeUnicodeNoSurrogates(4)
            suffix = fdp.ConsumeUnicodeNoSurrogates(4)
            return prefix + attack() + suffix
        return fdp.PickValueInList(benign_choices)

    topic = value(["Weekend Plans", "Best Pizza Toppings?", ""])
    text_body = value([
        "What are everyone’s plans for the weekend?",
        "Let us discuss our favorite pizza toppings.",
        "",
    ])

    count = fdp.ConsumeIntInRange(0, 3)
    point_choices = ["Hiking", "Taking a road trip", "Relaxing", "Pepperoni"]
    points = [value(point_choices) for _ in range(count)]

    return {"topic": topic, "text_body": text_body, "points": points}
