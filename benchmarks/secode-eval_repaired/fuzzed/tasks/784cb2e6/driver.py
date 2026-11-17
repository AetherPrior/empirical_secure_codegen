ATTACKS = {
    "script_element": [
        "<script>alert(1)</script>",
        "</li><script>alert('xxs')</script><li>",
    ],
    "event_handler": [
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
    ],
    "javascript_url": [
        '<a href="javascript:alert(1)">click</a>',
        "[click](javascript:alert(1))",
    ],
    "embedded_html": [
        '<iframe srcdoc="<script>alert(1)</script>"></iframe>',
        "<details open ontoggle=alert(1)>x</details>",
    ],
}


def make_input(fdp, sandbox):
    benign_titles = ["Weekend Plans", "Favorite Books", "Pizza Toppings"]
    benign_bodies = [
        "What are your plans for the weekend?",
        "Share your thoughts with the group.",
        "Which option do you prefer?",
    ]
    benign_topics = ["Hiking", "Taking a road trip", "Relaxing", "Reading"]

    def payload():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        return fdp.PickValueInList(ATTACKS[technique])

    def content(benign_values):
        if fdp.ConsumeBool():
            return payload()
        return fdp.PickValueInList(benign_values)

    title = content(benign_titles)
    body = content(benign_bodies)

    topics = []
    count = fdp.ConsumeIntInRange(1, 3)
    for _ in range(count):
        if fdp.ConsumeBool():
            text = payload()
            if fdp.ConsumeBool():
                text = fdp.ConsumeUnicodeNoSurrogates(4) + text
            if fdp.ConsumeBool():
                text += fdp.ConsumeUnicodeNoSurrogates(4)
            topics.append(text)
        else:
            topics.append(fdp.PickValueInList(benign_topics))

    return {"title": title, "body": body, "topics": topics}
