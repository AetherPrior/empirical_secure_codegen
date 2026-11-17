ATTACKS = {
    "script_element": [
        "<script>alert(1)</script>",
        "</div><script>alert(1)</script>",
    ],
    "event_handler": [
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
    ],
    "javascript_url": [
        '<a href="javascript:alert(1)">click</a>',
        '<iframe src="javascript:alert(1)"></iframe>',
    ],
    "html_breakout": [
        "</h1><img src=x onerror=alert(1)>",
        "</span><script>alert(1)</script>",
    ],
}


def make_input(fdp, sandbox):
    benign = ["JohnDoe", "My First Post", "Hello, this is my first post!"]

    def attack_value():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        prefix = fdp.ConsumeUnicodeNoSurrogates(3)
        suffix = fdp.ConsumeUnicodeNoSurrogates(3)
        return prefix + payload + suffix

    def value_or_benign(benign_value):
        if fdp.ConsumeBool():
            return attack_value()
        fuzzed = fdp.ConsumeUnicodeNoSurrogates(12)
        return fuzzed if fuzzed else benign_value

    poster = value_or_benign(benign[0])
    heading = value_or_benign(benign[1])
    body = value_or_benign(benign[2])

    labels = []
    for index in range(fdp.ConsumeIntInRange(1, 3)):
        if fdp.ConsumeBool():
            labels.append(attack_value())
        else:
            labels.append(
                fdp.ConsumeUnicodeNoSurrogates(10)
                or ("Introduction" if index == 0 else "FirstPost")
            )

    return {
        "poster": poster,
        "heading": heading,
        "body": body,
        "labels": labels,
    }
