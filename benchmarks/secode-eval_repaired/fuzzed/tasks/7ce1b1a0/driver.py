ATTACKS = {
    "script_element": [
        "<script>alert(1)</script>",
        "</br><script>alert('xss')</script>",
    ],
    "event_handler_element": [
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<details open ontoggle=alert(1)>x</details>",
    ],
    "javascript_url": [
        '<a href="javascript:alert(1)">click</a>',
        '<iframe src="javascript:alert(1)"></iframe>',
    ],
    "markup_breakout": [
        "<!--><script>alert(1)</script>",
        "<math><mtext></style><script>alert(1)</script></math>",
    ],
}


def make_input(fdp, sandbox):
    benign = {
        "username": "Alice",
        "biography": "Software engineer from xyz.",
        "status": "Feeling great!",
    }
    fields = list(benign)

    if not fdp.ConsumeBool():
        return benign

    target = fdp.PickValueInList(fields)
    result = dict(benign)

    for field in fields:
        if field == target or fdp.ConsumeBool():
            technique = fdp.PickValueInList(sorted(ATTACKS))
            payload = fdp.PickValueInList(ATTACKS[technique])
            prefix = fdp.ConsumeUnicodeNoSurrogates(3)
            suffix = fdp.ConsumeUnicodeNoSurrogates(3)
            result[field] = prefix + payload + suffix

    return result
