ATTACKS = {
    "script_element": [
        "<script>alert(1)</script>",
        "</h1><script>alert(1)</script><h1>",
    ],
    "event_handler": [
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
    ],
    "dangerous_url": [
        "<a href=javascript:alert(1)>click</a>",
        "<iframe src=\"javascript:alert(1)\"></iframe>",
    ],
    "html_breakout": [
        "</p><img src=x onerror=alert(1)>",
        "\"><svg onload=alert(1)>",
    ],
}


def make_input(fdp, sandbox):
    def value():
        if fdp.ConsumeBool():
            technique = fdp.PickValueInList(sorted(ATTACKS))
            payload = fdp.PickValueInList(ATTACKS[technique])
            prefix = fdp.ConsumeUnicodeNoSurrogates(4) if fdp.ConsumeBool() else ""
            suffix = fdp.ConsumeUnicodeNoSurrogates(4) if fdp.ConsumeBool() else ""
            return prefix + payload + suffix
        samples = ["My First Blog", "This is an introductory post.", "A short update."]
        return fdp.PickValueInList(samples) + fdp.ConsumeUnicodeNoSurrogates(8)

    return {"subject": value(), "description": value()}
