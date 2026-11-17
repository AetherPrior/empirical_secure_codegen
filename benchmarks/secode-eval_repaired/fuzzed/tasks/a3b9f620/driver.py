ATTACKS = {
    "script_element": [
        "<script>alert(1)</script>",
        "</div><script>alert('xss')</script>",
    ],
    "event_handler": [
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<body onload=alert(1)>",
    ],
    "html_element_breakout": [
        "</p><iframe src=javascript:alert(1)>",
        "<details open ontoggle=alert(1)>",
    ],
}

def make_input(fdp, sandbox):
    benign = {
        "full_name": ["Alice", "Jordan Lee", "Sam"],
        "about_me": ["Software engineer from xyz.", "I enjoy hiking and reading.", "Hello!"],
        "status_update": ["Feeling great!", "Working on a project.", "Hello."],
    }

    def value_for(field):
        if not fdp.ConsumeBool():
            return fdp.PickValueInList(benign[field])

        family = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[family])
        prefix = fdp.ConsumeUnicodeNoSurrogates(3)
        suffix = fdp.ConsumeUnicodeNoSurrogates(3)
        return prefix + payload + suffix

    return {
        "full_name": value_for("full_name"),
        "about_me": value_for("about_me"),
        "status_update": value_for("status_update"),
    }
