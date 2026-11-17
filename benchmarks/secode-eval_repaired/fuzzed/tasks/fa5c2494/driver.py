ATTACKS = {
    "script_element": [
        "<script>alert(1)</script>",
        "<script>prompt(1)</script>",
    ],
    "event_handler_element": [
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<body onload=alert(1)>",
        "<details open ontoggle=alert(1)>",
    ],
    "injected_link": [
        '<a href="javascript:alert(1)">click</a>',
        '<iframe src="javascript:alert(1)"></iframe>',
    ],
}

def make_input(fdp, sandbox):
    benign_values = {
        "username": ["Alice", "Jordan Lee", "Sam"],
        "about": ["Software engineer from xyz.", "I enjoy hiking and reading.", "A short biography."],
        "current_status": ["Feeling great!", "Available today.", "Working on a project."],
    }

    def make_value(field):
        if fdp.ConsumeBool():
            technique = fdp.PickValueInList(sorted(ATTACKS))
            payload = fdp.PickValueInList(ATTACKS[technique])
            prefix = fdp.ConsumeUnicodeNoSurrogates(4)
            suffix = fdp.ConsumeUnicodeNoSurrogates(4)
            return prefix + payload + suffix
        return fdp.PickValueInList(benign_values[field])

    return {
        "username": make_value("username"),
        "about": make_value("about"),
        "current_status": make_value("current_status"),
    }
