ATTACKS = {
    "script_element": [
        "<script>alert(1)</script>",
        "</h2><script>alert('xss')</script>",
    ],
    "event_handler": [
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
    ],
    "javascript_uri": [
        '<a href="javascript:alert(1)">open</a>',
        '<iframe src="javascript:alert(1)"></iframe>',
    ],
    "html_injection": [
        "'\"><b>injected</b>",
        "<details open ontoggle=alert(1)>",
    ],
}

def make_input(fdp, sandbox):
    benign = {
        "title": ["Charity Gala", "Team Lunch"],
        "description": [
            "A formal event to support our community.",
            "Talks, activities, and refreshments for all attendees.",
        ],
        "date": ["2023-12-12", "2024-06-15"],
        "notes": ["Dress code: business formal.", "Please arrive ten minutes early."],
    }

    def value(field):
        if not fdp.ConsumeBool():
            return fdp.PickValueInList(benign[field])

        family = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[family])
        prefix = fdp.ConsumeUnicodeNoSurrogates(3)
        suffix = fdp.ConsumeUnicodeNoSurrogates(3)
        return prefix + payload + suffix

    return {
        "title": value("title"),
        "description": value("description"),
        "date": value("date"),
        "notes": value("notes"),
    }
