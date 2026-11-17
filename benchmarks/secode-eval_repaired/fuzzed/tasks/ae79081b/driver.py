ATTACKS = {
    "script_element": [
        "<script>alert(1)</script>",
        "</h2><script>alert('xss')</script><h2>",
    ],
    "event_handler": [
        "<img src=x onerror=alert(1)>",
        '"><svg onload=alert(1)>',
    ],
    "svg_payload": [
        "<svg/onload=alert(1)>",
        "</p><svg><script>alert(1)</script></svg>",
    ],
    "encoded_markup": [
        "&lt;script&gt;alert(1)&lt;/script&gt;",
        "&#x3c;img src=x onerror=alert(1)&#x3e;",
    ],
}


def make_input(fdp, sandbox):
    del sandbox

    benign_values = {
        "headline": ["Community Meetup", "Music Concert", "Code Expo"],
        "summary": [
            "A night filled with melodies and rhythm.",
            "Join us for talks, activities, and refreshments.",
            "First paragraph.\n\nA second paragraph with more details.",
        ],
        "scheduled_date": ["2023-11-15", "2024-06-01", "October 25, 2025"],
        "additional_info": [
            "Tickets are available at the venue entrance.",
            "Please arrive 15 minutes early.",
            "Bring your registration confirmation.",
        ],
    }

    def value_for(field):
        if fdp.ConsumeBool():
            family = fdp.PickValueInList(sorted(ATTACKS))
            payload = fdp.PickValueInList(ATTACKS[family])
            prefix = fdp.ConsumeUnicodeNoSurrogates(5)
            suffix = fdp.ConsumeUnicodeNoSurrogates(5)
            return prefix + payload + suffix
        return fdp.PickValueInList(benign_values[field])

    return {
        "headline": value_for("headline"),
        "summary": value_for("summary"),
        "scheduled_date": value_for("scheduled_date"),
        "additional_info": value_for("additional_info"),
    }
