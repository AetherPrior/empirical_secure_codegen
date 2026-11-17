ATTACKS = {
    "script_element": [
        "<script>alert(1)</script>",
        "<ScRiPt>alert('xss')</sCrIpT>",
    ],
    "event_handler": [
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<body onpageshow=alert(1)>",
    ],
    "html_context_breakout": [
        "</p><script>alert(1)</script><p>",
        '"><img src=x onerror=alert(1)>',
        "</h2><svg onload=alert(1)>",
    ],
    "javascript_link": [
        '<a href="javascript:alert(1)">click</a>',
        '<iframe src="javascript:alert(1)"></iframe>',
    ],
}


def make_input(fdp, sandbox):
    benign_values = {
        "title_of_event": [
            "Charity Gala",
            "Community Workshop",
            "Annual Meeting",
        ],
        "event_details": [
            "A formal event to support our community.",
            "Join us for talks and activities.\nRefreshments will be provided.",
            "Doors open at 6 PM.",
        ],
        "scheduled_date": ["2023-12-12", "2024-05-18", "June 3, 2025"],
        "extra_info": [
            "Dress code: business formal.",
            "Please RSVP by Friday.",
            "Bring a reusable water bottle.",
        ],
    }

    def value_for(field):
        if not fdp.ConsumeBool():
            return fdp.PickValueInList(benign_values[field])

        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        prefix = fdp.ConsumeUnicodeNoSurrogates(3) if fdp.ConsumeBool() else ""
        suffix = fdp.ConsumeUnicodeNoSurrogates(3) if fdp.ConsumeBool() else ""
        return prefix + payload + suffix

    return {
        field: value_for(field)
        for field in (
            "title_of_event",
            "event_details",
            "scheduled_date",
            "extra_info",
        )
    }
