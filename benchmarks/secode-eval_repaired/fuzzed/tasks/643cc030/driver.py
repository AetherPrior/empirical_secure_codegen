ATTACKS = {
    "script_element": [
        "<script>alert(1)</script>",
        "<script>confirm('xss')</script>",
    ],
    "tag_closure": [
        "</p><script>alert(1)</script><p>",
        "</h2><img src=x onerror=alert(1)>",
    ],
    "html_event_handler": [
        "<img src=x onerror=alert(1)>",
        "<body onload=alert(1)>",
    ],
    "svg_event_handler": [
        "<svg onload=alert(1)>",
        "<svg><script>alert(1)</script></svg>",
    ],
    "mixed_case_tag": [
        "<ScRiPt>alert(1)</ScRiPt>",
        "<IMG SRC=x ONERROR=alert(1)>",
    ],
    "html_entity": [
        "&lt;script&gt;alert(1)&lt;/script&gt;",
        "&#x3c;img src=x onerror=alert(1)&#x3e;",
    ],
}

_BENIGN = {
    "e_title": ["Charity Gala", "Community Meetup", "Annual Hackathon"],
    "e_description": [
        "A formal event to support our community.",
        "Join us for talks, food, and activities.\nAll are welcome.",
    ],
    "e_date": ["2023-12-12", "2024-06-15"],
    "e_notes": ["Dress code: business formal.", "Please arrive 15 minutes early."],
}


def make_input(fdp, sandbox):
    def value_for(field):
        if fdp.ConsumeBool():
            technique = fdp.PickValueInList(sorted(ATTACKS))
            payload = fdp.PickValueInList(ATTACKS[technique])
            prefix = fdp.ConsumeUnicodeNoSurrogates(4)
            suffix = fdp.ConsumeUnicodeNoSurrogates(4)
            return prefix + payload + suffix
        if fdp.ConsumeBool():
            return fdp.PickValueInList(_BENIGN[field])
        return fdp.ConsumeUnicodeNoSurrogates(16)

    return {
        "e_title": value_for("e_title"),
        "e_description": value_for("e_description"),
        "e_date": value_for("e_date"),
        "e_notes": value_for("e_notes"),
    }
