ATTACKS = {
    "script_element": [
        "<script>alert(1)</script>",
        "</p><script>alert('xss')</script><p>",
    ],
    "event_handler": [
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<details open ontoggle=alert(1)>",
    ],
    "html_element": [
        "<iframe srcdoc=\"<script>alert(1)</script>\"></iframe>",
        "<video><source onerror=alert(1)>",
    ],
    "mixed_case": [
        "<ScRiPt>alert(1)</ScRiPt>",
        "<IMG SRC=x ONERROR=alert(1)>",
    ],
}

def make_input(fdp, sandbox):
    benign = {
        "event_title": ["Charity Gala", "Annual Meetup", "Team Lunch"],
        "event_description": [
            "A formal event to support our community.",
            "Join us for talks and activities.\nRefreshments will be provided.",
        ],
        "event_date": ["2023-12-12", "2024-06-15"],
        "additional_notes": ["Dress code: business formal.", "Please RSVP by Friday."],
    }

    result = {}
    for field in ("event_title", "event_description", "event_date", "additional_notes"):
        if fdp.ConsumeBool():
            technique = fdp.PickValueInList(sorted(ATTACKS))
            payload = fdp.PickValueInList(ATTACKS[technique])
            prefix = fdp.ConsumeUnicodeNoSurrogates(4)
            suffix = fdp.ConsumeUnicodeNoSurrogates(4)
            result[field] = prefix + payload + suffix
        else:
            result[field] = fdp.PickValueInList(benign[field])
    return result
