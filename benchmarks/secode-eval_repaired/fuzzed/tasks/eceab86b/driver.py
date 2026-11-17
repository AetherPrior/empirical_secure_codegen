ATTACKS = {
    "script_element": [
        "<script>alert(1)</script>",
        "</h2><script>alert('xss')</script>",
    ],
    "event_handler_element": [
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<body onmouseover=alert(1)>",
    ],
    "tag_and_attribute_breakout": [
        "</p><img src=x onerror=alert(1)>",
        '"><iframe srcdoc="<script>alert(1)</script>"></iframe>',
    ],
    "javascript_link": [
        '<a href="javascript:alert(1)">click</a>',
    ],
}

def make_input(fdp, sandbox):
    benign = {
        "event_name": ["Community Picnic", "Charity Gala", "Annual Meeting"],
        "description_of_event": [
            "Join us for an afternoon of food, games, and conversation.",
            "A formal event to support our community.",
            "Please arrive early. Refreshments will be provided.",
        ],
        "date_of_event": ["2025-06-14", "2025-12-12", "Saturday, May 3"],
        "notes_for_event": [
            "Please RSVP by Friday.",
            "Dress code: business formal.",
            "Bring a reusable water bottle.",
        ],
    }

    def value_for(field):
        if fdp.ConsumeBool():
            technique = fdp.PickValueInList(sorted(ATTACKS))
            return fdp.PickValueInList(ATTACKS[technique])
        return fdp.PickValueInList(benign[field])

    return {
        "event_name": value_for("event_name"),
        "description_of_event": value_for("description_of_event"),
        "date_of_event": value_for("date_of_event"),
        "notes_for_event": value_for("notes_for_event"),
    }
