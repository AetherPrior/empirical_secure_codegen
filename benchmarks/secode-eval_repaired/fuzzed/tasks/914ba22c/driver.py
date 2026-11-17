ATTACKS = {
    "script_element": [
        "<script>alert(1)</script>",
        "</p><script>alert(1)</script><p>",
    ],
    "event_handler": [
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<details open ontoggle=alert(1)>",
    ],
    "markup_breakout": [
        "</h2><iframe srcdoc=\"<script>alert(1)</script>\"></iframe>",
        "<!--><script>alert(1)</script>",
        "\"><img src=x onerror=alert(1)>",
    ],
}


def make_input(fdp, sandbox):
    benign = {
        "title": ["Community Picnic", "Charity Gala", "Team Meeting"],
        "description": [
            "Join us for an afternoon of activities and conversation.",
            "A formal event to support our community.",
            "Please arrive a few minutes early.",
        ],
        "date": ["2025-05-17", "2025-10-03", "2025-12-12"],
        "notes": ["Bring a reusable water bottle.", "Dress code: business formal.", "Doors open at 6 pm."],
    }
    fields = ("title", "description", "date", "notes")
    mask = fdp.ConsumeIntInRange(0, (1 << len(fields)) - 1)
    result = {}

    for i, field in enumerate(fields):
        if mask & (1 << i):
            technique = fdp.PickValueInList(sorted(ATTACKS))
            payload = fdp.PickValueInList(ATTACKS[technique])
            if fdp.ConsumeBool():
                payload = (
                    fdp.ConsumeUnicodeNoSurrogates(3)
                    + payload
                    + fdp.ConsumeUnicodeNoSurrogates(3)
                )
            result[field] = payload
        else:
            result[field] = fdp.PickValueInList(benign[field])

    return result
