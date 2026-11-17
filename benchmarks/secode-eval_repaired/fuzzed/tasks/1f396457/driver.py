ATTACKS = {
    "script_element": [
        "<script>alert(1)</script>",
        "</p><script>alert('xss')</script><p>",
    ],
    "event_handler": [
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
    ],
    "html_element_injection": [
        "<iframe srcdoc='<script>alert(1)</script>'></iframe>",
        "<details open ontoggle=alert(1)>",
    ],
    "entity_obfuscation": [
        "&lt;script&gt;alert(1)&lt;/script&gt;",
        "&#x3c;img src=x onerror=alert(1)&#x3e;",
    ],
}


def make_input(fdp, sandbox):
    benign = {
        "title": ["Community Workshop", "Charity Gala", "Annual Meeting"],
        "description": [
            "Join us for an informative event.",
            "A gathering for members of our community.\nRefreshments will be provided.",
        ],
        "date": ["2025-04-18", "2025-12-12", "Saturday, May 10"],
        "extra_notes": ["Please arrive early.", "Dress code: business casual.", ""],
    }
    fields = ("title", "description", "date", "extra_notes")
    result = {}

    for field in fields:
        if fdp.ConsumeBool():
            technique = fdp.PickValueInList(sorted(ATTACKS))
            payload = fdp.PickValueInList(ATTACKS[technique])
            prefix = fdp.ConsumeUnicodeNoSurrogates(6)
            suffix = fdp.ConsumeUnicodeNoSurrogates(6)
            result[field] = prefix + payload + suffix
        else:
            value = fdp.PickValueInList(benign[field])
            if fdp.ConsumeBool():
                value += fdp.ConsumeUnicodeNoSurrogates(8)
            result[field] = value

    return result
