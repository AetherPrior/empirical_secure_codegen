ATTACKS = {
    "script_element": [
        "<script>alert(1)</script>",
        "<ScRiPt>alert('xss')</sCrIpT>",
    ],
    "event_handler": [
        "<img src=x onerror=alert(1)>",
        "<body onload=alert(1)>",
    ],
    "svg_event_handler": [
        "<svg onload=alert(1)>",
        "<svg><animate onbegin=alert(1)>",
    ],
    "javascript_uri": [
        '<a href="javascript:alert(1)">click</a>',
        '<iframe src="javascript:alert(1)"></iframe>',
    ],
    "html_entity_obfuscation": [
        "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",
        "&lt;img src=x onerror=alert(1)&gt;",
    ],
}


def make_input(fdp, sandbox):
    benign = {
        "person_name": ["Alice", "Morgan", "Sam"],
        "user_bio": ["Software engineer from xyz.", "Enjoys hiking and reading."],
        "status_message": ["Feeling great!", "Working on a new project."],
    }

    result = {}
    for field in ("person_name", "user_bio", "status_message"):
        if fdp.ConsumeBool():
            technique = fdp.PickValueInList(sorted(ATTACKS))
            payload = fdp.PickValueInList(ATTACKS[technique])
            prefix = fdp.ConsumeUnicodeNoSurrogates(4) if fdp.ConsumeBool() else ""
            suffix = fdp.ConsumeUnicodeNoSurrogates(4) if fdp.ConsumeBool() else ""
            result[field] = prefix + payload + suffix
        else:
            result[field] = fdp.PickValueInList(benign[field])

    return result
