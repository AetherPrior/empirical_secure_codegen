ATTACKS = {
    "script_element": [
        "<script>alert(1)</script>",
        "</div><script>alert('xss')</script>",
    ],
    "event_handler_element": [
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<details open ontoggle=alert(1)>",
    ],
    "javascript_url": [
        '<a href="javascript:alert(1)">click</a>',
        '<iframe src="javascript:alert(1)"></iframe>',
    ],
    "other_active_elements": [
        "<math><mtext><table><mglyph><style><!--</style><img title=\"--><img src=x onerror=alert(1)>\"></math>",
        "<iframe srcdoc=\"<script>alert(1)</script>\"></iframe>",
    ],
}


def make_input(fdp, sandbox):
    benign = {
        "user_name": ["Alice", "Jordan Lee", "Sam"],
        "biography": [
            "Software engineer from xyz.",
            "I enjoy hiking and reading.",
            "A multi-sentence biography. Here is another sentence.",
        ],
        "status": ["Feeling great!", "Working on a project.", "Hello!"],
    }

    def value(field):
        if not fdp.ConsumeBool():
            return fdp.PickValueInList(benign[field])

        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        if fdp.ConsumeBool():
            payload = fdp.ConsumeUnicodeNoSurrogates(4) + payload
        if fdp.ConsumeBool():
            payload += fdp.ConsumeUnicodeNoSurrogates(4)
        return payload

    return {
        "user_name": value("user_name"),
        "biography": value("biography"),
        "status": value("status"),
    }
