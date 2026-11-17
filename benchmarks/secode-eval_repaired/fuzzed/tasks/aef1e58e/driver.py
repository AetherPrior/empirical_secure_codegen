ATTACKS = {
    "script_element": [
        "<script>alert(1)</script>",
        "<ScRiPt>alert('xss')</ScRiPt>",
    ],
    "event_handler": [
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<details open ontoggle=alert(1)>",
    ],
    "javascript_url": [
        "<a href=\"javascript:alert(1)\">click</a>",
        "<iframe src=\"javascript:alert(1)\"></iframe>",
    ],
    "html_injection": [
        "</div><script>alert(1)</script>",
        "<iframe srcdoc=\"&lt;script&gt;alert(1)&lt;/script&gt;\"></iframe>",
    ],
}

_BENIGN = [
    "Alice",
    "Software engineer from xyz.",
    "Feeling great!",
    "Enjoying the weekend.",
]


def make_input(fdp, sandbox):
    values = [fdp.PickValueInList(_BENIGN) for _ in range(3)]

    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        field = fdp.ConsumeIntInRange(0, 2)

        # Occasionally place ordinary text around the payload to exercise
        # sanitization when markup is embedded within otherwise benign content.
        if fdp.ConsumeBool():
            payload = (
                fdp.ConsumeUnicodeNoSurrogates(4)
                + payload
                + fdp.ConsumeUnicodeNoSurrogates(4)
            )
        values[field] = payload

    return {
        "fullname": values[0],
        "biography": values[1],
        "current_status": values[2],
    }
