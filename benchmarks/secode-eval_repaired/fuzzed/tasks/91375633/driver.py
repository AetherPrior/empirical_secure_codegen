ATTACKS = {
    "script_element": [
        "<script>alert(1)</script>",
        "</script><script>alert(1)</script>",
    ],
    "event_handler": [
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        '<body onload=alert(1)>',
    ],
    "html_element_injection": [
        "<iframe src=javascript:alert(1)>",
        "<marquee onstart=alert(1)>x</marquee>",
    ],
    "javascript_uri": [
        '<a href="javascript:alert(1)">click</a>',
        '<form action="javascript:alert(1)"><input type=submit></form>',
    ],
}


def make_input(fdp, sandbox):
    values = {
        "name": "Alice",
        "bio": "Software engineer from xyz.",
        "status_msg": "Feeling great!",
    }

    if fdp.ConsumeBool():
        field = fdp.PickValueInList(["name", "bio", "status_msg"])
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        values[field] = payload

    return values
