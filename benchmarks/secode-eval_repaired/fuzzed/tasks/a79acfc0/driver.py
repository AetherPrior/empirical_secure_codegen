ATTACKS = {
    "script_element": [
        "<script>alert(1)</script>",
        "</h1><script>alert('xss')</script>",
    ],
    "event_handler": [
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<body onload=alert(1)>",
    ],
    "javascript_uri": [
        '<a href="javascript:alert(1)">click</a>',
        '<iframe src="javascript:alert(1)"></iframe>',
    ],
    "html_elements": [
        "<marquee onstart=alert(1)>x</marquee>",
        "<details open ontoggle=alert(1)>x</details>",
    ],
}


def make_input(fdp, sandbox):
    def fuzz_text(limit=8):
        return fdp.ConsumeUnicodeNoSurrogates(limit)

    if not fdp.ConsumeBool():
        return {
            "title": fdp.PickValueInList(
                ["My First Blog", "A short title", fuzz_text()]
            ),
            "body": fdp.PickValueInList(
                ["This is an introductory post.", "A little blog text.", fuzz_text(16)]
            ),
        }

    technique = fdp.PickValueInList(sorted(ATTACKS))
    payload = fdp.PickValueInList(ATTACKS[technique])
    decorated = fuzz_text(4) + payload + fuzz_text(4)

    if fdp.ConsumeBool():
        title = decorated
        body = fdp.PickValueInList(["This is an introductory post.", fuzz_text(16)])
    else:
        title = fdp.PickValueInList(["My First Blog", fuzz_text(8)])
        body = decorated

    return {"title": title, "body": body}
