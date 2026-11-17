ATTACKS = {
    "script_element": [
        "<script>alert(1)</script>",
        "</h2><script>alert('xss')</script>",
    ],
    "event_handler": [
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
    ],
    "javascript_url": [
        '<a href="javascript:alert(1)">click</a>',
        '<iframe src="javascript:alert(1)">',
    ],
}


def make_input(fdp, sandbox):
    benign_headlines = ["A Day at the Zoo", "Notes", "Weekend"]
    benign_texts = ["Saw lots of amazing animals!", "Hello, world.", "A short update."]

    def fuzz_text():
        return fdp.ConsumeUnicodeNoSurrogates(8)

    def value(is_headline):
        if fdp.ConsumeBool():
            return fdp.PickValueInList(
                benign_headlines if is_headline else benign_texts
            ) + fuzz_text()

        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        if fdp.ConsumeBool():
            return fuzz_text() + payload
        return payload + fuzz_text()

    return {
        "headline": value(True),
        "text": value(False),
    }
