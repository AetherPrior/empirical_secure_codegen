ATTACKS = {
    "script_element": [
        "<script>alert(1)</script>",
        "<ScRiPt>alert(document.domain)</ScRiPt>",
    ],
    "event_handler": [
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        '<body onpageshow=alert(1)>',
    ],
    "html_context_breakout": [
        "</div><script>alert(1)</script><div>",
        "</h1><img src=x onerror=alert(1)>",
        "</span><svg onload=alert(1)>",
    ],
    "javascript_url": [
        '<a href="javascript:alert(1)">click</a>',
        '<iframe src="javascript:alert(1)">',
    ],
    "malformed_markup": [
        "<<script>alert(1)</script>",
        "<scr<script>ipt>alert(1)</scr</script>ipt>",
    ],
    "entity_obfuscation": [
        "&#60;script&#62;alert(1)&#60;/script&#62;",
        "&lt;img src=x onerror=alert(1)&gt;",
    ],
}


def make_input(fdp, sandbox):
    def fuzz_fragment():
        raw = fdp.ConsumeUnicodeNoSurrogates(8)
        return "".join(ch for ch in raw if ch.isalnum())[:6]

    def value(benign):
        if not fdp.ConsumeBool():
            return benign
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        prefix = fuzz_fragment()
        suffix = fuzz_fragment()
        return prefix + payload + suffix

    poster_name = value("JohnDoe")
    headline = value("My First Post")
    text = value("Hello, this is my first post!")

    count = fdp.ConsumeIntInRange(2, 3)
    hashtags = []
    for i in range(count):
        hashtags.append(value(("Introduction", "FirstPost", "Discussion")[i]))

    return {
        "poster_name": poster_name,
        "headline": headline,
        "text": text,
        "hashtags": hashtags,
    }
