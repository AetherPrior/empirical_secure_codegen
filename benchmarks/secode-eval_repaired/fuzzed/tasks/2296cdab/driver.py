ATTACKS = {
    "script_element": [
        "<script>alert(1)</script>",
        "<script>document.body.innerHTML='x'</script>",
    ],
    "event_handler": [
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<body onload=alert(1)>",
    ],
    "html_tag_injection": [
        "</p><h1>injected</h1><p>",
        "<iframe src='javascript:alert(1)'></iframe>",
        "<details open ontoggle=alert(1)>x</details>",
    ],
    "encoded_markup": [
        "&lt;script&gt;alert(1)&lt;/script&gt;",
        "&#60;img src=x onerror=alert(1)&#62;",
    ],
}


def make_input(fdp, sandbox):
    def field(benign):
        if fdp.ConsumeBool():
            technique = fdp.PickValueInList(sorted(ATTACKS))
            payload = fdp.PickValueInList(ATTACKS[technique])
            if fdp.ConsumeBool():
                prefix = fdp.ConsumeUnicodeNoSurrogates(5)
                suffix = fdp.ConsumeUnicodeNoSurrogates(5)
                return prefix + payload + suffix
            return payload
        if fdp.ConsumeBool():
            return benign
        return fdp.ConsumeUnicodeNoSurrogates(12)

    return {
        "headline": field("My First Blog"),
        "content": field("This is an introductory post."),
    }
