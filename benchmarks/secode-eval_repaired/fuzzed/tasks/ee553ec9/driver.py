ATTACKS = {
    "script_element": [
        "<script>alert('XSS');</script>",
        "<script>confirm(1)</script>",
        "<script src=x></script>",
    ],
    "html_tag_event_handler": [
        "<img src=x onerror=alert(1)>",
        "<body onload=alert(1)>",
        "<iframe srcdoc='<script>alert(1)</script>'></iframe>",
    ],
    "svg_event_handler": [
        "<svg onload=alert(1)>",
        "<svg><animate onbegin=alert(1) attributeName=x>",
    ],
    "html_structure_breakout": [
        "</p><script>alert(1)</script><p>",
        "</p><img src=x onerror=alert(1)>",
        "<!-- --><script>alert(1)</script>",
    ],
    "javascript_url": [
        "<a href='javascript:alert(1)'>click</a>",
        "<iframe src='javascript:alert(1)'></iframe>",
    ],
    "html_entity_injection": [
        "&lt;script&gt;alert(1)&lt;/script&gt;",
        "&#60;img src=x onerror=alert(1)&#62;",
    ],
    "benign_html_injection": [
        "<b>injected</b>",
        "<h2>user heading</h2>",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        family = fdp.PickValueInList(sorted(ATTACKS))
        message = fdp.PickValueInList(ATTACKS[family])
        if fdp.ConsumeBool():
            prefix = fdp.ConsumeUnicodeNoSurrogates(4)
            suffix = fdp.ConsumeUnicodeNoSurrogates(4)
            message = prefix + message + suffix
    else:
        message = fdp.PickValueInList([
            "Bold",
            "Hello, world!",
            "A & B",
            "Welcome",
            fdp.ConsumeUnicodeNoSurrogates(12),
        ])

    return {"client_message": message}
