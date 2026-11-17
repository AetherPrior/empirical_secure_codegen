ATTACKS = {
    "script_tag": [
        "<script>alert(1)</script>",
        "<ScRiPt>alert('xss')</sCrIpT>",
        "Important<script>",
        "alert('xss')</script>Message",
    ],
    "html_event_handler": [
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<body onload=alert(1)>",
        "<a href='#' onclick=alert(1)>click</a>",
    ],
    "javascript_url": [
        "<a href='javascript:alert(1)'>click</a>",
        "<iframe src='javascript:alert(1)'>",
        "<form action='javascript:alert(1)'>",
    ],
    "svg_and_mathml": [
        "<svg><script>alert(1)</script></svg>",
        "<math><mtext><img src=x onerror=alert(1)></mtext></math>",
        "<svg><a xlink:href='javascript:alert(1)'>click</a></svg>",
    ],
    "malformed_tag": [
        "<scr<script>ipt>alert(1)</scr</script>ipt>",
        "<img src=x onerror='alert(1)'",
        "<!--><script>alert(1)</script>",
    ],
    "encoded_markup": [
        "&#60;script&#62;alert(1)&#60;/script&#62;",
        "&lt;img src=x onerror=alert(1)&gt;",
        "&#x3c;svg onload=alert(1)&#x3e;",
    ],
}


def make_input(fdp, sandbox):
    benign_values = [
        "My First Blog",
        "This is an introductory post.",
        "A short update",
        "Plain text with no markup.",
    ]

    def value():
        if fdp.ConsumeBool():
            technique = fdp.PickValueInList(sorted(ATTACKS))
            payload = fdp.PickValueInList(ATTACKS[technique])
            prefix = fdp.ConsumeUnicodeNoSurrogates(4)
            suffix = fdp.ConsumeUnicodeNoSurrogates(4)
            return prefix + payload + suffix
        return fdp.PickValueInList(benign_values)

    return {"headline": value(), "text": value()}
