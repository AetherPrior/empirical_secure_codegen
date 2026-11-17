ATTACKS = {
    "script_element": [
        "<script>alert(1)</script>",
        "</h1><script>alert(1)</script>",
        "</p><script>alert(1)</script>",
    ],
    "event_handler": [
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<iframe srcdoc=\"<script>alert(1)</script>\"></iframe>",
    ],
    "tag_breakout": [
        "</h1><img src=x onerror=alert(1)>",
        "</p><svg onload=alert(1)>",
    ],
    "javascript_link": [
        "<a href=\"javascript:alert(1)\">click</a>",
    ],
}


def make_input(fdp, sandbox):
    benign_headlines = [
        "My First Blog",
        "A short update",
        "Notes from today",
    ]
    benign_contents = [
        "This is an introductory post.",
        "A few ordinary words for the page.",
        "Thanks for reading.",
    ]

    def fuzz_letters(limit):
        raw = fdp.ConsumeBytes(limit)
        return "".join(chr(97 + byte % 26) for byte in raw)

    def value(benign_values):
        if fdp.ConsumeBool():
            family = fdp.PickValueInList(sorted(ATTACKS))
            payload = fdp.PickValueInList(ATTACKS[family])
            return fuzz_letters(3) + payload + fuzz_letters(3)
        return fdp.PickValueInList(benign_values)

    return {
        "headline": value(benign_headlines),
        "content": value(benign_contents),
    }
