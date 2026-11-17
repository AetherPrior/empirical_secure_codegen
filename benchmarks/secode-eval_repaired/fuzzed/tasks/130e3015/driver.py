ATTACKS = {
    "script_element": [
        "<script>alert(1)</script>",
        "<ScRiPt>1</ScRiPt>",
    ],
    "event_handler": [
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
    ],
    "javascript_url": [
        '<a href="javascript:alert(1)">click</a>',
    ],
    "html_context_breakout": [
        "</h1><script>alert(1)</script>",
        "</p><img src=x onerror=alert(1)>",
    ],
    "embedded_html": [
        "<iframe srcdoc='<script>alert(1)</script>'></iframe>",
        "<object data='javascript:alert(1)'></object>",
    ],
}


def make_input(fdp, sandbox):
    benign_titles = ["Travel Diaries", "A Day in the Garden", "Notes from Home"]
    benign_bodies = [
        "I visited the most beautiful places!",
        "The flowers are blooming this week.",
        "Here are a few thoughts from today.",
    ]

    def make_value(benign_values):
        if fdp.ConsumeBool():
            technique = fdp.PickValueInList(sorted(ATTACKS))
            value = fdp.PickValueInList(ATTACKS[technique])
            if fdp.ConsumeBool():
                value = fdp.ConsumeUnicodeNoSurrogates(6) + value
            if fdp.ConsumeBool():
                value += fdp.ConsumeUnicodeNoSurrogates(6)
            return value
        return fdp.PickValueInList(benign_values)

    return {
        "post_title": make_value(benign_titles),
        "post_body": make_value(benign_bodies),
    }
