ATTACKS = {
    "script_element": [
        "<script>alert(1)</script>",
        "Check this out<script>alert('xss')</script>!",
    ],
    "event_handler": [
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
    ],
    "html_breakout": [
        '"><img src=x onerror=alert(1)>',
        "</h1><script>alert(1)</script>",
        "Malicious<script>",
    ],
    "javascript_url": [
        '<a href="javascript:alert(1)">click</a>',
        '<iframe src="javascript:alert(1)"></iframe>',
    ],
}


def make_input(fdp, sandbox):
    benign_values = [
        "JohnDoe",
        "My First Post",
        "Hello, this is my first post!",
        "Introduction",
        "FirstPost",
    ]

    def value():
        if fdp.ConsumeBool():
            technique = fdp.PickValueInList(sorted(ATTACKS))
            payload = fdp.PickValueInList(ATTACKS[technique])
            if fdp.ConsumeBool():
                fuzz = fdp.ConsumeUnicodeNoSurrogates(4)
                return fuzz + payload
            return payload
        return fdp.PickValueInList(benign_values)

    username = value()
    post_title = value()
    post_body = value()
    tags = [value() for _ in range(fdp.ConsumeIntInRange(0, 4))]

    return {
        "username": username,
        "post_title": post_title,
        "post_body": post_body,
        "tags": tags,
    }
