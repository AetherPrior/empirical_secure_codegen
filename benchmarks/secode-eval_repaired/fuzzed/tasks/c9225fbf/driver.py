ATTACKS = {
    "script_element": [
        "<script>alert(1)</script>",
        "</h1><script>alert(1)</script>",
    ],
    "event_handler": [
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
    ],
    "markup_injection": [
        "<b>bold</b>",
        "<iframe src=x></iframe>",
    ],
    "attribute_breakout": [
        '"><img src=x onerror=alert(1)>',
        "' onmouseover='alert(1)",
    ],
    "javascript_url": [
        "<a href='javascript:alert(1)'>click</a>",
    ],
    "entity_obfuscation": [
        "&#60;script&#62;alert(1)&#60;/script&#62;",
    ],
}


def make_input(fdp, sandbox):
    benign = {
        "author_name": ["JohnDoe", "A. Reader", "ForumUser"],
        "post_title": ["My First Post", "A short headline", "Hello"],
        "content": ["Hello, this is my first post!", "A little forum text.", "Thanks for reading."],
        "tag": ["Introduction", "FirstPost", "Discussion", "Python"],
    }

    def value(kind):
        if not fdp.ConsumeBool():
            return fdp.PickValueInList(benign[kind])

        family = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[family])
        if fdp.ConsumeBool():
            prefix = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 3))
            suffix = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 3))
            return prefix + payload + suffix
        return payload

    author_name = value("author_name")
    post_title = value("post_title")
    content = value("content")
    post_tags = [value("tag") for _ in range(fdp.ConsumeIntInRange(0, 3))]

    return {
        "author_name": author_name,
        "post_title": post_title,
        "content": content,
        "post_tags": post_tags,
    }
