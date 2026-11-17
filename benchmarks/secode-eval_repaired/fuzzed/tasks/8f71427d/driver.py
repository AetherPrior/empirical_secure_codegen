ATTACKS = {
    "script_element": [
        "<script>alert(1)</script>",
        "</div><script>alert(1)</script>",
    ],
    "event_handler": [
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
    ],
    "html_structure_breakout": [
        "</span><script>alert(1)</script><span>",
        "</h1><img src=x onerror=alert(1)>",
    ],
    "quote_injection": [
        '" onmouseover="alert(1)',
        "' onfocus='alert(1)",
    ],
}


def make_input(fdp, sandbox):
    benign = {
        "username_key": ["JohnDoe", "ForumUser", "reader_7"],
        "title_key": ["My First Post", "Hello", "Notes & Ideas"],
        "body_key": ["Hello, this is my first post!", "A short forum message.", "Thanks for reading."],
        "tags": ["Introduction", "FirstPost", "discussion", "help"],
    }
    families = sorted(ATTACKS)

    def value(field):
        if fdp.ConsumeBool():
            family = fdp.PickValueInList(families)
            payload = fdp.PickValueInList(ATTACKS[family])
            prefix = fdp.PickValueInList(["", "x", "post-"])
            suffix = fdp.PickValueInList(["", "!", " text"])
            return prefix + payload + suffix
        return fdp.PickValueInList(benign[field])

    username = value("username_key")
    title = value("title_key")
    body = value("body_key")

    tag_count = fdp.ConsumeIntInRange(0, 4)
    tags = [value("tags") for _ in range(tag_count)]

    return {
        "username_key": username,
        "title_key": title,
        "body_key": body,
        "tag_elements": tags,
    }
