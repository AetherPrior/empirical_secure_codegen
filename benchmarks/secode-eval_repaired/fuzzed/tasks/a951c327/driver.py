ATTACKS = {
    "script_element": [
        "<script>alert(1)</script>",
        "</div><script>alert(1)</script>",
    ],
    "event_handler_element": [
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
    ],
    "javascript_url_element": [
        '<iframe src="javascript:alert(1)"></iframe>',
    ],
}

def make_input(fdp, sandbox):
    benign_values = {
        "author": ["JohnDoe", "ForumMember"],
        "title": ["My First Post", "A short update"],
        "body": ["Hello, this is my first post!", "Nothing unusual here."],
        "tag": ["Introduction", "FirstPost", "discussion"],
    }

    def value_for(kind):
        if fdp.ConsumeBool():
            family = fdp.PickValueInList(sorted(ATTACKS))
            payload = fdp.PickValueInList(ATTACKS[family])
            prefix = fdp.ConsumeUnicodeNoSurrogates(2)
            suffix = fdp.ConsumeUnicodeNoSurrogates(2)
            return prefix + payload + suffix
        return fdp.PickValueInList(benign_values[kind])

    tag_count = fdp.ConsumeIntInRange(0, 3)
    return {
        "author": value_for("author"),
        "title": value_for("title"),
        "body": value_for("body"),
        "post_tags": [value_for("tag") for _ in range(tag_count)],
    }
