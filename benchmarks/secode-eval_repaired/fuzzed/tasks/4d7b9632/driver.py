ATTACKS = {
    "script_element": [
        "<script>alert(1)</script>",
        "</div><script>alert(1)</script>",
    ],
    "event_handler": [
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
    ],
    "html_context_breakout": [
        '"><svg onload=alert(1)>',
        "'><img src=x onerror=alert(1)>",
    ],
    "tag_container_breakout": [
        "</span><script>alert(1)</script><span>",
        "</div><img src=x onerror=alert(1)>",
    ],
}


def make_input(fdp, sandbox):
    def user_value():
        if fdp.ConsumeBool():
            family = fdp.PickValueInList(sorted(ATTACKS))
            payload = fdp.PickValueInList(ATTACKS[family])
            if fdp.ConsumeBool():
                fuzz = fdp.ConsumeUnicodeNoSurrogates(4)
                return fuzz + payload
            if fdp.ConsumeBool():
                fuzz = fdp.ConsumeUnicodeNoSurrogates(4)
                return payload + fuzz
            return payload
        return fdp.PickValueInList([
            "ForumUser",
            "A post",
            "Hello, this is a forum post.",
            "news",
            "python",
        ])

    author_name = user_value()
    title = user_value()
    body_content = user_value()

    tag_count = fdp.ConsumeIntInRange(0, 3)
    tag_list = [user_value() for _ in range(tag_count)]

    return {
        "author_name": author_name,
        "title": title,
        "body_content": body_content,
        "tag_list": tag_list,
    }
