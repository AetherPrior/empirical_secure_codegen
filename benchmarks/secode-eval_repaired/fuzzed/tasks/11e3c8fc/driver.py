ATTACKS = {
    "script_element": [
        "<script>alert(1)</script>",
        "</h1><script>alert(1)</script>",
        "</div><script>alert(1)</script>",
    ],
    "event_handler_element": [
        "<img src=x onerror=alert(1)>",
        '"><svg onload=alert(1)>',
        "<details open ontoggle=alert(1)>",
    ],
    "tag_structure_breakout": [
        "</span><script>alert(1)</script>",
        "</div><img src=x onerror=alert(1)>",
    ],
    "encoded_markup": [
        "&lt;script&gt;alert(1)&lt;/script&gt;",
        "&#60;img src=x onerror=alert(1)&#62;",
    ],
}


def make_input(fdp, sandbox):
    values = {
        "author_id": "JohnDoe",
        "post_heading": "My First Post",
        "content": "Hello, this is my first post!",
        "labels": ["Introduction", "FirstPost"],
    }

    # Most inputs remain benign; attack inputs target one component at a time.
    if fdp.ConsumeBool():
        field = fdp.PickValueInList(
            ["author_id", "post_heading", "content", "labels"]
        )
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        prefix = fdp.ConsumeUnicodeNoSurrogates(3)
        suffix = fdp.ConsumeUnicodeNoSurrogates(3)
        attack_text = prefix + payload + suffix

        if field == "labels":
            values["labels"] = ["Introduction", attack_text]
        else:
            values[field] = attack_text

    return values
