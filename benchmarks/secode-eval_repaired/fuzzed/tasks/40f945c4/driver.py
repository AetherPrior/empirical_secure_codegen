ATTACKS = {
    "script_element": ["<script>alert(1)</script>", "<script>1</script>"],
    "event_handler": [
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
    ],
    "html_boundary_breakout": [
        "</div><script>alert(1)</script>",
        "</span><img src=x onerror=alert(1)>",
    ],
    "entity_encoded_markup": ["&lt;script&gt;alert(1)&lt;/script&gt;"],
}


def make_input(fdp, sandbox):
    benign_values = {
        "user_name": "JohnDoe",
        "post_heading": "My First Post",
        "post_content": "Hello, this is my first post!",
    }

    def value_for(field):
        if not fdp.ConsumeBool():
            return benign_values[field]

        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        prefix = fdp.ConsumeUnicodeNoSurrogates(3)
        suffix = fdp.ConsumeUnicodeNoSurrogates(3)
        return prefix + payload + suffix

    tags = []
    for i in range(fdp.ConsumeIntInRange(0, 3)):
        if fdp.ConsumeBool():
            technique = fdp.PickValueInList(sorted(ATTACKS))
            payload = fdp.PickValueInList(ATTACKS[technique])
            tags.append(fdp.ConsumeUnicodeNoSurrogates(2) + payload)
        else:
            tags.append(fdp.PickValueInList(["Introduction", "FirstPost", "Python"]))

    return {
        "user_name": value_for("user_name"),
        "post_heading": value_for("post_heading"),
        "post_content": value_for("post_content"),
        "post_tags": tags,
    }
