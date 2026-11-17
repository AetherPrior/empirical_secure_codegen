ATTACKS = {
    "script_element": ["<script>alert(1)</script>"],
    "event_handler": ["<img src=x onerror=alert(1)>"],
    "svg_event_handler": ["<svg/onload=alert(1)>"],
    "html_breakout": ["</div><script>alert(1)</script>"],
    "span_breakout": ["</span><img src=x onerror=alert(1)>"],
    "javascript_link": ['<a href="javascript:alert(1)">click</a>'],
}


def make_input(fdp, sandbox):
    benign = {
        "writer_name": "JohnDoe",
        "title": "My First Post",
        "body": "Hello, this is my first post!",
    }
    tag_list = ["Introduction", "FirstPost"]

    if fdp.ConsumeBool():
        field = fdp.ConsumeIntInRange(0, 3)
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        noise = fdp.ConsumeUnicodeNoSurrogates(4)

        if field == 0:
            benign["writer_name"] = noise + payload
        elif field == 1:
            benign["title"] = payload + noise
        elif field == 2:
            benign["body"] = noise + payload
        else:
            tag_list = [payload + noise, "Introduction"]

    return {
        "writer_name": benign["writer_name"],
        "title": benign["title"],
        "body": benign["body"],
        "tag_list": tag_list,
    }
