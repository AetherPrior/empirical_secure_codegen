ATTACKS = {
    "script_tag": ["<script>alert(1)</script>", "<script>alert('xss')</script>"],
    "event_handler": [
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<details open ontoggle=alert(1)>x</details>",
    ],
    "attribute_breakout": ['"><img src=x onerror=alert(1)>'],
    "javascript_url": ['<a href="javascript:alert(1)">click</a>'],
    "embedded_document": ['<iframe srcdoc="<script>alert(1)</script>"></iframe>'],
}

def make_input(fdp, sandbox):
    benign = {
        "username": ["Alice", "Sam", "Taylor"],
        "biography": ["Software engineer from xyz.", "I enjoy hiking and reading.", "A few sentences about me."],
        "status": ["Feeling great!", "Working on a project.", "Enjoying the weekend."],
    }

    def value_for(field):
        if fdp.ConsumeBool():
            technique = fdp.PickValueInList(sorted(ATTACKS))
            payload = fdp.PickValueInList(ATTACKS[technique])
            if fdp.ConsumeBool():
                payload = fdp.ConsumeUnicodeNoSurrogates(4) + payload
            if fdp.ConsumeBool():
                payload += fdp.ConsumeUnicodeNoSurrogates(4)
            return payload
        return fdp.PickValueInList(benign[field])

    return {
        "username": value_for("username"),
        "biography": value_for("biography"),
        "status": value_for("status"),
    }
