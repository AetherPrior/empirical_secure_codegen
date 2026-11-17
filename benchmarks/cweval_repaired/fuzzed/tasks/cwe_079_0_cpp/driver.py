ATTACKS = {
    "script_tag": ["<script>alert(1)</script>", "</title><script>alert(1)</script>"],
    "event_handler": ['<img src=x onerror=alert(1)>', '<svg onload=alert(1)>'],
    "html_tag_injection": ["<iframe src=x></iframe>", "<details open ontoggle=alert(1)>"],
    "html_metacharacters": ["<", ">", "&", '"', "'"],
    "entity_encoding": ["&lt;script&gt;alert(1)&lt;/script&gt;"],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        left = fdp.ConsumeUnicodeNoSurrogates(6).replace("\x00", "")
        right = fdp.ConsumeUnicodeNoSurrogates(6).replace("\x00", "")
        username = left + payload + right
    else:
        username = fdp.PickValueInList(["Alice", "guest", "user_123", ""])

    return {"username": username[:128]}
