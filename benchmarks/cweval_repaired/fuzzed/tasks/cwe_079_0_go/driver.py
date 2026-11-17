ATTACKS = {
    "script_tag": ["<script>alert(1)</script>", "</title><script>alert(1)</script>"],
    "event_handler": ["<img src=x onerror=alert(1)>", "<svg/onload=alert(1)>"],
    "attribute_breakout": ['" onmouseover="alert(1)', "' autofocus onfocus='alert(1)"],
    "style_context": ["<style>@import'javascript:alert(1)'</style>"],
}

def make_input(fdp, sandbox):
    benign = ["alice", "guest", "user123", "welcome-user"]
    if not fdp.ConsumeBool():
        return {"username": fdp.PickValueInList(benign)}

    technique = fdp.PickValueInList(sorted(ATTACKS))
    payload = fdp.PickValueInList(ATTACKS[technique])
    prefix = fdp.ConsumeUnicodeNoSurrogates(4).replace("\x00", "")
    suffix = fdp.ConsumeUnicodeNoSurrogates(4).replace("\x00", "")
    return {"username": prefix + payload + suffix}
