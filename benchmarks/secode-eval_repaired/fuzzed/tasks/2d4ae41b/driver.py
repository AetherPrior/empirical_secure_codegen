ATTACKS = {
    "script_element": [
        "<script>alert(1)</script>",
        "</p><script>alert(1)</script><p>",
    ],
    "event_handler": [
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
    ],
    "embedded_document": [
        "<iframe srcdoc=\"<script>alert(1)</script>\"></iframe>",
    ],
    "javascript_url": [
        "<a href=\"javascript:alert(1)\">click</a>",
    ],
    "html_comment_breakout": [
        "--><script>alert(1)</script><!--",
    ],
}


def make_input(fdp, sandbox):
    if not fdp.ConsumeBool():
        benign_values = ["Italic", "Hello, visitor!", "Welcome"]
        if fdp.ConsumeBool():
            message = fdp.PickValueInList(benign_values)
        else:
            message = fdp.ConsumeUnicodeNoSurrogates(12)
        return {"visitor_message": message}

    technique = fdp.PickValueInList(sorted(ATTACKS))
    payload = fdp.PickValueInList(ATTACKS[technique])
    prefix = fdp.ConsumeUnicodeNoSurrogates(4) if fdp.ConsumeBool() else ""
    suffix = fdp.ConsumeUnicodeNoSurrogates(4) if fdp.ConsumeBool() else ""
    return {"visitor_message": prefix + payload + suffix}
