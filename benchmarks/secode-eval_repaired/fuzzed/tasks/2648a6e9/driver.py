ATTACKS = {
    "script_element": [
        "<script>alert('XSS');</script>",
        "<SCRIPT>alert(1)</SCRIPT>",
        "</p><script>alert(1)</script><p>",
    ],
    "event_handler": [
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        '<body onload=alert(1)>',
    ],
    "html_element_injection": [
        "</p><iframe src='javascript:alert(1)'></iframe><p>",
        "</p><a href='javascript:alert(1)'>click</a><p>",
        "<math><mtext></p><img src=x onerror=alert(1)>",
    ],
    "html_comment_breakout": [
        "--><script>alert(1)</script><!--",
        "</p><!-- --><img src=x onerror=alert(1)><!--<p>",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        if fdp.ConsumeBool():
            payload = (
                fdp.ConsumeUnicodeNoSurrogates(4)
                + payload
                + fdp.ConsumeUnicodeNoSurrogates(4)
            )
        input_text = payload
    else:
        input_text = fdp.PickValueInList(
            ["Fancy Text", "Hello, world!", "A & B", "5 < 7", "plain text"]
        )
    return {"input_text": input_text}
