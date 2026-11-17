ATTACKS = {
    "element_breakout": [
        "</message><injected>1</injected><message>",
        "</message><admin>true</admin><message>",
    ],
    "cdata_termination": [
        "]]></message><injected/>",
        "]]>injected<![CDATA[",
    ],
    "comment_breakout": [
        "--><injected/><!--",
        "<!-- comment --><injected/>",
    ],
    "processing_instruction": [
        "<?xml-stylesheet href='evil'?>",
        "<?target data?><injected/>",
    ],
    "entity_reference": [
        "&#x3C;injected/&#x3E;",
        "&lt;injected/&gt;",
    ],
    "markup_injection": [
        "<script>alert(1)</script>",
        "<![CDATA[injection]]>",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        prefix = fdp.ConsumeUnicodeNoSurrogates(3)
        suffix = fdp.ConsumeUnicodeNoSurrogates(3)
        user_content = prefix + payload + suffix
    else:
        user_content = fdp.PickValueInList(
            ["Special Char", "plain text", "A & B", "5 < 7"]
        )
    return {"user_content": user_content}
