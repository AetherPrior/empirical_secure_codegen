ATTACKS = {
    "tag_breakout": [
        "</message><admin>true</admin><message>",
        "</message><script>alert(1)</script><message>",
        "<admin/>",
    ],
    "cdata_termination": [
        "<![CDATA[injection]]>",
        "]]><admin>true</admin><![CDATA[",
    ],
    "comment_termination": [
        "--><admin>true</admin><!--",
    ],
    "processing_instruction": [
        "<?target data?>",
    ],
    "entity_reference": [
        "&amp;",
        "&#60;admin/&#62;",
        "&xx;",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        if fdp.ConsumeBool():
            prefix = fdp.ConsumeUnicodeNoSurrogates(4)
            suffix = fdp.ConsumeUnicodeNoSurrogates(4)
            payload = prefix + payload + suffix
        return {"input_data": payload}

    benign_values = [
        "Special Char",
        "plain text",
        "hello & goodbye",
        "5 < 7",
        "café",
    ]
    if fdp.ConsumeBool():
        value = fdp.PickValueInList(benign_values)
    else:
        value = fdp.ConsumeUnicodeNoSurrogates(12)
    return {"input_data": value}
