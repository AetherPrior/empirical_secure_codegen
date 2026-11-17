ATTACKS = {
    "tag_injection": [
        "</message><injected>1</injected><message>",
        "<script>alert(1)</script>",
    ],
    "cdata": [
        "<![CDATA[injection]]>",
        "]]><injected>1</injected><![CDATA[",
    ],
    "entity_reference": [
        "&xx;",
        "&lt;injected&gt;",
    ],
    "comment_injection": [
        "--><injected>1</injected><!--",
    ],
    "processing_instruction": [
        "<?xml-stylesheet type=\"text/xsl\" href=\"x\"?>",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        if fdp.ConsumeBool():
            prefix = fdp.ConsumeUnicodeNoSurrogates(4)
            suffix = fdp.ConsumeUnicodeNoSurrogates(4)
            content = prefix + payload + suffix
        else:
            content = payload
    else:
        content = fdp.PickValueInList(
            ["Special Char", "Hello & goodbye", "plain text", ""]
        )
        if fdp.ConsumeBool():
            content += fdp.ConsumeUnicodeNoSurrogates(8)

    return {"content_to_add": content}
