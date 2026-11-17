ATTACKS = {
    "closing_tag_breakout": [
        "</message><injected>1</injected><message>",
        "</message><admin>true</admin><message>",
    ],
    "cdata_terminator": [
        "]]><injected>1</injected><![CDATA[",
        "<![CDATA[x]]><injected/>",
    ],
    "comment_markup": [
        "<!--x--><injected/>",
        "<!--><injected/>",
    ],
    "processing_instruction": [
        "<?probe data?><injected/>",
        "<?xml-stylesheet type='text/xml'?>",
    ],
    "entity_references": [
        "&amp;",
        "&#60;injected/&#62;",
        "&lt;injected&gt;",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        user_text = fdp.PickValueInList(ATTACKS[technique])
        if fdp.ConsumeBool():
            user_text = (
                fdp.ConsumeUnicodeNoSurrogates(4)
                + user_text
                + fdp.ConsumeUnicodeNoSurrogates(4)
            )
    else:
        user_text = fdp.PickValueInList(
            ["Special Char", "hello", "A & B", "plain text", ""]
        )
    return {"user_text": user_text}
