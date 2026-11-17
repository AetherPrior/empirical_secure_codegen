ATTACKS = {
    "element_breakout": [
        "</message><admin>true</admin><message>",
        "</message><message>injected</message><message>",
    ],
    "cdata_terminator": [
        "]]><admin>true</admin><![CDATA[",
        "]]>injected<![CDATA[",
    ],
    "entity_reference": [
        "&xx;",
        "&#60;admin&#62;true&#60;/admin&#62;",
    ],
    "comment_injection": [
        "<!--injected-->",
        "--><!--injected><!--",
    ],
    "processing_instruction": [
        "<?probe injected?>",
        "<?xml-stylesheet type='text/xsl' href='x'?>",
    ],
}

def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        prefix = fdp.ConsumeUnicodeNoSurrogates(4)
        suffix = fdp.ConsumeUnicodeNoSurrogates(4)
        user_entry = prefix + payload + suffix
    else:
        benign_samples = ["Special Char", "hello", "A & B", "5 < 7"]
        user_entry = fdp.PickValueInList(benign_samples)

    return {"user_entry": user_entry}
