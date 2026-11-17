ATTACKS = {
    "element_breakout": [
        "</message><admin>true</admin><message>",
        "</message></response><admin>true</admin>",
    ],
    "script_element": [
        "<script>alert(1)</script>",
        "<svg onload=\"alert(1)\"/>",
    ],
    "cdata": [
        "<![CDATA[injection]]>",
        "]]><admin>true</admin><![CDATA[",
    ],
    "entity_reference": [
        "&xx;",
        "&amp;",
    ],
    "internal_doctype_entity": [
        "</message></response><!DOCTYPE response [<!ENTITY x \"injected\">]><response><message>&x;",
    ],
    "processing_instruction": [
        "<?xml-stylesheet type=\"text/xsl\" href=\"evil.xsl\"?>",
    ],
    "comment": [
        "<!--injected-->",
        "--><admin>true</admin><!--",
    ],
}

def make_input(fdp, sandbox):
    benign = ["Special Char", "hello", "café", "1 < 2 & 3 > 0"]

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
        user_text = fdp.PickValueInList(benign)

    return {"user_text": user_text}
