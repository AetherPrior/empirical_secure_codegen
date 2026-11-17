ATTACKS = {
    "element_breakout": [
        "</message><admin>true</admin><message>",
        "<!----></message><injected/>",
    ],
    "nested_markup": [
        "<injected>value</injected>",
        "<script>alert(1)</script>",
    ],
    "cdata": [
        "<![CDATA[injection]]>",
        "]]><injected/><![CDATA[",
    ],
    "entity_reference": [
        "&amp;<injected/>",
        "&#x3C;injected&#x3E;",
    ],
    "comment": [
        "<!--injected--><injected/>",
        "--><injected/><!--",
    ],
    "processing_instruction": [
        "<?xml-stylesheet type=\"text/xsl\"?><injected/>",
        "<?target data?><injected/>",
    ],
    "doctype_declaration": [
        "<!DOCTYPE response [<!ENTITY x \"injected\">]>&x;",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        if fdp.ConsumeBool():
            payload = fdp.ConsumeUnicodeNoSurrogates(4) + payload
        if fdp.ConsumeBool():
            payload += fdp.ConsumeUnicodeNoSurrogates(4)
        value = payload
    else:
        value = fdp.PickValueInList([
            "Special Char",
            "ordinary text",
            "A & B",
            "less < than",
            "quotes ' and \"",
            fdp.ConsumeUnicodeNoSurrogates(12),
        ])

    return {"input_content": value}
