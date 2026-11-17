ATTACKS = {
    "element_breakout": [
        "</message><admin>true</admin><message>",
        "</message><evil attr='x'>injected</evil><message>",
    ],
    "cdata_termination": [
        "]]><injected/>",
        "]]>injected<![CDATA[",
        "<![CDATA[injection]]>",
    ],
    "doctype_entity": [
        "</message><!DOCTYPE x [<!ENTITY e 'injected'>]><message>&e;",
        "&xx;",
    ],
    "processing_instruction": [
        "<?target injected?>",
        "text?><?target injected?>",
    ],
    "comment_markup": [
        "--><evil/> <!--",
        "<!-- comment --><injected/>",
    ],
    "xml_special_characters": [
        "<tag>",
        "&amp;",
        "\" ' < > &",
    ],
}

_BENIGN = [
    "Special Char",
    "Hello, XML!",
    "plain text 123",
    "A & B",
]


def make_input(fdp, sandbox):
    if not fdp.ConsumeBool():
        content = fdp.PickValueInList(_BENIGN)
    else:
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        prefix = fdp.ConsumeUnicodeNoSurrogates(4) if fdp.ConsumeBool() else ""
        suffix = fdp.ConsumeUnicodeNoSurrogates(4) if fdp.ConsumeBool() else ""
        content = prefix + payload + suffix

    return {"content_insert": content}
