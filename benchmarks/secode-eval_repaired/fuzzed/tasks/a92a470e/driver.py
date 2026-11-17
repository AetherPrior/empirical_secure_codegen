ATTACKS = {
    "closing_tag_injection": [
        "</message><admin>true</admin><message>",
        "</message><script>alert(1)</script><message>",
        "</message><message>injected",
    ],
    "cdata_injection": [
        "<![CDATA[injection]]>",
        "]]><admin>true</admin><![CDATA[",
        "<![CDATA[x]]>y",
    ],
    "entity_injection": [
        "&xxe;",
        "&#60;admin&#62;true&#60;/admin&#62;",
        "&amp;<admin>true</admin>",
    ],
    "processing_instruction": [
        "<?xml-stylesheet href=\"javascript:alert(1)\"?>",
        "<?target data?>",
    ],
    "comment_injection": [
        "--><admin>true</admin><!--",
        "<!-- comment -->",
    ],
    "doctype_injection": [
        "</message></response><!DOCTYPE response [<!ENTITY x \"injected\">]><response><message>&x;</message>",
        "</message></response><!DOCTYPE response SYSTEM \"file:///etc/passwd\"><response><message>",
    ],
    "malformed_markup": [
        "<admin>",
        "</message>",
        "<",
        "&",
    ],
}

def make_input(fdp, sandbox):
    benign = [
        "Special Char",
        "hello & goodbye",
        "5 < 7",
        "quotes: ' and \"",
        "plain text",
    ]

    if not fdp.ConsumeBool():
        value = fdp.PickValueInList(benign)
        if fdp.ConsumeBool():
            value += fdp.ConsumeUnicodeNoSurrogates(8)
        return {"client_input": value}

    technique = fdp.PickValueInList(sorted(ATTACKS))
    payload = fdp.PickValueInList(ATTACKS[technique])

    if fdp.ConsumeBool():
        payload = fdp.ConsumeUnicodeNoSurrogates(4) + payload
    if fdp.ConsumeBool():
        payload += fdp.ConsumeUnicodeNoSurrogates(4)

    return {"client_input": payload}
