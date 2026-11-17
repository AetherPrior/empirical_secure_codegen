ATTACKS = {
    "tag_injection": [
        "</message><admin>true</admin><message>",
        "</message><x>injected</x><message>",
        "<x>injected</x>",
    ],
    "cdata_markup": [
        "<![CDATA[injection]]>",
        "]]><x>injected</x><![CDATA[",
    ],
    "entity_reference": [
        "&xx;",
        "&amp;",
        "&#x3C;injected&#x3E;",
    ],
    "comment_injection": [
        "--><x>injected</x><!--",
        "<!--injected-->",
    ],
    "processing_instruction": [
        "<?target injected?>",
        "</message><?target injected?><message>",
    ],
    "doctype_entity_declaration": [
        '</message><!DOCTYPE response [<!ENTITY x "injected">]><message>&x;',
    ],
    "invalid_xml_character": [
        "\x00",
        "\x01",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        prefix = fdp.ConsumeUnicodeNoSurrogates(4)
        suffix = fdp.ConsumeUnicodeNoSurrogates(4)
        user_input = prefix + payload + suffix
    else:
        user_input = fdp.PickValueInList([
            "Special Char",
            "hello",
            "plain text",
        ])

    return {"user_input": user_input}
