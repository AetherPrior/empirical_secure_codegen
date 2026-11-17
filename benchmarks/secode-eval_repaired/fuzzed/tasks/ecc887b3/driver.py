ATTACKS = {
    "pickle_protocol0": ["(lp0\nI1\naI2\na."],
    "pickle_protocol2": ["\x80\x02]q\x00(K\x01K\x02e."],
    "pickle_protocol4": ["\x80\x04\x95\x0b\x00\x00\x00\x00\x00\x00\x00]\x94(K\x01K\x02K\x03e."],
    "pickle_format_alias": ["PICKLE", "Pickle", "pIcKlE", "pickle "],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        family = fdp.PickValueInList(
            ["pickle_protocol0", "pickle_protocol2", "pickle_protocol4"]
        )
        serialized_bytes = fdp.PickValueInList(ATTACKS[family]).encode("latin-1")
        if fdp.ConsumeBool():
            allowed_format = "pickle"
        else:
            allowed_format = fdp.PickValueInList(ATTACKS["pickle_format_alias"])
        return {
            "serialized_bytes": serialized_bytes,
            "allowed_format": allowed_format,
        }

    if fdp.ConsumeBool():
        serialized_bytes = b'[1, 2, 3]'
        allowed_format = "json"
    else:
        serialized_bytes = b"<items><item>1</item><item>2</item></items>"
        allowed_format = "xml"

    return {
        "serialized_bytes": serialized_bytes,
        "allowed_format": allowed_format,
    }
