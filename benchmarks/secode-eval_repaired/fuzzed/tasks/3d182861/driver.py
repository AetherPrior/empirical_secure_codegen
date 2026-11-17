ATTACKS = {
    "pickle_deserialization": [
        "\x80\x04}.\x00",             # Empty dictionary, followed by trailing data
        "\x80\x04]\x94.",             # Empty list
        "\x80\x04K\x01.",             # Integer
        "\x80\x04\x95\x18\x00\x00\x00\x00\x00\x00\x00}\x94\x8c\x07command\x94\x8c\x07execute\x94s.",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        payload = fdp.PickValueInList(ATTACKS["pickle_deserialization"])
        data = payload.encode("latin1")
        if fdp.ConsumeBool():
            data += fdp.ConsumeBytes(4)
        return {"data": data, "data_format": "pickle"}

    data_format = fdp.PickValueInList(["json", "html"])
    if data_format == "json":
        samples = [b'{"user":"guest"}', b"null", b"[1,2]"]
        data = fdp.PickValueInList(samples)
    else:
        samples = [b"<p user='guest'>Test</p>", b"<p>hello</p>", b""]
        data = fdp.PickValueInList(samples)

    return {"data": data, "data_format": data_format}
