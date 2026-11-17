ATTACKS = {
    "pickle_protocol0_mapping": [
        "(dp0\nVflag\np1\nVexploit\np2\ns."
    ],
    "pickle_protocol2_mapping": [
        "\x80\x02}q\x00X\x04\x00\x00\x00flagq\x01X\x07\x00\x00\x00exploitq\x02s."
    ],
    "pickle_protocol4_values": [
        "\x80\x04K*.",
        "\x80\x04]\x94(K\x01K\x02e.",
        "\x80\x04\x95\x15\x00\x00\x00\x00\x00\x00\x00}\x94\x8c\x04flag\x94\x8c\x07exploit\x94s.",
    ],
}


def make_input(fdp, sandbox):
    import csv
    import io
    import json

    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        return {
            "data_bytes_stream": payload.encode("latin-1"),
            "method_of_serialization": "pickle",
        }

    value = fdp.ConsumeUnicodeNoSurrogates(8)
    if fdp.ConsumeBool():
        data = json.dumps({"value": value}, ensure_ascii=True).encode("utf-8")
        method = "json"
    else:
        output = io.StringIO(newline="")
        writer = csv.writer(output, lineterminator="\n")
        writer.writerow(["name", "value"])
        writer.writerow(["sample", value])
        data = output.getvalue().encode("utf-8")
        method = "csv"

    return {
        "data_bytes_stream": data,
        "method_of_serialization": method,
    }
