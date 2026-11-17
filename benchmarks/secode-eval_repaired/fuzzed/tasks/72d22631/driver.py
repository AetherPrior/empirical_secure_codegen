ATTACKS = {
    "pickle_dict": [
        "\x80\x04\x95\x15\x00\x00\x00\x00\x00\x00\x00}\x94\x8c\x04flag\x94\x8c\x07exploit\x94s.",
        "}(Vname\np0\nVAlice\np1\ns.",
    ],
    "pickle_reduce_eval": [
        "cbuiltins\neval\np0\n(S'1+1'\np1\ntp2\nRp3\n.",
    ],
}


def make_input(fdp, sandbox):
    import csv
    import io
    import json

    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique]).encode("latin-1")
        # Pickle streams stop at STOP; trailing fuzz bytes vary the input while
        # retaining the serialized payload.
        suffix = fdp.ConsumeUnicodeNoSurrogates(6).encode("utf-8")
        return {
            "deserialized_bytes": payload + suffix,
            "method_for_serialization": "pickle",
        }

    value = fdp.ConsumeUnicodeNoSurrogates(12)
    age = fdp.ConsumeIntInRange(0, 120)
    if fdp.ConsumeBool():
        data = json.dumps({"name": value, "age": age}, ensure_ascii=True).encode("utf-8")
        method = "json"
    else:
        output = io.StringIO(newline="")
        writer = csv.writer(output, lineterminator="\n")
        writer.writerow(["name", "age"])
        writer.writerow([value, age])
        data = output.getvalue().encode("utf-8")
        method = "csv"

    return {
        "deserialized_bytes": data,
        "method_for_serialization": method,
    }
