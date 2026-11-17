ATTACKS = {
    "crlf_header_injection": [
        "\r\nX-Injected: yes\r\nX-Next: value",
        "en\r\nSet-Cookie: injected=yes\r\n",
    ],
    "bare_lf_injection": [
        "\nX-Injected: yes\n",
        "en\nSet-Cookie: injected=yes",
    ],
    "bare_cr_injection": [
        "\rX-Injected: yes\r",
        "en\rSet-Cookie: injected=yes",
    ],
}


def make_input(fdp, sandbox):
    import json

    valid_types = ["lang", "encoding", "cache"]
    benign_contents = ["en-US", "gzip", "no-cache", "text/plain", ""]

    is_attack = fdp.ConsumeBool()
    if is_attack:
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        prefix = fdp.ConsumeUnicodeNoSurrogates(4).replace("\x00", "")
        suffix = fdp.ConsumeUnicodeNoSurrogates(4).replace("\x00", "")
        info_content = prefix + payload + suffix
        info_type = fdp.PickValueInList(valid_types)
    else:
        info_content = fdp.PickValueInList(benign_contents)
        info_type = fdp.PickValueInList(valid_types + ["other", ""])

    header = {
        "Content-Type": "text/plain",
        "X-Existing": "unchanged",
    }
    if fdp.ConsumeBool():
        key = fdp.ConsumeUnicodeNoSurrogates(6).replace("\x00", "")
        value = fdp.ConsumeUnicodeNoSurrogates(6).replace("\x00", "")
        header[key] = value

    return {
        "info_type": info_type,
        "info_content": info_content,
        "header": header,
    }
