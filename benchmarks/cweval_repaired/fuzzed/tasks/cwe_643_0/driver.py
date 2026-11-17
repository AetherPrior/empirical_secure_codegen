ATTACKS = {
    "boolean_or_tautology": [
        "' or '1'='1",
        "' or true() or '",
    ],
}


def make_input(fdp, sandbox):
    xml_data = (
        "<students>"
        "<student><username>alice</username><password>pw-a</password>"
        "<name>Alice Example</name><citizenship>Wonderland</citizenship>"
        "<age>20</age></student>"
        "<student><username>bob</username><password>pw-b</password>"
        "<name>Bob Example</name><citizenship>Freedonia</citizenship>"
        "<age>21</age></student>"
        "</students>"
    )

    if fdp.ConsumeBool():
        field = fdp.PickValueInList(["username", "password"])
        payload = fdp.PickValueInList(ATTACKS["boolean_or_tautology"])
        fuzz_prefix = "".join(
            ch for ch in fdp.ConsumeUnicodeNoSurrogates(4)
            if ch.isascii() and ch.isalnum()
        )
        injected = fuzz_prefix + payload

        if field == "username":
            username, password = injected, "missing"
        else:
            username, password = "missing", injected
    else:
        if fdp.ConsumeBool():
            username, password = "alice", "pw-a"
        else:
            username, password = "nobody", "missing"

    return {
        "xml_data": xml_data,
        "username": username,
        "password": password,
    }
