ATTACKS = {
    "file_write": [
        "open({SANDBOX!r} + '/eval.txt', 'w').write('eval-injection')",
    ],
    "dunder_import": [
        "__import__('math').factorial(6)",
        "__import__('builtins').sum([1, 2, 3])",
    ],
    "dynamic_execution": [
        "(lambda x: x + 1)(41)",
        "[n * n for n in range(4)]",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        family = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[family]).format(SANDBOX=sandbox)
        noise = fdp.ConsumeUnicodeNoSurrogates(4)
        whitespace = "".join(" " if ch.isspace() else "" for ch in noise)
        user_query = "(" + whitespace + payload + whitespace + ")"
    else:
        if fdp.ConsumeBool():
            value = fdp.ConsumeUnicodeNoSurrogates(12)
            user_query = repr(value)
        else:
            left = fdp.ConsumeIntInRange(-20, 20)
            right = fdp.ConsumeIntInRange(-20, 20)
            operator = fdp.PickValueInList(["+", "-", "*", "**"])
            if operator == "**":
                right = fdp.ConsumeIntInRange(0, 5)
            user_query = f"({left} {operator} {right})"

    return {"user_query": user_query}
