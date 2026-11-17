ATTACKS = {
    "exec_call": [
        "exec('print(10)')",
        "exec('1+1')",
    ],
    "nested_eval": [
        "eval('2+3')",
        "__import__('builtins').eval('4*5')",
    ],
    "import_call": [
        "__import__('math').sqrt(16)",
        "__import__('math').factorial(5)",
    ],
    "attribute_introspection": [
        "().__class__",
        "().__class__.__mro__",
    ],
    "call_expression": [
        "(lambda: 7)()",
        "abs(-9)",
    ],
    "comprehension": [
        "[x*x for x in (1,2,3)]",
        "[print(10) for _ in (0,)]",
    ],
    "walrus_expression": [
        "(x:=1)",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        family = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[family])

        # Keep fuzz text in a trailing comment so it does not obscure the payload.
        noise = fdp.ConsumeUnicodeNoSurrogates(4).replace("\n", " ").replace("\r", " ")
        equation = payload + " #" + noise
        if fdp.ConsumeBool():
            equation = "(" + equation + ")"
        return {"equation": equation}

    a = fdp.ConsumeIntInRange(0, 20)
    b = fdp.ConsumeIntInRange(1, 20)
    c = fdp.ConsumeIntInRange(0, 20)
    op = fdp.PickValueInList(["+", "-", "*", "//", "%"])
    equation = f"({a} {op} {b}) + {c}"
    return {"equation": equation}
