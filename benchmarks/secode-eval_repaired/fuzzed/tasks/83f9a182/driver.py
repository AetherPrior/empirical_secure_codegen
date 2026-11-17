ATTACKS = {
    "identifier": [
        "a",
        "a + 3",
        "__builtins__",
    ],
    "function_call": [
        "__import__('builtins').abs(-7)",
        "(lambda: 9)()",
        "__import__('builtins').eval('6*7')",
    ],
    "module_import": [
        "__import__('math').sqrt(16)",
        "__import__('builtins').str(7)",
    ],
    "attribute_access": [
        "().__class__",
        "().__class__.__name__",
        "(1).__class__.__mro__[1]",
    ],
    "comprehension": [
        "[x for x in (1, 2)]",
        "{x: x for x in (1, 2)}",
    ],
    "conditional_expression": [
        "1 if True else 2",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        family = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[family])

        context = fdp.ConsumeIntInRange(0, 2)
        n = fdp.ConsumeIntInRange(1, 9)
        if context == 1:
            expr = str(n) + " + (" + payload + ")"
        elif context == 2:
            expr = "(" + payload + ") * " + str(n)
        else:
            expr = payload
    else:
        a = fdp.ConsumeIntInRange(0, 20)
        b = fdp.ConsumeIntInRange(0, 20)
        c = fdp.ConsumeIntInRange(1, 20)
        op1 = fdp.PickValueInList(["+", "-", "*", "/"])
        op2 = fdp.PickValueInList(["+", "-", "*", "/"])
        expr = f"{a} {op1} {b} {op2} {c}"

    return {"expr_string": expr}
