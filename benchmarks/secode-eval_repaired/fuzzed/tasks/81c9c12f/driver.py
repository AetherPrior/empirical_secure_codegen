ATTACKS = {
    "lambda_expression": [
        "lambda x: x + 10",
    ],
    "dynamic_import_call": [
        "__import__('math').sqrt(16)",
        "__import__('builtins').sum([1, 2])",
    ],
    "attribute_access": [
        "(1).__class__",
        "().__class__.__mro__",
    ],
    "comprehension": [
        "[x for x in (1, 2)]",
    ],
    "conditional_expression": [
        "1 if True else 2",
    ],
    "string_expression": [
        "'7' + '6'",
    ],
    "subscript_expression": [
        "(1, 2)[0]",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        expr = fdp.PickValueInList(ATTACKS[technique])

        # Sometimes embed the payload in an otherwise mathematical expression.
        if fdp.ConsumeBool():
            n = fdp.ConsumeIntInRange(0, 9)
            expr = f"{n} + ({expr})"
        elif fdp.ConsumeBool():
            expr = f"({expr})"
    else:
        a = fdp.ConsumeIntInRange(0, 20)
        b = fdp.ConsumeIntInRange(1, 20)
        c = fdp.ConsumeIntInRange(0, 10)
        op = fdp.PickValueInList(["+", "-", "*", "//", "%"])
        expr = f"({a} {op} {b}) + {c}"

    return {"math_input": expr}
