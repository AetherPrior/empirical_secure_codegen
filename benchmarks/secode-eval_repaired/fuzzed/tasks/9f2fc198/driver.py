ATTACKS = {
    "lambda_expression": [
        "lambda x: x + 10",
    ],
    "dynamic_import_call": [
        "__import__('math').sqrt(16)",
        "1 + __import__('math').factorial(5)",
    ],
    "builtin_call": [
        "__import__('builtins').sum((1, 2))",
    ],
    "attribute_introspection": [
        "().__class__.__mro__",
        "(1).__class__",
    ],
    "comprehension": [
        "[x for x in (1, 2)]",
    ],
    "call_expression": [
        "(lambda: 7)()",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        expr = f"({payload})"
        if fdp.ConsumeBool():
            expr = " " + expr + " "
    else:
        left = fdp.ConsumeIntInRange(0, 20)
        right = fdp.ConsumeIntInRange(1, 20)
        operator = fdp.PickValueInList(["+", "-", "*", "//", "%", "**"])
        if operator == "**":
            right = fdp.ConsumeIntInRange(0, 3)
        expr = f"{left} {operator} {right}"

    return {"expr_input": expr}
