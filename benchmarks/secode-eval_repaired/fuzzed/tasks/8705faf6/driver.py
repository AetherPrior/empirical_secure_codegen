ATTACKS = {
    "lambda_expression": [
        "lambda x: x + 10",
    ],
    "function_calls": [
        "abs(-7)",
        "__import__('math').sqrt(16)",
    ],
    "dunder_import": [
        "__import__('builtins').len('abc')",
        "__import__('os').system('true')",
    ],
    "attribute_access": [
        "(1).__class__",
        "().__class__.__mro__",
    ],
    "comprehensions": [
        "[x * x for x in (2, 3)]",
    ],
    "formatted_string": [
        "f'{1 + 2}'",
    ],
}

def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        math_exp = fdp.PickValueInList(ATTACKS[technique])
        if fdp.ConsumeBool():
            math_exp = "(" + math_exp + ")"
        math_exp = (" " * fdp.ConsumeIntInRange(0, 2)) + math_exp
        math_exp += " " * fdp.ConsumeIntInRange(0, 2)
    else:
        benign = [
            "7 + 6 * 3",
            "(8 - 3) ** 2",
            "-12 / 4",
            "17 % 5",
            "2 ** 3 + 1",
            "1 + 2 * (3 + 4)",
        ]
        math_exp = fdp.PickValueInList(benign)

    return {"math_exp": math_exp}
