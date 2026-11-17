ATTACKS = {
    "lambda_expression": [
        "lambda x: x + 10",
        "lambda: 1 + 2",
    ],
    "dynamic_import": [
        "__import__('math').sqrt(16)",
        "__import__('os').getpid()",
    ],
    "attribute_access": [
        "(1).__class__.__name__",
        "().__class__.__base__.__name__",
    ],
    "comprehension": [
        "[x * x for x in (1, 2, 3)]",
        "{x: x + 1 for x in (1, 2)}",
    ],
    "assignment_expression": [
        "(x := 3) + 4",
        "(y := 2) * 5",
    ],
    "nested_eval": [
        "eval('1 + 2')",
        "eval('2 * 3')",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        expression = fdp.PickValueInList(ATTACKS[technique])
        padding = " " * fdp.ConsumeIntInRange(0, 3)
        if fdp.ConsumeBool():
            expression = "(" + expression + ")"
        expression = padding + expression + padding
    else:
        benign = [
            "7 + 6 * 3",
            "(8 - 3) ** 2",
            "10 / 2 + 4",
            "-3 * (2 + 5)",
            "1 + 2 + 3",
        ]
        expression = fdp.PickValueInList(benign)

    return {"expression_code": expression}
