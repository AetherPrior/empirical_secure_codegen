ATTACKS = {
    "eval_call": [
        "eval('2 + 2')",
        "eval('6 * 7')",
    ],
    "imported_function_call": [
        "__import__('math').sqrt(81)",
        "__import__('builtins').sum([1, 2, 3])",
    ],
    "attribute_introspection": [
        "().__class__.__name__",
        "(1).__class__.__name__",
    ],
    "lambda_call": [
        "(lambda: 42)()",
    ],
    "file_write": [
        "open('__SANDBOX__/marker', 'w').write('executed')",
    ],
    "unsupported_operators": [
        "2 ** 8",
        "9 // 2",
        "5 % 2",
        "1 << 3",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        family = fdp.PickValueInList(sorted(ATTACKS))
        expression = fdp.PickValueInList(ATTACKS[family])

        if family == "file_write":
            import os
            marker_path = os.path.join(sandbox, "marker")
            expression = expression.replace(
                "'__SANDBOX__/marker'", repr(marker_path)
            )

        if fdp.ConsumeBool():
            expression = "(" + expression + ")"
        expression = (" " * fdp.ConsumeIntInRange(0, 2)) + expression
        expression += " " * fdp.ConsumeIntInRange(0, 2)
    else:
        left = fdp.ConsumeIntInRange(0, 100)
        operator = fdp.PickValueInList(["+", "-", "*", "/"])
        right = fdp.ConsumeIntInRange(1, 100) if operator == "/" else fdp.ConsumeIntInRange(0, 100)
        expression = f"{left} {operator} {right}"

    return {"user_input": expression}
