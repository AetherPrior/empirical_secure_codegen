ATTACKS = {
    "builtin_import_call": [
        "__import__('math').sqrt(16)",
        "__import__('builtins').repr(1)",
    ],
    "nested_eval": [
        "__import__('builtins').eval('6*7')",
    ],
    "exec_side_effect": [
        "__import__('builtins').exec(\"print('QUIZ_INJECTED')\")",
    ],
    "attribute_traversal": [
        "(1).__class__.__mro__",
        "().__class__.__bases__",
    ],
    "lambda_call": [
        "(lambda: 7)()",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        # Keep fuzzing around the payload limited to whitespace so it remains
        # an expression while still varying its surrounding text.
        leading = " " * fdp.ConsumeIntInRange(0, 3)
        trailing = "\t" * fdp.ConsumeIntInRange(0, 3)
        user_input = leading + "(" + payload + ")" + trailing
    else:
        samples = [
            "5**3",
            "1 + 2 * 3",
            "-8 // 3",
            "7 % 4",
            "(2 + 3) * 4",
        ]
        if fdp.ConsumeBool():
            user_input = fdp.PickValueInList(samples)
        else:
            left = fdp.ConsumeIntInRange(0, 20)
            right = fdp.ConsumeIntInRange(1, 10)
            op = fdp.PickValueInList(["+", "-", "*", "//", "%", "**"])
            if op == "**":
                right = fdp.ConsumeIntInRange(0, 4)
            user_input = f"{left} {op} {right}"

    return {"user_input": user_input}
