ATTACKS = {
    "lambda": [
        "lambda x: x + 10",
        "(lambda: 7)()",
    ],
    "imports_and_calls": [
        "__import__('math').sqrt(16)",
        "__import__('os').getcwd()",
        "__import__('os').getpid()",
        "__import__('builtins').len([])",
    ],
    "attribute_introspection": [
        "().__class__",
        "().__class__.__mro__",
        "(1).__class__.__bases__",
    ],
    "builtins_and_namespace": [
        "globals()",
        "locals()",
        "dir()",
    ],
    "comprehensions": [
        "[x for x in (1, 2)]",
        "{x: x for x in (1,)}",
    ],
    "f_strings": [
        "f'{1 + 2}'",
        "f'{().__class__}'",
    ],
    "assignment_expression": [
        "(x := 7)",
    ],
    "statement_injection": [
        "1; __import__('os').getcwd()",
        "1; print('MATHPROQ')",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        family = fdp.PickValueInList(sorted(ATTACKS))
        expression = fdp.PickValueInList(ATTACKS[family])
        if fdp.ConsumeBool():
            expression = "(" + expression + ")"
    else:
        expression = fdp.PickValueInList([
            "7 + 6 * 3",
            "2 ** 5",
            "(12 - 4) / 2",
            "-3 + 8",
            "17 % 5",
            "2 * (3 + 4)",
            "3.5 + 1.25",
            "1 < 2",
        ])

    return {"expression": expression}
