ATTACKS = {
    "builtin_eval": [
        "eval('2 + 2')",
        "__import__('builtins').eval('3 * 7')",
    ],
    "module_import_and_call": [
        "__import__('math').sqrt(81)",
        "__import__('os').getcwd()",
        "__import__('math').factorial(5)",
    ],
    "attribute_introspection": [
        "().__class__.__mro__",
        "().__class__.__base__",
        "(1).__class__",
    ],
    "executable_expressions": [
        "(lambda: 6 * 7)()",
        "[x * x for x in (2, 3)]",
        "1 if True else 0",
    ],
    "unsupported_operators": [
        "2 ** 10",
        "9 // 2",
        "1 % 2",
    ],
    "comments_and_newlines": [
        "1 + 2 # comment",
        "1 + 2\n+ 3",
    ],
}


def make_input(fdp, sandbox):
    benign = [
        "5 * 9",
        "1 + 2",
        "18 / 3",
        "7 - 4",
        "(2 + 3) * 4",
        " 12 / 4 ",
    ]

    if not fdp.ConsumeBool():
        expression = fdp.PickValueInList(benign)
    else:
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        expression = payload

        if fdp.ConsumeBool():
            expression = "(" + expression + ")"
        if fdp.ConsumeBool():
            expression = " " + expression
        if fdp.ConsumeBool():
            expression += " "

    return {"expression_input": expression}
