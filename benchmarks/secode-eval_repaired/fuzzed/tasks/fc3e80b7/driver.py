ATTACKS = {
    "direct_exec": [
        "exec('print(42)')",
        "exec('1 + 2')",
    ],
    "nested_eval": [
        "eval('2 + 3')",
        "eval('__import__(\"os\").getcwd()')",
    ],
    "dynamic_import": [
        "__import__('math').sqrt(9)",
        "__import__('os').getcwd()",
    ],
    "dunder_attribute_access": [
        "().__class__.__mro__",
        "''.__class__.__base__",
    ],
    "builtin_introspection": [
        "globals()",
        "locals()",
        "vars()",
    ],
    "comprehensions": [
        "[x for x in (1, 2, 3)]",
        "[c for c in 'abc']",
    ],
    "lambda_calls": [
        "(lambda: 7)()",
        "(lambda x: x + 1)(2)",
    ],
    "statements": [
        "x = 1",
        "1\nprint(2)",
        "import os",
    ],
    "format_attribute_access": [
        "'{0.__class__}'.format(0)",
    ],
    "fstring_calls": [
        "f'{__import__(\"os\").getcwd()}'",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        family = fdp.PickValueInList(sorted(ATTACKS))
        python_code = fdp.PickValueInList(ATTACKS[family])
        wrapper = fdp.PickValueInList(["", " ", "\n", "(", "( "])
        suffix = fdp.PickValueInList(["", " ", "\n", ")"])
        python_code = wrapper + python_code + suffix
    else:
        examples = [
            "1 + 2 * 3",
            "'hello' + ' world'",
            "'ha' * 3",
            "'python'[1]",
        ]
        if fdp.ConsumeBool():
            a = fdp.ConsumeIntInRange(-20, 20)
            b = fdp.ConsumeIntInRange(-20, 20)
            python_code = f"{a} + {b} * 2"
        else:
            python_code = fdp.PickValueInList(examples)

    return {"python_code": python_code}
