ATTACKS = {
    "exec_call": [
        "exec('1+1')",
        "exec('print(123)')",
    ],
    "import_call": [
        "__import__('math').sqrt(16)",
        "__import__('math').factorial(5)",
    ],
    "function_calls": [
        "abs(-3)",
        "pow(2, 5)",
        "sum([1,2,3])",
    ],
    "attribute_access": [
        "(1).__class__",
        "().__class__",
        "'x'.upper()",
    ],
    "comprehensions": [
        "[x*x for x in (1,2,3)]",
        "{x for x in (1,2)}",
    ],
    "lambda_calls": [
        "(lambda: 7)()",
        "(lambda x: x+1)(4)",
    ],
    "format_calls": [
        "'{0}'.format(7)",
        "('{0}{1}').format(1,2)",
    ],
    "other_python_syntax": [
        "(1,2,3)",
        "{'a': 1}",
        "1 if True else 2",
        "2**3",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        expression = (" " * fdp.ConsumeIntInRange(0, 2)) + payload
        if fdp.ConsumeBool():
            expression = "(" + expression + ")"
        if fdp.ConsumeBool():
            expression += " " * fdp.ConsumeIntInRange(0, 2)
    else:
        a = fdp.ConsumeIntInRange(-20, 20)
        b = fdp.ConsumeIntInRange(-20, 20)
        op = fdp.PickValueInList(["+", "-", "*", "/", "//", "%"])
        if op in ("/", "//", "%") and b == 0:
            b = 1
        expression = f"({a}) {op} ({b})"

    return {"expression_str": expression}
