ATTACKS = {
    "exec_call": [
        "exec('print(123)')",
        "exec('1+2')",
    ],
    "eval_call": [
        "eval('1+2')",
        "eval('__import__(\"math\").sqrt(16)')",
    ],
    "builtin_calls": [
        "sum([1,2,3])",
        "abs(-7)",
        "pow(2,5)",
    ],
    "import_and_attribute": [
        "__import__('math').sqrt(9)",
        "__import__('math').factorial(5)",
    ],
    "attribute_introspection": [
        "().__class__.__name__",
        "(1).__class__.__name__",
        "().__class__.__mro__",
    ],
    "lambda_expression": [
        "(lambda: 7)()",
        "(lambda x: x+1)(4)",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        expression = fdp.PickValueInList(ATTACKS[technique])
        if fdp.ConsumeBool():
            whitespace = fdp.PickValueInList(["", " ", "\t", "\n"])
            expression = whitespace + expression + whitespace
    else:
        samples = ["8 / 2", "1 + 2 * 3", "(9 - 4) * 2", "2 ** 3"]
        if fdp.ConsumeBool():
            expression = fdp.PickValueInList(samples)
        else:
            left = fdp.ConsumeIntInRange(0, 20)
            right = fdp.ConsumeIntInRange(1, 10)
            operator = fdp.PickValueInList(["+", "-", "*", "/"])
            expression = f"({left}) {operator} ({right})"

    return {"ex_string": expression}
